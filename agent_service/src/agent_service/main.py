# src/agent_service/main.py

import httpx  # Using httpx for async requests
from fastapi import FastAPI, Depends, HTTPException, status, Header, Body
from typing import Dict, Optional, Any, Tuple, Set
import asyncio
from fastapi.responses import HTMLResponse
from fastapi import Request
import random
import os
import requests

from .auth_utils import get_current_user_agent, AgentTokenData, get_obo_token_for_tool_service, ConsentRequiredException
from .config import settings

app = FastAPI(
    title="AgentServiceApp API",
    description="Service that acts on behalf of a user to call other tools.",
    version="0.1.0"
)


@app.on_event("startup")
async def startup_event():
    print("--- AgentServiceApp (FastAPI) Starting Up ---")
    print(f"Tenant ID: {settings.AGENT_TENANT_ID}")
    print(f"Client ID (Agent): {settings.AGENT_CLIENT_ID}")
    print(f"Audience (Agent): {settings.AGENT_AUDIENCE}")
    print(f"Tool Service Base URL: {settings.TOOL_SERVICE_BASE_URL}")
    print(f"Tool Service Client ID: {settings.TOOL_SERVICE_CLIENT_ID}")
    print(f"Tool Service Scopes: {settings.TOOL_SERVICE_SCOPES}")
    print("-------------------------------------------")


@app.get("/")
async def home():
    return {"message": "Agent Service is running!"}


# In-memory store for paused invocations (for demo; use persistent store in prod)
paused_invocations = {}

# In-memory persistent token cache: (user_oid, as_type, frozenset(scopes)) -> {access_token, refresh_token, expires_at}
token_cache = {}

# Mock database: client_id -> redirect_uri
CLIENT_ID_TO_REDIRECT_URI = {
    # Example: WebAppUI-BFF client ID mapped to its callback
    "cb4fa55f-597f-4b70-a4e2-6237d74670be": "https://localhost:8000/auth/callback",
    # Add more mappings as needed for other UIs
}

# --- Simulated Tool Registry ---
TOOL_REGISTRY = {
    "weather_tool": {
        "as_type": "entra_id",
        "client_id": settings.AGENT_CLIENT_ID,
        "client_secret": settings.AGENT_CLIENT_SECRET,
        "authority": settings.AUTHORITY,
        "scopes": settings.TOOL_SERVICE_SCOPES,
        "redirect_uri": settings.AGENT_REDIRECT_URI,
        "endpoint": f"{settings.TOOL_SERVICE_BASE_URL}/api/checkweather",
    },
    "github_tool": {
        "as_type": "github",
        "client_id": os.getenv("GITHUB_CLIENT_ID"),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET"),
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "scopes": ["repo"],
        "redirect_uri": settings.AGENT_REDIRECT_URI,
        "endpoint": f"{settings.TOOL_SERVICE_BASE_URL}/api/github-repos",
    },
}


@app.post("/api/invokeagent/checkweather", response_model=Dict)
async def invoke_agent_check_weather(
        city: str = "TestCityFromAgent",  # Example parameter for the tool
        authorization: Optional[str] = Header(None),  # To get the raw Bearer token
        x_client_id: Optional[str] = Header(None),  # UI/BFF client ID header
        current_user: AgentTokenData = Depends(get_current_user_agent)  # Validates incoming token
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Authorization header")
    if not x_client_id or x_client_id not in CLIENT_ID_TO_REDIRECT_URI:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unknown or missing client ID for redirect mapping.")
    redirect_uri = CLIENT_ID_TO_REDIRECT_URI[x_client_id]
    user_assertion_token = authorization.split("Bearer ")[1]

    print(f"AgentService: User {current_user.name} (oid: {current_user.oid}) invoking agent for weather.")

    # Randomly choose a tool to invoke
    tool_id = random.choice(["weather_tool", "github_tool"])
    tool_config = TOOL_REGISTRY[tool_id]
    invocation_id = f"{current_user.oid}:{city}:{tool_id}"
    user_oid = current_user.oid
    as_type = tool_config["as_type"]
    scopes_needed = frozenset(tool_config["scopes"])
    # --- Token cache lookup by (user_oid, as_type, scopes) ---
    cached_token = None
    if tool_id == "github_tool":
        # Look for an exact or superset match in the cache
        for (cache_user_oid, cache_as_type, cache_scopes), token_data in token_cache.items():
            if cache_user_oid == user_oid and cache_as_type == as_type and cache_scopes.issuperset(scopes_needed):
                cached_token = token_data
                break
        if cached_token and cached_token.get("access_token"):
            print(f"AgentService: Using cached GitHub token for user {user_oid} with scopes {scopes_needed}.")
            github_token = cached_token["access_token"]
            tool_service_url = tool_config["endpoint"]
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Content-Type": "application/json"
            }
            async with httpx.AsyncClient(verify=False) as client:
                try:
                    print(f"AgentService: Calling ToolService at {tool_service_url} for GitHub repos (cached token)")
                    response = await client.get(tool_service_url, headers=headers, timeout=10.0)
                    response.raise_for_status()
                    tool_response_data = response.json()
                    print(f"AgentService: Received response from ToolService: {tool_response_data}")
                except Exception as e:
                    print(f"AgentService: Error calling ToolService (GitHub): {e}")
                    raise HTTPException(status_code=500, detail=f"Error calling ToolService (GitHub): {e}")
            return {
                "agent_message": f"Agent processed request for user {current_user.name} (github_tool, cached token).",
                "tool_service_response": tool_response_data
            }
    # For weather_tool, use OBO as before; for github_tool, simulate consent/token flow
    if tool_id == "weather_tool":
        try:
            tool_service_token = await get_obo_token_for_tool_service(user_assertion_token)
        except ConsentRequiredException as ce:
            paused_invocations[invocation_id] = {
                "city": city,
                "user": current_user,
                "user_assertion_token": user_assertion_token,
                "redirect_uri": redirect_uri,
                "client_id": x_client_id,
                "tool_id": tool_id
            }
            return {
                "status": "paused",
                "reason": "consent_required",
                "consent_url": ce.consent_url,
                "required_scopes": ce.required_scopes,
                "invocation_id": invocation_id,
                "error_description": ce.error_description
            }
        except HTTPException as e:
            raise e
        except Exception as e:
            print(f"AgentService: Unexpected error during OBO token acquisition: {e}")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="OBO token acquisition failed.")
        if not tool_service_token:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to obtain OBO token.")
        print("AgentService: Successfully obtained OBO token for ToolService.")
        tool_service_url = tool_config["endpoint"]
        headers = {
            "Authorization": f"Bearer {tool_service_token}",
            "Content-Type": "application/json"
        }
        params = {"city": city}
        async with httpx.AsyncClient(verify=False) as client:
            try:
                print(f"AgentService: Calling ToolService at {tool_service_url} with city: {city}")
                response = await client.get(tool_service_url, headers=headers, params=params, timeout=10.0)
                response.raise_for_status()
                tool_response_data = response.json()
                print(f"AgentService: Received response from ToolService: {tool_response_data}")
            except Exception as e:
                print(f"AgentService: Error calling ToolService: {e}")
                raise HTTPException(status_code=500, detail=f"Error calling ToolService: {e}")
        return {
            "agent_message": f"Agent processed request for user {current_user.name} (weather_tool).",
            "tool_service_response": tool_response_data
        }
    elif tool_id == "github_tool":
        # Simulate consent required for GitHub tool
        # In a real implementation, check for a stored GitHub token for this user
        consent_url = (
            f"https://github.com/login/oauth/authorize?client_id={tool_config['client_id']}"
            f"&redirect_uri={tool_config['redirect_uri']}"
            f"&scope={' '.join(tool_config['scopes'])}"
            f"&state={invocation_id}"
        )
        paused_invocations[invocation_id] = {
            "city": city,
            "user": current_user,
            "user_assertion_token": user_assertion_token,
            "redirect_uri": redirect_uri,
            "client_id": x_client_id,
            "tool_id": tool_id
        }
        return {
            "status": "paused",
            "reason": "consent_required",
            "consent_url": consent_url,
            "required_scopes": tool_config["scopes"],
            "invocation_id": invocation_id,
            "error_description": "GitHub consent required."
        }


@app.post("/api/invokeagent/resume", response_model=Dict)
async def resume_paused_invocation(
    body: Dict[str, Any] = Body(...),
    authorization: Optional[str] = Header(None),
    current_user: AgentTokenData = Depends(get_current_user_agent)
):
    invocation_id = body.get("invocation_id")
    if not invocation_id or invocation_id not in paused_invocations:
        raise HTTPException(status_code=404, detail="No paused invocation found for this ID.")
    paused = paused_invocations.pop(invocation_id)
    city = paused["city"]
    tool_id = paused.get("tool_id", "weather_tool")
    tool_config = TOOL_REGISTRY.get(tool_id)
    as_type = tool_config["as_type"]
    user_oid = paused["user"].oid if paused.get("user") and hasattr(paused["user"], "oid") else None
    scopes_needed = frozenset(tool_config["scopes"])
    # Look for a cached token with a superset of the required scopes
    cached_token = None
    if tool_id == "github_tool":
        for (cache_user_oid, cache_as_type, cache_scopes), token_data in token_cache.items():
            if cache_user_oid == user_oid and cache_as_type == as_type and cache_scopes.issuperset(scopes_needed):
                cached_token = token_data
                break
        github_token = paused.get("tool_access_token") or (cached_token or {}).get("access_token")
        if not github_token:
            raise HTTPException(status_code=400, detail="No GitHub access token found for this invocation. Please grant consent.")
        tool_service_url = tool_config["endpoint"]
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Content-Type": "application/json"
        }
        async with httpx.AsyncClient(verify=False) as client:
            try:
                print(f"AgentService: [RESUME] Calling ToolService at {tool_service_url} for GitHub repos")
                response = await client.get(tool_service_url, headers=headers, timeout=10.0)
                response.raise_for_status()
                tool_response_data = response.json()
                print(f"AgentService: [RESUME] Received response from ToolService: {tool_response_data}")
            except Exception as e:
                print(f"AgentService: [RESUME] Error calling ToolService (GitHub): {e}")
                raise HTTPException(status_code=500, detail=f"Error calling ToolService (GitHub) on resume: {e}")
        return {
            "agent_message": f"Agent resumed and completed request for user {current_user.name} (github_tool).",
            "tool_service_response": tool_response_data
        }
    elif tool_id == "weather_tool":
        user_assertion_token = authorization.split("Bearer ")[1] if authorization and authorization.startswith("Bearer ") else paused["user_assertion_token"]
        try:
            tool_service_token = await get_obo_token_for_tool_service(user_assertion_token)
        except Exception as e:
            print(f"AgentService: Error acquiring OBO token on resume: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to acquire OBO token on resume: {e}")
        tool_service_url = tool_config["endpoint"]
        headers = {
            "Authorization": f"Bearer {tool_service_token}",
            "Content-Type": "application/json"
        }
        params = {"city": city}
        async with httpx.AsyncClient(verify=False) as client:
            try:
                print(f"AgentService: [RESUME] Calling ToolService at {tool_service_url} with city: {city}")
                response = await client.get(tool_service_url, headers=headers, params=params, timeout=10.0)
                response.raise_for_status()
                tool_response_data = response.json()
                print(f"AgentService: [RESUME] Received response from ToolService: {tool_response_data}")
            except Exception as e:
                print(f"AgentService: [RESUME] Error calling ToolService: {e}")
                raise HTTPException(status_code=500, detail=f"Error calling ToolService on resume: {e}")
        return {
            "agent_message": f"Agent resumed and completed request for user {current_user.name} (weather_tool).",
            "tool_service_response": tool_response_data
        }


@app.get("/auth/callback")
async def consent_callback(request: Request):
    """
    Handles the redirect from the authorization server after user consent.
    Exchanges the code for a token and marks the invocation as ready to resume.
    """
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    invocation_id = state
    if not code or not invocation_id:
        return HTMLResponse("Missing code or invocation_id (state).", status_code=400)

    paused = paused_invocations.get(invocation_id)
    if not paused:
        return HTMLResponse("No paused invocation found for this ID.", status_code=404)

    # --- Lookup tool config from registry (simulate weather_tool for now) ---
    tool_id = paused.get("tool_id", "weather_tool")  # Default to weather_tool for this demo
    tool_config = TOOL_REGISTRY.get(tool_id)
    if not tool_config:
        return HTMLResponse(f"Tool config not found for tool_id: {tool_id}", status_code=500)
    tool_as_type = tool_config["as_type"]

    user_oid = paused["user"].oid if paused.get("user") and hasattr(paused["user"], "oid") else None
    scopes_needed = frozenset(tool_config["scopes"])
    token_cache_key = (user_oid, tool_as_type, scopes_needed)
    if tool_as_type == "entra_id":
        import msal
        msal_app = msal.ConfidentialClientApplication(
            client_id=tool_config["client_id"],
            authority=tool_config["authority"],
            client_credential=tool_config["client_secret"],
        )
        try:
            result = msal_app.acquire_token_by_authorization_code(
                code=code,
                scopes=tool_config["scopes"],
                redirect_uri=tool_config["redirect_uri"]
            )
            if "access_token" in result:
                paused["tool_access_token"] = result["access_token"]
                paused["consent_complete"] = True
                paused_invocations[invocation_id] = paused
                return HTMLResponse("Consent complete. Please return to the app and click Resume.")
            else:
                error = result.get("error_description", str(result))
                return HTMLResponse(f"Token exchange failed: {error}", status_code=400)
        except Exception as e:
            return HTMLResponse(f"Exception during token exchange: {str(e)}", status_code=500)
    elif tool_as_type == "github":
        # Real GitHub token exchange
        token_url = tool_config["token_url"]
        client_id = tool_config["client_id"]
        client_secret = tool_config["client_secret"]
        redirect_uri = tool_config["redirect_uri"]
        try:
            response = requests.post(
                token_url,
                headers={"Accept": "application/json"},
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                timeout=10,
            )
            token_data = response.json()
            access_token = token_data.get("access_token")
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data.get("expires_in")
            if not access_token:
                return HTMLResponse(f"GitHub token exchange failed: {token_data}", status_code=400)
            paused["tool_access_token"] = access_token
            paused["consent_complete"] = True
            paused_invocations[invocation_id] = paused
            # Store in persistent token cache by (user_oid, as_type, scopes)
            token_cache[token_cache_key] = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "expires_at": None  # Optionally, calculate expiry time
            }
            return HTMLResponse("GitHub consent complete. Please return to the app and click Resume.")
        except Exception as e:
            return HTMLResponse(f"Exception during GitHub token exchange: {str(e)}", status_code=500)
    else:
        return HTMLResponse("Tool AS not supported yet.", status_code=501)


def _build_consent_url(redirect_uri: Optional[str] = None):
    # Construct a consent URL for the user to grant the required permissions
    tenant_id = settings.AGENT_TENANT_ID
    client_id = settings.AGENT_CLIENT_ID
    scopes = settings.TOOL_SERVICE_SCOPES
    if isinstance(scopes, list):
        scopes_str = ' '.join(scopes)
    else:
        scopes_str = str(scopes)
    # Use provided redirect_uri or fallback to config
    redirect_uri_final = redirect_uri or settings.AGENT_REDIRECT_URI
    base_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
    url = f"{base_url}?client_id={client_id}&response_type=code&redirect_uri={redirect_uri_final}&response_mode=query&scope={scopes_str}&prompt=consent"
    return url
