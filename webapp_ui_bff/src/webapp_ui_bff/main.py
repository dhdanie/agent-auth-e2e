# src/webapp_ui_bff/main.py

import httpx
import typing
from fastapi import FastAPI, Depends, Request, HTTPException, status, Response
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import os
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response as StarletteResponse

from .config import settings, PROJECT_ROOT_DIR
from . import auth_utils

# --- Simple In-Memory Session Store Implementation ---
# This is a basic implementation for development/testing.
# For production, consider a more robust store like RedisStore from starlette-redis.
# The session data is expected to be a dictionary (dict) by ISessionBackend
_in_memory_session_data_storage: typing.Dict[str, dict] = {}

SESSION_COOKIE_NAME = "session_id"
SESSION_COOKIE_MAX_AGE = 60 * 60 * 4  # 4 hours


class SessionMiddlewareCustom(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id or session_id not in _in_memory_session_data_storage:
            session_id = str(uuid.uuid4())
            _in_memory_session_data_storage[session_id] = {}
        request.state.session_id = session_id
        request.state.session = _in_memory_session_data_storage[session_id]
        response: StarletteResponse = await call_next(request)
        response.set_cookie(
            SESSION_COOKIE_NAME,
            session_id,
            max_age=SESSION_COOKIE_MAX_AGE,
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax",
        )
        return response


def get_session(request: Request) -> dict:
    return request.state.session


def save_session(request: Request):
    _in_memory_session_data_storage[request.state.session_id] = request.state.session


# --- FastAPI App Setup ---
app = FastAPI(
    title="WebAppUI-BFF API",
    description="Backend-For-Frontend for the WebApp UI, handling auth and proxying to AgentService.",
    version="0.1.0"
)

# --- Session Management Setup (using starlette-session) ---
app.add_middleware(
    SessionMiddlewareCustom,
)

# --- Static Files and Templates ---
app.mount(
    "/static",
    StaticFiles(directory=PROJECT_ROOT_DIR / "src" / "webapp_ui_bff" / "static"),
    name="static"
)
templates = Jinja2Templates(
    directory=PROJECT_ROOT_DIR / "src" / "webapp_ui_bff" / "templates"
)


# --- Favicon Route ---
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = PROJECT_ROOT_DIR / "src" / "webapp_ui_bff" / "static" / "favicon.ico"
    if os.path.exists(favicon_path) and os.path.isfile(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    else:
        return Response(status_code=status.HTTP_204_NO_CONTENT)


# --- Dependency for checking authentication ---
async def get_authenticated_user(request: Request) -> dict:
    # starlette-session uses request.session as a dictionary-like object
    user_session_data = request.state.session.get("user")
    print(
        f"MAIN: get_authenticated_user dependency called for URL: {request.url}. User in session: {'Yes' if user_session_data else 'No'}")

    if not user_session_data:
        print(f"MAIN: get_authenticated_user - User NOT found in session. Redirecting to /login.")
        redirect_path = str(request.url)
        if request.url.path in ["/login", "/auth/callback"]:
            redirect_path = "/"  # Default to root if coming from auth paths

        # Store the intended redirect path in a temporary cookie
        # This is because the session might not be fully established yet for the /login redirect
        response = RedirectResponse(url="/login", status_code=status.HTTP_307_TEMPORARY_REDIRECT)
        response.set_cookie(
            key="auth_redirect_path_temp",
            value=redirect_path,
            max_age=300,  # Valid for 5 minutes
            httponly=True,
            secure=True,  # Assuming HTTPS
            samesite="lax",
            path="/"
        )
        raise HTTPException(
            status_code=response.status_code,
            detail="Not authenticated",
            headers=dict(response.headers)
        )

    print(f"MAIN: get_authenticated_user - User '{user_session_data.get('name', 'N/A')}' authenticated.")
    return user_session_data


# --- Authentication Routes ---
@app.get("/login")
async def login(request: Request):
    print(f"MAIN: /login route hit. Current session keys: {list(request.state.session.keys())}")
    state = str(uuid.uuid4())
    request.state.session["auth_state"] = state  # Store state in the session

    # Retrieve the intended redirect path from the temporary cookie if it exists
    redirect_path_temp = request.cookies.get("auth_redirect_path_temp")
    if redirect_path_temp:
        request.state.session["auth_redirect_path"] = redirect_path_temp
        print(f"MAIN: /login - Stored auth_redirect_path from temp cookie: {redirect_path_temp}")
    else:
        request.state.session["auth_redirect_path"] = "/"  # Default
        print(f"MAIN: /login - No temp redirect path found, defaulting to /")

    auth_url = auth_utils.build_auth_url(request, state=state)  # Pass state to auth_utils

    # The response for redirecting to login should also clear the temp cookie
    response = RedirectResponse(url=auth_url, status_code=status.HTTP_302_FOUND)
    if redirect_path_temp:
        response.delete_cookie(key="auth_redirect_path_temp", secure=True, samesite="lax", path="/")

    print(f"MAIN: /login - Redirecting to auth URL. State stored in session: {state}")
    return response


@app.get("/auth/callback")
async def auth_callback(request: Request):
    print(f"MAIN: /auth/callback entered. Query params: {request.query_params}")
    print(f"MAIN: /auth/callback session keys BEFORE auth: {list(request.state.session.keys())}")

    expected_state = request.state.session.pop("auth_state", None)
    redirect_path = request.state.session.pop("auth_redirect_path", "/")  # Get redirect path from session

    try:
        # auth_utils.get_token_from_code now needs the expected_state
        token_result = await auth_utils.get_token_from_code(request, expected_state=expected_state)

        # Store user information and tokens in the session (as a dictionary)
        request.state.session["user"] = token_result.get("id_token_claims")
        request.state.session["access_token"] = token_result.get("access_token")
        request.state.session["refresh_token"] = token_result.get("refresh_token")
        request.state.session["token_expires_in"] = token_result.get("expires_in")
        # Consider storing token acquisition time for proactive refresh
        # import time
        # request.session["token_acquired_at"] = int(time.time())

        user_name_in_session = request.state.session.get('user', {}).get('name', 'Not in session')
        print(f"MAIN: /auth/callback successful. User in session: {user_name_in_session}")
        print(f"MAIN: /auth/callback session keys AFTER auth: {list(request.state.session.keys())}")
        print(f"MAIN: /auth/callback will redirect to: {redirect_path}")

        return RedirectResponse(url=redirect_path, status_code=status.HTTP_302_FOUND)

    except HTTPException as e:
        print(f"MAIN: Error during auth callback: {e.detail}, Status: {e.status_code}")
        # Clear potentially partial session data on error
        request.state.session.clear()
        raise e
    except Exception as e_gen:
        print(f"MAIN: Generic error during auth callback: {str(e_gen)}")
        import traceback
        traceback.print_exc()
        # Clear potentially partial session data on error
        request.state.session.clear()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                            detail="An unexpected error occurred during authentication.")


@app.get("/logout")
async def logout(request: Request):
    user_before_logout = request.state.session.get('user', {}).get('name', 'Not in session')
    print(f"MAIN: /logout route hit. User before logout: {user_before_logout}")

    # Clear the server-side session
    request.state.session.clear()
    print(f"MAIN: /logout - Session cleared. Current session keys: {list(request.state.session.keys())}")

    # Build the Entra ID logout URL
    # auth_utils.build_logout_url should just return the URL
    logout_url_entra = auth_utils.build_logout_url(request)

    # Redirect to Entra ID for logout. The session cookie will be cleared by SessionMiddleware
    # because the session is now empty.
    response = RedirectResponse(url=logout_url_entra, status_code=status.HTTP_302_FOUND)
    print(f"MAIN: /logout - Redirecting to Entra ID logout URL. Session cookie should be cleared by middleware.")
    return response


# --- BFF API Endpoints (called by the frontend) ---
@app.get("/api/bff/userinfo")
async def get_user_info(
        request: Request,
        user: dict = Depends(get_authenticated_user)  # This dependency now uses request.session
):
    # Access other session data if needed, e.g., token expiry
    token_expires = request.state.session.get("token_expires_in", "N/A")
    print(f"MAIN: /api/bff/userinfo - Token expires in: {token_expires}")
    return {"user": user}


@app.post("/api/bff/invoke-weather")
async def invoke_weather_via_agent(
        request: Request,
        city_data: dict,
        user: dict = Depends(get_authenticated_user)  # Ensures user is authenticated
):
    access_token = request.state.session.get("access_token")

    if not access_token:
        # This case should ideally not be reached if get_authenticated_user passed
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Access token not found in session.")

    agent_service_url = f"{settings.AGENT_SERVICE_BASE_URL}api/invokeagent/checkweather"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "X-Client-Id": settings.BFF_CLIENT_ID  # Pass the client ID for redirect mapping
    }
    city = city_data.get("city", "DefaultCityFromBFF")
    params = {"city": city}

    async with httpx.AsyncClient(verify=False) as client:  # verify=False for localhost self-signed certs
        try:
            print(f"BFF: Calling AgentService at {agent_service_url} with city: {city}")
            response = await client.post(agent_service_url, headers=headers, params=params)
            response.raise_for_status()
            agent_response_data = response.json()
            print(f"BFF: Received response from AgentService: {agent_response_data}")
            # Check for paused/consent_required response from Agent
            if (
                isinstance(agent_response_data, dict)
                and agent_response_data.get("status") == "paused"
                and agent_response_data.get("reason") == "consent_required"
            ):
                return agent_response_data
        except httpx.HTTPStatusError as e:
            print(f"BFF: HTTP error calling AgentService: {e.response.status_code} - {e.response.text}")
            try:
                error_json = e.response.json()
                # Pass through paused/consent_required error from Agent
                if (
                    isinstance(error_json, dict)
                    and error_json.get("status") == "paused"
                    and error_json.get("reason") == "consent_required"
                ):
                    return error_json
            except Exception:
                pass
            error_detail_from_agent = e.response.text
            try:
                error_detail_from_agent = e.response.json().get('detail', e.response.text)
            except:
                pass
            if e.response.status_code == status.HTTP_403_FORBIDDEN and "OBO consent required" in error_detail_from_agent:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Consent required for downstream service: {error_detail_from_agent}"
                )
            raise HTTPException(
                status_code=e.response.status_code,
                detail=f"Error from AgentService: {error_detail_from_agent}"
            )
        except httpx.RequestError as e:
            print(f"BFF: Request error calling AgentService: {str(e)}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Could not connect to AgentService: {str(e)}"
            )
        except Exception as e_gen:
            print(f"BFF: Generic error during AgentService call: {str(e_gen)}")
            import traceback
            traceback.print_exc()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"An unexpected error occurred while calling AgentService: {str(e_gen)}"
            )

    return {
        "bff_message": f"BFF processed request for user {user.get('name', 'Unknown')} for city {city}.",
        "agent_service_response": agent_response_data
    }


@app.post("/api/bff/resume-invocation")
async def resume_paused_invocation(request: Request):
    body = await request.json()
    invocation_id = body.get("invocation_id")
    access_token = request.state.session.get("access_token")
    if not invocation_id:
        raise HTTPException(status_code=400, detail="Missing invocation_id.")
    if not access_token:
        raise HTTPException(status_code=401, detail="Access token not found in session.")
    agent_service_url = f"{settings.AGENT_SERVICE_BASE_URL}api/invokeagent/resume"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    try:
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(agent_service_url, headers=headers, json={"invocation_id": invocation_id})
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        print(f"BFF: HTTP error calling AgentService resume: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
    except Exception as e:
        print(f"BFF: Error resuming invocation: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error resuming invocation: {str(e)}")


# --- Simple Frontend Serving ---
@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    user = request.state.session.get("user")
    print(
        f"MAIN: / read_root entered. Session keys: {list(request.state.session.keys())}. User in session: {'Yes' if user else 'No'}")

    if user:
        print(f"MAIN: / read_root - User '{user.get('name', 'N/A')}' is authenticated. Rendering index.html with user.")
    else:
        print("MAIN: / read_root - User is NOT authenticated. Rendering index.html without user.")
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "user": user}
    )


# --- Startup Event (Optional) ---
@app.on_event("startup")
async def startup_event():
    print("--- WebAppUI-BFF (FastAPI) Starting Up ---")
    print(f"BFF Client ID: {settings.BFF_CLIENT_ID}")
    print(f"BFF Authority: {settings.BFF_AUTHORITY}")
    print(f"BFF Redirect URI: {settings.BFF_REDIRECT_URI}")  # Ensure this is HTTPS
    print(f"Agent Service Scopes: {settings.AGENT_SERVICE_SCOPES}")
    print(f"Agent Service Base URL: {settings.AGENT_SERVICE_BASE_URL}")
    print(f"Session Secret Key is set: {'Yes' if settings.SESSION_SECRET_KEY else 'NO (CRITICAL ERROR!)'}")
    if not settings.SESSION_SECRET_KEY:
        print("CRITICAL: SESSION_SECRET_KEY is not set. Application will not be secure.")
    print("Using starlette-session with SimpleMemoryStore (ISessionBackend implementation).")  # Updated message
    print("-------------------------------------------")
