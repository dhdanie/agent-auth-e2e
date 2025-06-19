# src/agent_service/auth_utils.py

import requests
import msal
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt
from pydantic import BaseModel

from .config import settings

# --- Token Validation for Incoming Tokens (to AgentServiceApp) ---
oauth2_scheme_agent = OAuth2PasswordBearer(tokenUrl="token_agent", auto_error=False)
JWKS_CACHE_AGENT: Dict[str, Dict] = {}

class AgentTokenData(BaseModel):
    sub: Optional[str] = None
    name: Optional[str] = None
    oid: Optional[str] = None
    scp: Optional[str] = None
    # Add other claims you expect from the token issued by WebApp-UI for AgentServiceApp

def get_jwks_agent() -> Dict:
    global JWKS_CACHE_AGENT
    if not JWKS_CACHE_AGENT.get(settings.JWKS_URI):
        try:
            response = requests.get(settings.JWKS_URI, timeout=10)
            response.raise_for_status()
            JWKS_CACHE_AGENT[settings.JWKS_URI] = response.json()
        except requests.exceptions.RequestException as e:
            print(f"AgentService: Error fetching JWKS for incoming token: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not retrieve signing keys for incoming token.",
            )
    return JWKS_CACHE_AGENT[settings.JWKS_URI]

def get_signing_key_agent(token: str) -> Dict:
    jwks = get_jwks_agent()
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid incoming token header: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    rsa_key = {}
    if "kid" not in unverified_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incoming token header missing 'kid'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"], "kid": key["kid"], "use": key["use"],
                "n": key["n"], "e": key["e"],
            }
            if "x5c" in key: rsa_key["x5c"] = key["x5c"]
            break

    if not rsa_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to find appropriate signing key for incoming token (kid: {unverified_header['kid']})",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return rsa_key

async def get_current_user_agent(
    # security_scopes: SecurityScopes, # If AgentServiceApp defines its own scopes for WebApp-UI to request
    token: Optional[str] = Depends(oauth2_scheme_agent)
) -> AgentTokenData:
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated (no token for AgentService)",
            headers={"WWW-Authenticate": "Bearer"},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials for AgentService token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    # scope_exception = HTTPException( # If AgentServiceApp has its own scopes
    #     status_code=status.HTTP_403_FORBIDDEN,
    #     detail="Not enough permissions for AgentService",
    #     headers={"WWW-Authenticate": f"Bearer scope=\"{security_scopes.scope_str}\""},
    # )

    try:
        signing_key = get_signing_key_agent(token)
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.AGENT_AUDIENCE, # Validates token is for AgentServiceApp
            issuer=settings.ISSUER,
        )
        token_data = AgentTokenData(**payload)

        # If AgentServiceApp defines its own scopes that WebApp-UI must request:
        # if token_data.scp is None: raise scope_exception
        # token_scopes = token_data.scp.split()
        # for scope in security_scopes.scopes:
        #     if scope not in token_scopes: raise scope_exception

        return token_data
    except JWTError as e:
        print(f"AgentService: JWT Validation Error for incoming token: {e}")
        raise credentials_exception from e
    except Exception as e:
        print(f"AgentService: Unexpected error during incoming token validation: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Error validating incoming token.")

# --- On-Behalf-Of (OBO) Token Acquisition ---
msal_app = None
token_cache = msal.SerializableTokenCache() # In-memory cache for this example

def get_msal_app():
    global msal_app
    if not msal_app:
        msal_app = msal.ConfidentialClientApplication(
            client_id=settings.AGENT_CLIENT_ID,
            authority=settings.AUTHORITY,
            client_credential=settings.AGENT_CLIENT_SECRET,
            token_cache=token_cache # For caching OBO tokens
        )
    return msal_app

class ConsentRequiredException(Exception):
    def __init__(self, required_scopes, consent_url, error_description=None):
        self.required_scopes = required_scopes
        self.consent_url = consent_url
        self.error_description = error_description
        super().__init__(error_description or "Consent required for additional scopes.")

async def get_obo_token_for_tool_service(user_assertion: str) -> Optional[str]:
    """
    Acquires an OBO token for ToolServiceApp.
    user_assertion is the access token received by AgentServiceApp from WebApp-UI.
    """
    app = get_msal_app()

    # Check cache first (MSAL handles this internally if cache is provided)
    accounts = app.get_accounts() # May not be useful for OBO directly unless you manage accounts by user OID

    # For OBO, we typically acquire token silently first, then by assertion if needed.
    # MSAL's acquire_token_on_behalf_of handles this logic.

    result = app.acquire_token_on_behalf_of(
        user_assertion=user_assertion,
        scopes=settings.TOOL_SERVICE_SCOPES
    )

    if "access_token" in result:
        return result["access_token"]
    else:
        error_description = result.get("error_description", "No error description provided.")
        print(f"AgentService: OBO token acquisition failed: {result.get('error')}")
        print(f"AgentService: OBO error details: {error_description}")

        # Specific check for consent-related issues
        if "AADSTS65001" in error_description or "interaction_required" in result.get("error", ""):
            # Build consent URL for all required scopes
            from .main import _build_consent_url
            consent_url = _build_consent_url()
            raise ConsentRequiredException(
                required_scopes=settings.TOOL_SERVICE_SCOPES,
                consent_url=consent_url,
                error_description=error_description
            )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to acquire OBO token for ToolService: {error_description}"
        )