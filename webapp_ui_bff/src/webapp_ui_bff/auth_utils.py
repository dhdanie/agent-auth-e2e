# src/webapp_ui_bff/auth_utils.py
import typing

import msal
# Removed: import uuid (state generation now in main.py)
from fastapi import Request, HTTPException, status
from urllib.parse import urlparse

from .config import settings

# Initialize MSAL Confidential Client Application
msal_app = msal.ConfidentialClientApplication(
    client_id=settings.BFF_CLIENT_ID,
    authority=settings.BFF_AUTHORITY,
    client_credential=settings.BFF_CLIENT_SECRET,
)


# --- OIDC Flow Functions ---

def build_auth_url(request: Request, state: str, scopes: list = None) -> str:
    """
    Builds the MSAL authorization URL.
    The 'state' is generated and stored in the session by the calling route (e.g., /login).
    """
    if not scopes:
        scopes = settings.AGENT_SERVICE_SCOPES

    redirect_uri = str(settings.BFF_REDIRECT_URI)  # Ensure this is HTTPS
    auth_url = msal_app.get_authorization_request_url(
        scopes=scopes,
        state=state,  # Use the state passed from the /login route
        redirect_uri=redirect_uri,
    )
    print(f"AUTH_UTILS: build_auth_url - Generated auth URL. State: {state}, Redirect URI: {redirect_uri}")
    return auth_url


async def get_token_from_code(request: Request, expected_state: typing.Optional[str]) -> dict:
    """
    Acquires tokens using the authorization code.
    Verifies the returned state against the expected_state (retrieved from session by the calling route).
    Returns the token result dictionary.
    """
    returned_state = request.query_params.get("state")
    print(
        f"AUTH_UTILS: get_token_from_code - Returned state: {returned_state}, Expected state from session: {expected_state}")

    if not expected_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication state missing from session. Please try logging in again."
        )
    if not returned_state or returned_state != expected_state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Authentication state mismatch. Possible CSRF attack."
        )

    auth_code = request.query_params.get("code")
    if not auth_code:
        error = request.query_params.get("error")
        error_description = request.query_params.get("error_description")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Authentication failed at Entra ID: {error} - {error_description}"
        )

    redirect_uri = str(settings.BFF_REDIRECT_URI)  # Ensure this is HTTPS
    print(
        f"AUTH_UTILS: get_token_from_code - Acquiring token with code. Scopes: {settings.AGENT_SERVICE_SCOPES}, Redirect URI: {redirect_uri}")
    token_result = msal_app.acquire_token_by_authorization_code(
        code=auth_code,
        scopes=settings.AGENT_SERVICE_SCOPES,
        redirect_uri=redirect_uri
    )

    if "error" in token_result:
        print(f"AUTH_UTILS: get_token_from_code - Error acquiring token: {token_result.get('error_description')}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to acquire token: {token_result.get('error_description')}"
        )

    print(
        f"AUTH_UTILS: get_token_from_code - Token acquired successfully. User claims name: {token_result.get('id_token_claims', {}).get('name', 'No name in claims')}")
    return token_result


def build_logout_url(request: Request) -> str:
    """
    Builds the Entra ID logout URL.
    Session clearing is handled by the /logout route in main.py.
    """
    # Determine post_logout_redirect_uri based on the current request's scheme and host
    # This ensures it works correctly whether running locally (https://localhost:8000)
    # or in a deployed environment.
    parsed_url = urlparse(str(request.url_for('/')))  # Get base URL for root
    post_logout_redirect_uri = f"{parsed_url.scheme}://{parsed_url.netloc}/"

    logout_url = msal_app.get_sign_out_url(
        post_logout_redirect_uri=post_logout_redirect_uri
    )
    print(f"AUTH_UTILS: build_logout_url - Generated Entra ID logout URL. Post logout URI: {post_logout_redirect_uri}")
    return logout_url
