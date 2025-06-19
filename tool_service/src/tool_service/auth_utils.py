# tool_service_fastapi/auth_utils.py

import requests
from typing import Dict, List, Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, SecurityScopes
from jose import JWTError, jwt # python-jose
from pydantic import BaseModel

from .config import settings

# This is used by FastAPI to extract the token from the Authorization header
# The tokenUrl doesn't really matter here as we are not implementing an OAuth2 server,
# but FastAPI requires it.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token", auto_error=False)

# Cache for signing keys to avoid fetching them on every request
JWKS_CACHE: Dict[str, Dict] = {}

class TokenData(BaseModel):
    sub: Optional[str] = None
    name: Optional[str] = None
    oid: Optional[str] = None
    scp: Optional[str] = None # Scopes as a space-separated string
    # Add other claims you expect or want to use

def get_jwks() -> Dict:
    """Fetches and caches JWKS from Microsoft Entra ID."""
    global JWKS_CACHE
    if not JWKS_CACHE.get(settings.JWKS_URI):
        try:
            response = requests.get(settings.JWKS_URI, timeout=10)
            response.raise_for_status()
            JWKS_CACHE[settings.JWKS_URI] = response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching JWKS: {e}")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Could not retrieve signing keys from identity provider.",
            )
    return JWKS_CACHE[settings.JWKS_URI]

def get_signing_key(token: str) -> Dict:
    """
    Given a token, find the appropriate public key from JWKS
    to verify the token's signature.
    """
    jwks = get_jwks()
    try:
        unverified_header = jwt.get_unverified_header(token)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token header: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    rsa_key = {}
    if "kid" not in unverified_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token header missing 'kid'",
            headers={"WWW-Authenticate": "Bearer"},
        )

    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }
            # If x5c is present, you might want to use it for more robust validation
            # For now, we rely on 'n' and 'e' for RSA
            if "x5c" in key:
                rsa_key["x5c"] = key["x5c"]
            break

    if not rsa_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unable to find appropriate signing key for kid: {unverified_header['kid']}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return rsa_key

async def get_current_user(
    security_scopes: SecurityScopes, # FastAPI's way to get required scopes for the endpoint
    token: Optional[str] = Depends(oauth2_scheme)
) -> TokenData:
    """
    Dependency to validate the token and return its data.
    It also checks for required scopes.
    """
    if token is None:
        # This case is handled if auto_error=False in OAuth2PasswordBearer
        # and the route explicitly allows optional authentication.
        # For protected routes, auto_error=True (default) would raise an error earlier.
        # Or, if you want to be explicit:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": f"Bearer scope=\"{security_scopes.scope_str}\""},
        )

    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    scope_exception = HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Not enough permissions",
        headers={"WWW-Authenticate": f"Bearer scope=\"{security_scopes.scope_str}\""},
    )

    try:
        signing_key = get_signing_key(token)
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.AUDIENCE,
            issuer=settings.ISSUER,
        )

        # Extract claims into our Pydantic model
        token_data = TokenData(**payload)

        if token_data.scp is None:
            raise scope_exception # No scopes in token

        token_scopes = token_data.scp.split()
        for scope in security_scopes.scopes: # Scopes required by the endpoint
            if scope not in token_scopes:
                raise scope_exception

        return token_data

    except JWTError as e:
        print(f"JWT Validation Error: {e}")
        raise credentials_exception from e
    except Exception as e: # Catch any other unexpected errors during validation
        print(f"Unexpected error during token validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error validating token."
        )

# Convenience dependency for just getting the token data without scope checks here
# Scope checks are handled by FastAPI's SecurityScopes and the get_current_user dependency
async def get_validated_token_data(token: Optional[str] = Depends(oauth2_scheme)) -> TokenData:
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        signing_key = get_signing_key(token)
        payload = jwt.decode(
            token,
            signing_key,
            algorithms=["RS256"],
            audience=settings.AUDIENCE,
            issuer=settings.ISSUER,
        )
        return TokenData(**payload)
    except JWTError as e:
        print(f"JWT Validation Error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e