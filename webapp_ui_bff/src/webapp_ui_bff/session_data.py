# src/webapp_ui_bff/session_data.py

from pydantic import BaseModel
from typing import Dict, Any, Optional


class SessionData(BaseModel):
    """
    Represents the data stored server-side for a user session.
    Only a unique session ID will be stored in the browser cookie.
    """
    user: Optional[Dict[str, Any]] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_expires_in: Optional[int] = None
    token_acquired_at: Optional[int] = None  # Timestamp or similar
    auth_redirect_path: Optional[str] = "/"  # Path to redirect after login
    # Add any other data you need to persist across requests here
