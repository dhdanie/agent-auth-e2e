# src/webapp_ui_bff/config.py

import os
from pydantic import field_validator, AnyHttpUrl, model_validator # Added model_validator for completeness
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union, Any # Union is already here, good.
from pathlib import Path
from dotenv import load_dotenv

# Determine the base directory of this config file
# .env is at the project root, two levels up from src/webapp_ui_bff/
CONFIG_FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT_DIR = CONFIG_FILE_DIR.parent.parent
ENV_FILE_PATH = PROJECT_ROOT_DIR / ".env"

if ENV_FILE_PATH.exists():
    load_dotenv(dotenv_path=ENV_FILE_PATH, override=True)
    print(f"WebAppUI-BFF: Successfully loaded .env file from: {ENV_FILE_PATH}")
else:
    print(
        f"WebAppUI-BFF: Warning: .env file not found at {ENV_FILE_PATH}. Relying on environment variables."
    )


class Settings(BaseSettings):
    # === WebAppUI-BFF Entra ID Details ===
    BFF_TENANT_ID: str
    BFF_CLIENT_ID: str
    BFF_CLIENT_SECRET: str
    BFF_REDIRECT_URI: AnyHttpUrl
    # Allow Pydantic to initially see this as a string from the env,
    # then our validator will convert it to List[str]
    AGENT_SERVICE_SCOPES: Union[str, List[str]] # <-- Key change here!

    # === AgentServiceApp Details ===
    AGENT_SERVICE_BASE_URL: AnyHttpUrl

    # === Session Management ===
    SESSION_SECRET_KEY: str

    # === MSAL Configuration (derived properties) ===
    @property
    def BFF_AUTHORITY(self) -> str:
        return f"https://login.microsoftonline.com/{self.BFF_TENANT_ID}"

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False
    )

    @field_validator("AGENT_SERVICE_SCOPES", mode='before')
    @classmethod
    def parse_comma_separated_scopes(cls, v: Any) -> List[str]:
        print(f"DEBUG: AGENT_SERVICE_SCOPES validator called with: {v} (type: {type(v)})") # Add this debug print
        if isinstance(v, str):
            if not v.strip():
                return []
            return [scope.strip() for scope in v.split(',') if scope.strip()]
        if isinstance(v, list):
            return v # Already a list
        # If the env var is missing and the field is not Optional, Pydantic will raise an error.
        if v is not None:
            raise TypeError('AGENT_SERVICE_SCOPES: Expected a comma-separated string or a list.')
        # If v is None (env var not set), Pydantic will handle the "required" error
        # because the field is not Optional.
        # If you wanted to default to an empty list if the env var is missing:
        # return []
        raise ValueError("AGENT_SERVICE_SCOPES is required and was not found or was None.")

    # Optional: Add a model_validator to ensure the final type is List[str] after all processing
    @model_validator(mode='after')
    def check_final_scopes_type(self) -> 'Settings':
        if not isinstance(self.AGENT_SERVICE_SCOPES, list):
            # This should ideally not be reached if parse_comma_separated_scopes works
            raise ValueError(f"AGENT_SERVICE_SCOPES ended up as {type(self.AGENT_SERVICE_SCOPES)}, expected list.")
        if not all(isinstance(item, str) for item in self.AGENT_SERVICE_SCOPES):
            raise ValueError("All items in AGENT_SERVICE_SCOPES must be strings.")
        return self

try:
    # Optional: Add debug print for the raw env var before Settings instantiation
    # print(f"DEBUG: Raw AGENT_SERVICE_SCOPES from env: {os.getenv('AGENT_SERVICE_SCOPES')}")
    settings = Settings()
    # Verify critical settings after load
    print(f"BFF Authority: {settings.BFF_AUTHORITY}")
    print(f"BFF Redirect URI: {settings.BFF_REDIRECT_URI}")
    print(f"Agent Service Scopes: {settings.AGENT_SERVICE_SCOPES} (type: {type(settings.AGENT_SERVICE_SCOPES)})") # Added type check

except Exception as e:
    print(f"WebAppUI-BFF: Error instantiating Settings: {e}")
    import traceback
    traceback.print_exc() # Print full traceback for better debugging
    raise