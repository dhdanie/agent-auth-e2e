# src/agent_service/config.py

import os
from pathlib import Path
from typing import List, Any, Union  # Added Union

from dotenv import load_dotenv
from pydantic import field_validator, model_validator  # For Pydantic v2
from pydantic_settings import BaseSettings, SettingsConfigDict

# Determine the base directory of this config file
# Assuming .env is at the project root, two levels up from src/agent_service/
CONFIG_FILE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT_DIR = CONFIG_FILE_DIR.parent.parent
ENV_FILE_PATH = PROJECT_ROOT_DIR / ".env"

if ENV_FILE_PATH.exists():
    load_dotenv(dotenv_path=ENV_FILE_PATH, override=True)
    print(f"AgentService: Successfully loaded .env file from: {ENV_FILE_PATH}")
else:
    print(
        f"AgentService: Warning: .env file not found at {ENV_FILE_PATH}. Relying on environment variables."
    )


class Settings(BaseSettings):
    # === Entra ID Application (AgentServiceApp) Details ===
    AGENT_TENANT_ID: str
    AGENT_CLIENT_ID: str
    AGENT_CLIENT_SECRET: str
    AGENT_AUDIENCE: str
    AGENT_REDIRECT_URI: str  # Add this line

    # === Token Validation Parameters for incoming tokens ===
    @property
    def ISSUER(self) -> str:
        return f"https://login.microsoftonline.com/{self.AGENT_TENANT_ID}/v2.0"

    @property
    def JWKS_URI(self) -> str:
        return f"https://login.microsoftonline.com/{self.AGENT_TENANT_ID}/discovery/v2.0/keys"

    # === Downstream API (ToolServiceApp) Details ===
    TOOL_SERVICE_BASE_URL: str
    TOOL_SERVICE_CLIENT_ID: str
    # Allow Pydantic to initially see this as a string from the env,
    # then our validator will convert it to List[str]
    TOOL_SERVICE_SCOPES: Union[str, List[str]]

    # === MSAL Configuration ===
    @property
    def AUTHORITY(self) -> str:
        return f"https://login.microsoftonline.com/{self.AGENT_TENANT_ID}"

    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("TOOL_SERVICE_SCOPES", mode='before')
    @classmethod
    def parse_tool_service_scopes(cls, v: Any) -> List[str]:
        print(f"DEBUG: parse_tool_service_scopes called with: {v} (type: {type(v)})") # Add this
        if isinstance(v, str):
            if not v.strip():
                return []
            return [scope.strip() for scope in v.split(',') if scope.strip()]
        if isinstance(v, list):
            return v # Already a list, perhaps from direct instantiation
        # If the env var is missing and the field is not Optional, Pydantic will raise an error.
        # If it's present but not a string or list, this validator will raise an error.
        if v is not None: # Should not happen if type hint is Union[str, List[str]] and env provides a string
            raise TypeError(f'TOOL_SERVICE_SCOPES: Expected a comma-separated string or a list, got {type(v)}')
        # If v is None (meaning env var was not set AT ALL for TOOL_SERVICE_SCOPES)
        # Pydantic will raise a validation error because the field is not Optional.
        # If you wanted to provide a default empty list if the env var is missing:
        # return [] # This would make the field effectively optional with a default
        raise ValueError("TOOL_SERVICE_SCOPES is required and was not found or was None.")


    # Add a model_validator to ensure the final type is List[str]
    # This runs *after* field_validators.
    @model_validator(mode='after')
    def check_scopes_is_list(self) -> 'Settings':
        if not isinstance(self.TOOL_SERVICE_SCOPES, list):
            # This should ideally not be reached if parse_tool_service_scopes works correctly
            # and converts the string to a list.
            raise ValueError(f"TOOL_SERVICE_SCOPES ended up as {type(self.TOOL_SERVICE_SCOPES)}, expected list.")
        # Ensure all elements in the list are strings (though parse_tool_service_scopes should ensure this)
        if not all(isinstance(item, str) for item in self.TOOL_SERVICE_SCOPES):
            raise ValueError("All items in TOOL_SERVICE_SCOPES must be strings.")
        return self


# --- Instantiate Settings ---
# (Your debug prints for os.environ can remain here for now)
print("\n--- DEBUG: Environment Variables Before Pydantic Settings Instantiation ---")
relevant_vars = {
    k: v for k, v in os.environ.items() if "AGENT_" in k or "TOOL_" in k
}
for k, v in relevant_vars.items():
    print(f"{k}={v}")
print(f"Specifically, TOOL_SERVICE_SCOPES from os.environ: {os.getenv('TOOL_SERVICE_SCOPES')}")
print("--- END DEBUG ---\n")

try:
    settings = Settings()
    print(f"DEBUG: Loaded TOOL_SERVICE_SCOPES after Settings(): {settings.TOOL_SERVICE_SCOPES} (type: {type(settings.TOOL_SERVICE_SCOPES)})")
except Exception as e:
    print(f"AgentService: Error instantiating Settings: {e}")
    raise