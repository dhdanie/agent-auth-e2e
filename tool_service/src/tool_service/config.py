# tool_service_fastapi/config.py

import os  # Import os module
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List
from pathlib import Path
from dotenv import load_dotenv

# Determine the base directory of this config file
CONFIG_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE_PATH = CONFIG_DIR / ".env"

# Explicitly load the .env file if it exists
if ENV_FILE_PATH.exists():
    load_dotenv(dotenv_path=ENV_FILE_PATH, override=True)
    print(f"Successfully loaded .env file from: {ENV_FILE_PATH}")
else:
    print(
        f"Warning: .env file not found at {ENV_FILE_PATH}. Relying on environment variables."
    )


class Settings(BaseSettings):
    # === Entra ID Application (ToolServiceApp) Details ===
    TENANT_ID: str
    AUDIENCE: str

    # === Token Validation Parameters ===
    @property
    def ISSUER(self) -> str:
        return f"https://login.microsoftonline.com/{self.TENANT_ID}/v2.0"

    @property
    def JWKS_URI(self) -> str:
        return f"https://login.microsoftonline.com/{self.TENANT_ID}/discovery/v2.0/keys"

    DEFAULT_REQUIRED_SCOPES: List[str] = ["Tool.Execute"]

    # We are manually passing TENANT_ID and AUDIENCE,
    # so env_file in model_config is less critical for them,
    # but can be kept for other potential settings or future use.
    model_config = SettingsConfigDict(
        env_file=str(ENV_FILE_PATH),
        env_file_encoding="utf-8",
        extra="ignore",
    )


# --- Manually fetch critical environment variables and instantiate Settings ---
# This provides a more direct way if automatic loading is problematic.

# Fetch from environment (populated by load_dotenv or system env vars)
tenant_id_env = os.getenv("TENANT_ID")
audience_env = os.getenv("AUDIENCE")

# Check if the critical variables were found
if not tenant_id_env:
    print(
        "Error: TENANT_ID not found in environment variables or .env file. Please set it."
    )
    # You might want to raise an exception or exit here if these are critical
    # For now, we'll let Pydantic raise the validation error if it's still an issue.
if not audience_env:
    print(
        "Error: AUDIENCE not found in environment variables or .env file. Please set it."
    )

try:
    # Instantiate Settings by explicitly passing the critical values
    # Pydantic will still validate them against the type hints.
    # Other fields (like DEFAULT_REQUIRED_SCOPES) will use their defaults
    # or could be loaded from env if model_config is still active for them.
    if tenant_id_env and audience_env:
        settings = Settings(TENANT_ID=tenant_id_env, AUDIENCE=audience_env)
    else:
        # Fallback to Pydantic's default loading if manual fetch failed,
        # which will likely raise the validation error if they are still missing.
        print(
            "Warning: Manually fetched TENANT_ID or AUDIENCE is missing. Attempting Pydantic default load."
        )
        settings = Settings()

except Exception as e:
    print(f"Error instantiating Settings: {e}")
    print(
        "Please ensure TENANT_ID and AUDIENCE are correctly set in your .env file or environment variables."
    )
    raise
