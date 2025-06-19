# tool_service_fastapi/main.py

from typing import Dict, List

from fastapi import FastAPI, Depends, Security, HTTPException, status, Query
from pydantic import BaseModel

from .auth_utils import get_current_user, TokenData  # Import from the current package
from .config import settings  # Import from the current package

app = FastAPI(
    title="ToolServiceApp API",
    description="A service that provides tools requiring OAuth 2.0 authorization.",
    version="0.1.0",
)


# --- Pydantic Models for Request/Response ---
class WeatherReportResponse(BaseModel):
    user: str
    report: str
    message: str


class AnotherToolInput(BaseModel):
    input: str = "default input"


class AnotherToolResponse(BaseModel):
    result: str


# --- API Endpoints ---


@app.get("/")
async def home() -> Dict[str, str]:
    return {"message": "Tool Service is running with FastAPI!"}


@app.get(
    "/api/checkweather",
    response_model=WeatherReportResponse,
    summary="Checks the weather (simulated)",
    description="Requires a valid token with 'Tool.Execute' and 'Weather.Read' scopes.",
    dependencies=[Security(get_current_user, scopes=["Tool.Execute", "Weather.Read"])],
)
async def check_weather(
    city: str = Query(
        "your current location based on profile",
        description="City to check weather for",
    ),
    current_user: TokenData = Depends(get_current_user),  # Get the validated token data
) -> WeatherReportResponse:
    """
    A dummy endpoint that simulates checking the weather.
    """
    user_name = current_user.name or "User"  # Get user's name from token
    user_oid = current_user.oid

    # Simulate tool execution
    weather_report_text = f"Hello, {user_name} (oid: {user_oid})! The weather in {city} is sunny and 25°C."

    print(
        f"ToolService: Successfully executed 'checkweather' for user {user_name} (oid: {user_oid})."
    )
    print(f"Token Scopes: {current_user.scp}")
    print(
        f"Token Audience: {settings.AUDIENCE}"
    )  # Assuming audience is a single string in settings
    print(f"Token Issuer: {settings.ISSUER}")

    return WeatherReportResponse(
        user=user_name,
        report=weather_report_text,
        message="Weather data retrieved successfully via ToolServiceApp.",
    )


@app.post(
    "/api/anothertool",
    response_model=AnotherToolResponse,
    summary="Executes another dummy tool",
    description="Requires a valid token with 'Tool.Execute' scope.",
    dependencies=[Security(get_current_user, scopes=["Tool.Execute"])],
)
async def another_tool(
    payload: AnotherToolInput, current_user: TokenData = Depends(get_current_user)
) -> AnotherToolResponse:
    """
    Another dummy tool endpoint.
    """
    user_name = current_user.name or "User"
    tool_input = payload.input

    result_text = f"Tool processed '{tool_input}' for {user_name}."
    print(f"ToolService: Successfully executed 'anothertool' for user {user_name}.")
    return AnotherToolResponse(result=result_text)


# --- Lifecycle Events (Optional, for printing config on startup) ---
@app.on_event("startup")
async def startup_event():
    print("--- ToolServiceApp (FastAPI) Starting Up ---")
    print(f"Tenant ID: {settings.TENANT_ID}")
    print(f"Expected Token Audience (aud): {settings.AUDIENCE}")
    print(f"Expected Token Issuer: {settings.ISSUER}")
    print(f"Default Required Scopes (example): {settings.DEFAULT_REQUIRED_SCOPES}")
    print("-------------------------------------------")
