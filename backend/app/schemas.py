
from typing import Optional, Literal

from pydantic import BaseModel, EmailStr, Field


class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    org_name: str


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ApiKeyCreate(BaseModel):
    name: str


class EventIn(BaseModel):
    event_type: Literal["network_flow", "auth", "web_request"]
    source_ip: str
    features: Optional[dict[str, float]] = None
    success: Optional[bool] = None
    request_path: Optional[str] = None


class AnalysisOut(BaseModel):
    summary: str
    likely_attack_technique: str
    severity_assessment: Literal["low", "medium", "high", "critical"]
    evidence_used: list[str]
    recommended_actions: list[str]
    confidence: Literal["low", "medium", "high"]
    limitations: str
