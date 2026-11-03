
from typing import Optional
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class OrgCreate(BaseModel):
    name: str


class EventIn(BaseModel):
    org_id: int
    timestamp: Optional[datetime] = None

    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_type: Optional[str] = None
    username: Optional[str] = None
    success: Optional[bool] = None

    features: Optional[dict[str, float]] = None


class OrganizationOut(BaseModel):
    id: int
    name: str
    api_key: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EventOut(BaseModel):
    id: int
    org_id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    event_type: Optional[str] = None
    username: Optional[str] = None
    success: Optional[bool] = None
    features: Optional[dict[str, float]] = None

    model_config = ConfigDict(from_attributes=True)
