from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AlertCreate(BaseModel):
    source: str
    source_ip: Optional[str] = None
    asset: Optional[str] = None
    asset_ip: Optional[str] = None
    event: str
    raw_payload: Optional[str] = None
    severity: Optional[str] = "Medium"
    confidence: Optional[float] = 0.0


class AlertOut(BaseModel):
    id: str
    incidentId: Optional[str] = None
    source: str
    timestamp: str
    asset: str
    assetIp: Optional[str] = None
    event: str
    normalizedEvent: Optional[str] = None
    rawPayload: Optional[str] = None
    severity: str
    confidence: float
    correlationStatus: str
    classification: str
    mitre: Optional[str] = None
    mitreName: Optional[str] = None
    explanation: Optional[str] = None
    correlationScore: Optional[float] = None
    priorityScore: Optional[float] = None
    priorityLevel: Optional[str] = None

    class Config:
        from_attributes = True
