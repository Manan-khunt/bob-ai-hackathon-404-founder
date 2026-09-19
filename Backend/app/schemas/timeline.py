from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class TimelineEventOut(BaseModel):
    id: str
    event_type: str
    source: Optional[str] = None
    asset: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    timestamp: datetime

    class Config:
        from_attributes = True
