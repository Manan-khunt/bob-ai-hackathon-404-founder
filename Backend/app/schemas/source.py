from pydantic import BaseModel
from typing import Optional


class SourceOut(BaseModel):
    id: str
    name: str
    type: str
    eventsPerMin: int
    health: str
    status: str
    lastUpdate: str
    latencyMs: float
    coverage: Optional[str] = None
    description: Optional[str] = None
    uptimePct: Optional[float] = None
    totalEvents: Optional[int] = None

    class Config:
        from_attributes = True
