from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime


class BlufSummary(BaseModel):
    bottomLine: str
    impact: str
    evidence: List[str]
    mitreMapping: List[dict]
    priorityScore: float
    priorityLevel: str
    recommendedAction: str


class AffectedAsset(BaseModel):
    asset: str
    status: str
    type: str


class TimelineEntry(BaseModel):
    time: str
    source: str
    event: str


class IncidentOut(BaseModel):
    id: str
    priorityRank: str
    priorityScore: float
    title: str
    threatType: Optional[str] = None
    classification: str
    severity: str
    confidence: float
    status: str
    mitreId: Optional[str] = None
    mitreTechnique: Optional[str] = None
    mitreIds: List[str]
    assetsCount: int
    sourcesCount: int
    sources: List[str]
    affectedAssets: List[AffectedAsset]
    summary: Optional[str] = None
    attribution: Optional[str] = None
    firstSeen: Optional[str] = None
    lastSeen: Optional[str] = None
    bluf: Optional[BlufSummary] = None
    timeline: List[TimelineEntry]
    correlationScore: Optional[float] = None

    class Config:
        from_attributes = True


class IncidentDetail(IncidentOut):
    mitreChain: List[dict]
    blastRadius: Optional[dict] = None
