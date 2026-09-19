from pydantic import BaseModel
from typing import Optional


class MetricsOut(BaseModel):
    totalAlerts: int
    correlatedIncidents: int
    trueThreats: int
    falsePositives: int
    needsReview: Optional[int] = 0
    criticalIncidents: int
    activeSources: int
    falsePositiveReductionPct: Optional[float] = 0.0
    analystWorkloadReductionPct: Optional[float] = 0.0
    meanTimeToDetectSec: Optional[float] = 0.0
    meanTimeToTriageSec: Optional[float] = 0.0

    class Config:
        from_attributes = True


class DashboardSummary(BaseModel):
    metrics: MetricsOut
    alerts_count: int
    incidents_count: int
    sources_count: int
    healthiest_source: Optional[str] = None
    most_active_source: Optional[str] = None
