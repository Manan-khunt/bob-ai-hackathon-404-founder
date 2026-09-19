from pydantic import BaseModel
from typing import Optional, List


class BlufOut(BaseModel):
    bottomLine: str
    impact: str
    evidence: List[str]
    mitreMapping: List[dict]
    priorityScore: float
    priorityLevel: str
    recommendedAction: str
    generatedBy: Optional[str] = "deterministic"

    class Config:
        from_attributes = True
