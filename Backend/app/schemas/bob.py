from pydantic import BaseModel
from typing import Optional, List, Any


class BobRequest(BaseModel):
    query: str
    context: Optional[dict] = None
    mode: Optional[str] = "analysis"


class BobResponse(BaseModel):
    answer: str
    confidence: Optional[float] = None
    sources: Optional[List[str]] = None
    recommendations: Optional[List[str]] = None
    mode: Optional[str] = "analysis"

    class Config:
        from_attributes = True
