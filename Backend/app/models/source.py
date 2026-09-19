from sqlalchemy import Column, String, Float, Integer, DateTime
from ..database import Base
from datetime import datetime, timezone


class Source(Base):
    __tablename__ = "sources"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)
    description = Column(String, nullable=True)
    coverage = Column(String, nullable=True)
    status = Column(String, nullable=False, default="Healthy")
    health = Column(String, nullable=False, default="Operational")
    events_per_min = Column(Integer, nullable=False, default=0)
    latency_ms = Column(Float, nullable=False, default=0.0)
    last_update = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    uptime_pct = Column(Float, nullable=False, default=100.0)
    total_events = Column(Integer, nullable=False, default=0)
