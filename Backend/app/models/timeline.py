from sqlalchemy import Column, String, Float, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from ..database import Base
from datetime import datetime, timezone


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(String, primary_key=True)
    alert_id = Column(String, ForeignKey("alerts.id"), nullable=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    event_type = Column(String, nullable=False)
    source = Column(String, nullable=True)
    asset = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=True)
    confidence = Column(Float, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    alert = relationship("Alert", back_populates="timeline")
    incident = relationship("Incident", back_populates="timeline")
