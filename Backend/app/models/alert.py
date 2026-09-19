from sqlalchemy import Column, String, Float, Integer, Text, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from ..database import Base
from datetime import datetime, timezone


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)
    source = Column(String, nullable=False)
    source_ip = Column(String, nullable=True)
    source_type = Column(String, nullable=True)
    asset = Column(String, nullable=True)
    asset_ip = Column(String, nullable=True)
    asset_type = Column(String, nullable=True)
    event = Column(String, nullable=False)
    normalized_event = Column(String, nullable=True)
    raw_payload = Column(Text, nullable=True)
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    correlation_score = Column(Float, nullable=False, default=0.0)
    correlation_status = Column(String, nullable=False, default="UNCORRELATED")
    classification = Column(String, nullable=False, default="PENDING")
    priority_score = Column(Float, nullable=True)
    priority_level = Column(String, nullable=True)
    mitre_id = Column(String, nullable=True)
    mitre_name = Column(String, nullable=True)
    explanation = Column(Text, nullable=True)
    triage_result = Column(String, nullable=True, default="PENDING")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    processed_at = Column(DateTime, nullable=True)

    timeline = relationship("TimelineEvent", back_populates="alert", cascade="all, delete-orphan")
    incident = relationship("Incident", back_populates="alerts")
