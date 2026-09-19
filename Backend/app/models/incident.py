from sqlalchemy import Column, String, Float, Integer, Text, DateTime, JSON
from sqlalchemy.orm import relationship
from ..database import Base
from datetime import datetime, timezone


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True)
    title = Column(String, nullable=False)
    status = Column(String, nullable=False, default="NEW")
    classification = Column(String, nullable=False, default="PENDING")
    severity = Column(String, nullable=False)
    confidence = Column(Float, nullable=False, default=0.0)
    priority_score = Column(Float, nullable=False, default=0.0)
    priority_level = Column(String, nullable=False, default="LOW")
    threat_type = Column(String, nullable=True)

    affected_assets = Column(JSON, nullable=False, default=list)
    sources = Column(JSON, nullable=False, default=list)
    source_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    correlation_score = Column(Float, nullable=False, default=0.0)

    mitre_ids = Column(JSON, nullable=False, default=list)
    mitre_technique = Column(String, nullable=True)

    bluf_bottom_line = Column(Text, nullable=True)
    bluf_impact = Column(Text, nullable=True)
    bluf_evidence = Column(JSON, nullable=False, default=list)
    bluf_recommended_action = Column(Text, nullable=True)
    bluf_generated_by = Column(String, nullable=True, default="deterministic")
    bluf_generated_at = Column(DateTime, nullable=True)

    summary = Column(Text, nullable=True)
    attribution = Column(Text, nullable=True)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    alerts = relationship("Alert", back_populates="incident")
    timeline = relationship("TimelineEvent", back_populates="incident", cascade="all, delete-orphan")
