from sqlalchemy import Column, String, DateTime, Text, JSON
from ..database import Base
from datetime import datetime, timezone


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String, primary_key=True)
    event_type = Column(String, nullable=False)
    entity_type = Column(String, nullable=True)
    entity_id = Column(String, nullable=True)
    details = Column(JSON, nullable=True)
    actor = Column(String, nullable=True, default="system")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
