
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from datetime import datetime

from .database import Base


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    api_key = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    events = relationship("SecurityEvent", back_populates="organization")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)

    timestamp = Column(DateTime, default=datetime.utcnow)
    source_ip = Column(String)
    dest_ip = Column(String)
    event_type = Column(String)
    username = Column(String)
    success = Column(Boolean)
    features = Column(JSON)

    organization = relationship("Organization", back_populates="events")
    detections = relationship("DetectionResult", back_populates="event")


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=False)

    model_name = Column(String)
    predicted_label = Column(String)
    confidence = Column(Float)
    severity = Column(String)
    explanation = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    event = relationship("SecurityEvent", back_populates="detections")
