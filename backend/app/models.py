
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
    request_path = Column(String, nullable=True)
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


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="admin")
    org_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )
    created_at = Column(DateTime, default=datetime.utcnow)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    org_id = Column(
        Integer,
        ForeignKey("organizations.id"),
        nullable=False,
        index=True
    )
    name = Column(String(100), nullable=False)
    key_hash = Column(String(64), unique=True, nullable=False, index=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
