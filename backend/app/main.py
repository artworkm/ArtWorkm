
import secrets

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session

from .database import engine, Base, get_db
from . import models
from .schemas import OrgCreate, EventIn
from .detector import detect
from .rules import check_bruteforce, check_sql_injection


# Create database tables if they do not already exist.
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="SentinelAI API",
    description="AI-powered intrusion detection backend",
    version="1.0.0"
)


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/organizations")
def create_organization(
    organization: OrgCreate,
    db: Session = Depends(get_db)
):
 @app.get("/organizations")
 def get_organizations(db: Session = Depends(get_db)):
    organizations = db.query(models.Organization).all()

    return [
        {
            "id": org.id,
            "name": org.name,
            "created_at": org.created_at
        }
        for org in organizations
    ]

    # Prevent duplicate organization names.
    existing = db.query(models.Organization).filter(
        models.Organization.name == organization.name
    ).first()

    if existing:
        raise HTTPException(
            status_code=400,
            detail="Organization already exists."
        )

    new_organization = models.Organization(
        name=organization.name,
        api_key=secrets.token_urlsafe(32)
    )

    db.add(new_organization)
    db.commit()
    db.refresh(new_organization)

    return {
        "id": new_organization.id,
        "name": new_organization.name,
        "api_key": new_organization.api_key
    }


@app.post("/events")
def create_event(
    event: EventIn,
    db: Session = Depends(get_db)
):
    # Verify that the organization exists.
    organization = db.query(models.Organization).filter(
        models.Organization.id == event.org_id
    ).first()

    if not organization:
        raise HTTPException(
            status_code=404,
            detail="Organization not found."
        )

    # Store the incoming security event.
    new_event = models.SecurityEvent(
        org_id=event.org_id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        dest_ip=event.dest_ip,
        event_type=event.event_type,
        username=event.username,
        success=event.success,
        features=event.features
    )

    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    detections = []

    # Rule 1: Detect brute-force login attempts.
    is_login_event = (
        event.event_type is not None
        and (
            "login" in event.event_type.lower()
            or "auth" in event.event_type.lower()
        )
    )

    if is_login_event and check_bruteforce(
        event.source_ip or "",
        event.success
    ):
        detections.append({
            "model_name": "RuleBased",
            "predicted_label": "BruteForce",
            "confidence": 1.0,
            "severity": "high",
            "explanation": (
                "Five or more failed login attempts "
                "from the same IP within five minutes."
            )
        })

    # Rule 2: Detect suspicious SQL injection text.
    text_to_check = " ".join(
        str(value)
        for value in [
            event.event_type,
            event.username,
            event.source_ip,
            event.dest_ip
        ]
        if value is not None
    )

    if check_sql_injection(text_to_check):
        detections.append({
            "model_name": "RuleBased",
            "predicted_label": "WebAttack",
            "confidence": 1.0,
            "severity": "high",
            "explanation": "A suspicious SQL injection pattern was detected."
        })

    # Machine learning detection.
    if event.features:
        try:
            ml_result = detect(event.features)

            # Store only non-benign ML detections.
            if ml_result["predicted_label"] != "BENIGN":
                detections.append(ml_result)

        except Exception as error:
            raise HTTPException(
                status_code=400,
                detail=f"Model detection failed: {str(error)}"
            )

    # Save every detection result.
    for result in detections:
        detection = models.DetectionResult(
            event_id=new_event.id,
            model_name=result["model_name"],
            predicted_label=result["predicted_label"],
            confidence=result["confidence"],
            severity=result["severity"],
            explanation=result["explanation"]
        )

        db.add(detection)

    db.commit()

    return {
        "event_id": new_event.id,
        "org_id": new_event.org_id,
        "detections": detections
    }


@app.get("/events")
def get_events(
    org_id: int,
    db: Session = Depends(get_db)
):
    events = db.query(models.SecurityEvent).filter(
        models.SecurityEvent.org_id == org_id
    ).order_by(
        models.SecurityEvent.id.desc()
    ).all()

    return events


@app.get("/detections")
def get_detections(
    org_id: int,
    db: Session = Depends(get_db)
):
    detections = (
        db.query(models.DetectionResult)
        .join(
            models.SecurityEvent,
            models.DetectionResult.event_id == models.SecurityEvent.id
        )
        .filter(models.SecurityEvent.org_id == org_id)
        .order_by(models.DetectionResult.id.desc())
        .all()
    )

    return detections
