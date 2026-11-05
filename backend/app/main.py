import secrets

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request
)
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from .database import engine, Base, get_db
from . import models
from .schemas import RegisterIn, LoginIn, ApiKeyCreate, EventIn
from .security import (
    hash_password,
    verify_password,
    create_token,
    new_api_key
)
from .deps import current_user, require_admin, api_key_org
from .detector import detect
from .rules import check_bruteforce, check_sqli


# Create new tables if they do not already exist.
# Existing database tables and records are preserved.
Base.metadata.create_all(bind=engine)


# Configure rate limiting.
limiter = Limiter(key_func=get_remote_address)


app = FastAPI(
    title="SentinelAI API",
    description="AI-powered intrusion detection backend",
    version="1.0.0"
)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)


# Allow the React development server to communicate with FastAPI.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# --------------------------------------------------
# Health
# --------------------------------------------------

@app.get("/health")
def health():
    return {"status": "healthy"}


# --------------------------------------------------
# Authentication
# --------------------------------------------------

@app.post("/auth/register")
@limiter.limit("5/minute")
def register(
    request: Request,
    data: RegisterIn,
    db: Session = Depends(get_db)
):
    # Check whether the email is already registered.
    existing_user = db.query(models.User).filter(
        models.User.email == data.email
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email is already registered."
        )

        # Check whether the organization already exists.
    existing_org = db.query(models.Organization).filter(
        models.Organization.name == data.org_name
    ).first()

    if existing_org:
        # Allow the first administrator to join an existing
        # organization only when it has no registered users.
        existing_org_user = db.query(models.User).filter(
            models.User.org_id == existing_org.id
        ).first()

        if existing_org_user:
            raise HTTPException(
                status_code=400,
                detail="Organization already has a registered user."
            )

        # Reuse the existing Phase 1B organization.
        organization = existing_org

    else:
        # Create a new organization if it does not exist.
        organization = models.Organization(
            name=data.org_name,
            api_key=secrets.token_urlsafe(32)
        )

        db.add(organization)
        db.flush()

    # Create the administrator account.
    user = models.User(
        email=data.email,
        password_hash=hash_password(data.password),
        role="admin",
        org_id=organization.id
    )

    db.add(user)

    # Create the organization's first API key.
    raw_api_key, key_hash = new_api_key()

    api_key = models.ApiKey(
        org_id=organization.id,
        name="Default API Key",
        key_hash=key_hash,
        active=True
    )

    db.add(api_key)
    db.commit()

    db.refresh(user)
    db.refresh(organization)

    # Create a JWT for the newly registered user.
    token = create_token(
        user_id=user.id,
        org_id=organization.id,
        role=user.role
    )

    return {
        "message": "Registration successful",
        "user_id": user.id,
        "email": user.email,
        "org_id": organization.id,
        "org_name": organization.name,
        "access_token": token,
        "token_type": "bearer",
        "api_key": raw_api_key
    }


@app.post("/auth/login")
@limiter.limit("10/minute")
def login(
    request: Request,
    data: LoginIn,
    db: Session = Depends(get_db)
):
    user = db.query(models.User).filter(
        models.User.email == data.email
    ).first()

    if not user or not verify_password(
        data.password,
        user.password_hash
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password."
        )

    token = create_token(
        user_id=user.id,
        org_id=user.org_id,
        role=user.role
    )

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/auth/me")
def get_current_user(user=Depends(current_user)):
    return {
        "id": user.id,
        "email": user.email,
        "role": user.role,
        "org_id": user.org_id
    }


# --------------------------------------------------
# Organization
# --------------------------------------------------

@app.get("/organizations")
def get_organizations(
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    organizations = db.query(models.Organization).filter(
        models.Organization.id == user.org_id
    ).all()

    return [
        {
            "id": org.id,
            "name": org.name,
            "created_at": org.created_at
        }
        for org in organizations
    ]


# --------------------------------------------------
# API key management
# --------------------------------------------------

@app.post("/api-keys")
def create_api_key(
    data: ApiKeyCreate,
    user=Depends(require_admin),
    db: Session = Depends(get_db)
):
    raw_api_key, key_hash = new_api_key()

    api_key = models.ApiKey(
        org_id=user.org_id,
        name=data.name,
        key_hash=key_hash,
        active=True
    )

    db.add(api_key)
    db.commit()
    db.refresh(api_key)

    # The raw key is returned only once.
    return {
        "id": api_key.id,
        "name": api_key.name,
        "api_key": raw_api_key,
        "message": "Store this API key securely. It cannot be retrieved later."
    }


# --------------------------------------------------
# Security events and detection
# --------------------------------------------------

@app.post("/events")
def create_event(
    event: EventIn,
    organization=Depends(api_key_org),
    db: Session = Depends(get_db)
):
    # Store the incoming event using the existing database columns.
    new_event = models.SecurityEvent(
    org_id=organization.id,
    source_ip=event.source_ip,
    dest_ip=None,
    event_type=event.event_type,
    request_path=event.request_path,
    username=None,
    success=event.success,
    features=event.features
)

    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    detections = []

    # Rule 1: Brute-force detection.
    if event.event_type == "auth":
        brute_force_result = check_bruteforce(
            organization.id,
            event.source_ip,
            event.success
        )

        if brute_force_result:
            label, confidence, severity = brute_force_result

            detections.append({
                "model_name": "RuleBased",
                "predicted_label": label,
                "confidence": confidence,
                "severity": severity,
                "explanation": (
                    "Five or more failed login attempts "
                    "from the same IP within five minutes."
                )
            })

    # Rule 2: SQL injection detection.
    if event.event_type == "web_request":
        sqli_result = check_sqli(event.request_path or "")

        if sqli_result:
            label, confidence, severity = sqli_result

            detections.append({
                "model_name": "RuleBased",
                "predicted_label": label,
                "confidence": confidence,
                "severity": severity,
                "explanation": (
                    "A suspicious SQL injection pattern "
                    "was detected in the request path."
                )
            })

    # Rule 3: Machine-learning detection.
    if event.features:
        try:
            ml_result = detect(event.features)

            # Store only non-benign predictions.
            if ml_result["predicted_label"] != "BENIGN":
                detections.append(ml_result)

        except Exception as error:
            raise HTTPException(
                status_code=400,
                detail=f"Model detection failed: {str(error)}"
            )

    # Save detection results using the existing database structure.
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
        "org_id": organization.id,
        "detections": detections
    }


# --------------------------------------------------
# Dashboard endpoints
# --------------------------------------------------

@app.get("/events")
def get_events(
    user=Depends(current_user),
    db: Session = Depends(get_db)
):
    events = db.query(models.SecurityEvent).filter(
        models.SecurityEvent.org_id == user.org_id
    ).order_by(
        models.SecurityEvent.id.desc()
    ).all()

    return events


@app.get("/detections")
def get_detections(
    user=Depends(current_user),
    db: Session = Depends(get_db)
):
    detections = (
        db.query(models.DetectionResult)
        .join(
            models.SecurityEvent,
            models.DetectionResult.event_id == models.SecurityEvent.id
        )
        .filter(
            models.SecurityEvent.org_id == user.org_id
        )
        .order_by(
            models.DetectionResult.id.desc()
        )
        .all()
    )

    return detections


@app.get("/stats")
def get_stats(
    user=Depends(current_user),
    db: Session = Depends(get_db)
):
    total_events = db.query(
        func.count(models.SecurityEvent.id)
    ).filter(
        models.SecurityEvent.org_id == user.org_id
    ).scalar()

    total_detections = (
        db.query(func.count(models.DetectionResult.id))
        .join(
            models.SecurityEvent,
            models.DetectionResult.event_id == models.SecurityEvent.id
        )
        .filter(
            models.SecurityEvent.org_id == user.org_id
        )
        .scalar()
    )

    detection_counts = (
        db.query(
            models.DetectionResult.predicted_label,
            func.count(models.DetectionResult.id)
        )
        .join(
            models.SecurityEvent,
            models.DetectionResult.event_id == models.SecurityEvent.id
        )
        .filter(
            models.SecurityEvent.org_id == user.org_id
        )
        .group_by(
            models.DetectionResult.predicted_label
        )
        .all()
    )

    return {
        "total_events": total_events or 0,
        "total_detections": total_detections or 0,
        "detections_by_type": {
            label: count
            for label, count in detection_counts
        }
    }