from fastapi import Depends, HTTPException, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from .database import get_db
from . import models
from .security import decode_token, hash_api_key

bearer = HTTPBearer()


def current_user(
    creds: HTTPAuthorizationCredentials = Depends(bearer),
    db: Session = Depends(get_db)
):
    try:
        payload = decode_token(creds.credentials)
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    return user


def require_admin(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return user


def api_key_org(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db)
):
    if not x_api_key:
        raise HTTPException(
            status_code=401,
            detail="API key required"
        )

    key_hash = hash_api_key(x_api_key)

    api_key = db.query(models.ApiKey).filter(
        models.ApiKey.key_hash == key_hash,
        models.ApiKey.active == True
    ).first()

    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key"
        )

    org = db.query(models.Organization).filter(
        models.Organization.id == api_key.org_id
    ).first()

    if not org:
        raise HTTPException(
            status_code=401,
            detail="Organization not found"
        )

    return org