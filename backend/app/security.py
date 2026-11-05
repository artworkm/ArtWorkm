
import os
import secrets
import hashlib

from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

from dotenv import load_dotenv


# Load environment variables from the project's .env file
load_dotenv()

# Secret key used to sign JWT tokens
SECRET_KEY = os.environ["SECRET_KEY"]

# JWT signing algorithm
ALGO = "HS256"


# ---------------- Password Security ----------------

def hash_password(pw: str) -> str:
    """Convert a password into a secure bcrypt hash."""
    return bcrypt.hashpw(
        pw.encode(),
        bcrypt.gensalt()
    ).decode()


def verify_password(pw: str, hashed: str) -> bool:
    """Check whether a password matches its stored hash."""
    return bcrypt.checkpw(
        pw.encode(),
        hashed.encode()
    )


# ---------------- JWT Authentication ----------------

def create_token(
    user_id: int,
    org_id: int,
    role: str,
    minutes: int = 60
) -> str:
    """Create a signed JWT token for a logged-in user."""

    payload = {
        "sub": str(user_id),
        "org": org_id,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=minutes)
    }

    return jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGO
    )


def decode_token(token: str) -> dict:
    """Verify a JWT token and return its payload."""

    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGO]
    )


# ---------------- API Key Security ----------------

def hash_api_key(raw: str) -> str:
    """Convert an API key into a SHA-256 hash."""

    return hashlib.sha256(
        raw.encode()
    ).hexdigest()


def new_api_key():
    """Generate a new API key and its corresponding hash."""

    raw = "sk_" + secrets.token_urlsafe(32)

    return raw, hash_api_key(raw)
