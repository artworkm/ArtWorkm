import os

# Configure the test database BEFORE importing the application.
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["SECRET_KEY"] = (
    "test-secret-key-for-tests-only-0123456789abcdef"
)

import pytest
from fastapi.testclient import TestClient

from app.main import app, limiter
from app.database import Base, engine


@pytest.fixture(autouse=True)
def fresh_db():
    # Reset rate-limit counters before every test.
    limiter._storage.reset()

    # Give every test a clean, isolated database.
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    yield


@pytest.fixture
def client():
    return TestClient(app)