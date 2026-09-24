import pytest
import os
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

test_engine = create_engine("sqlite:///./test_sprint3.db", connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

from app.main import app
from app.db.database import Base, get_db

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()
    Base.metadata.drop_all(bind=test_engine)
    if os.path.exists("./test_sprint3.db"):
        try:
            os.remove("./test_sprint3.db")
        except PermissionError:
            pass

def test_sprint3_e2e_full_persistence_lifecycle():
    client = TestClient(app)

    # 1. Target Scan on Authorized Lab Target
    scan_payload = {
        "target": "192.168.1.100",
        "asset_criticality": 10.0,
        "exposure": 1.0
    }
    scan_res = client.post("/api/scan", json=scan_payload)
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["status"] == "success"
    assert "scan_id" in scan_data
    scan_id = scan_data["scan_id"]
    assert scan_data["total_findings"] > 0

    # 2. Verify Asset endpoint returns persisted asset
    assets_res = client.get("/api/assets")
    assert assets_res.status_code == 200
    assets = assets_res.json()
    assert len(assets) >= 1
    assert assets[0]["ip_address"] == "192.168.1.100"

    # 3. Create Remediation Plan with capacity 5.0h
    plan_payload = {
        "scan_id": scan_id,
        "target": "192.168.1.100",
        "asset_criticality": 10.0,
        "exposure": 1.0,
        "available_capacity": 5.0
    }
    plan_res = client.post("/api/plan", json=plan_payload)
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert "plan_id" in plan_data
    assert plan_data["available_capacity"] == 5.0
    assert plan_data["total_effort_used"] <= 5.0
    assert plan_data["selected_count"] > 0

    # 4. Simulate Browser Refresh: Call GET /api/plan/latest
    latest_res = client.get("/api/plan/latest")
    assert latest_res.status_code == 200
    latest_data = latest_res.json()
    assert latest_data["status"] == "success"
    assert latest_data["plan_id"] == plan_data["plan_id"]
    assert latest_data["scan_id"] == scan_id
    assert latest_data["target"] == "192.168.1.100"
    assert latest_data["available_capacity"] == 5.0
    assert len(latest_data["selected_vulnerabilities"]) == plan_data["selected_count"]
    assert latest_data["optimization_rationale"] is not None
