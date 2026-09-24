import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.db.database import init_db

init_db()
client = TestClient(app)

def test_health_check_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

def test_scan_unauthorized_target_rejection():
    payload = {
        "target": "8.8.8.8",
        "asset_criticality": 10.0,
        "exposure": 1.0
    }
    response = client.post("/api/scan", json=payload)
    assert response.status_code == 403
    assert "SECURITY REJECTION" in response.json()["detail"]

def test_scan_authorized_lab_target_pipeline():
    payload = {
        "target": "192.168.1.100",
        "asset_criticality": 10.0,
        "exposure": 1.0
    }
    response = client.post("/api/scan", json=payload)
    if response.status_code != 200:
        print("ERROR DETAIL:", response.json())
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["total_findings"] > 0
    
    findings = data["findings"]
    for i in range(len(findings) - 1):
        assert findings[i]["business_risk"] >= findings[i+1]["business_risk"]
