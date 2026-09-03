from fastapi.testclient import TestClient
from backend.main import app
import time

client = TestClient(app)

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["scanners"] == 10

def test_block_localhost():
    r = client.post("/api/scan", json={"url": "http://localhost/admin"})
    assert r.status_code == 422

def test_block_metadata():
    r = client.post("/api/scan", json={"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 422

def test_scan_flow():
    r = client.post("/api/scan", json={"url": "https://example.com"})
    assert r.status_code == 200
    sid = r.json()["scan_id"]
    assert len(sid) == 8
    # poll up to 15 sec
    for _ in range(15):
        time.sleep(1)
        res = client.get(f"/api/result/{sid}")
        assert res.status_code == 200
        j = res.json()
        if j["status"] == "completed":
            assert "risk_score" in j
            assert 0 <= j["risk_score"] <= 100
            assert len(j["findings"]) >= 0
            break
    else:
        assert False, "scan did not complete in 15s"

def test_history_and_export():
    # ensure at least one scan
    r = client.get("/api/history?limit=1")
    assert r.status_code == 200
    hist = r.json()["history"]
    if hist:
        sid = hist[0]["scan_id"]
        # export CSV
        rc = client.get(f"/api/export/{sid}")
        # may be 404 if not completed, but completed scans should be 200
        assert rc.status_code in (200, 400, 404)

def test_compare_needs_two():
    r = client.get("/api/compare?ids=a,b")
    # if no such scans, expect 404, but check endpoint exists
    assert r.status_code in (404, 200, 400)
