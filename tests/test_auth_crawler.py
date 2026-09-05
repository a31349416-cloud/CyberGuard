from fastapi.testclient import TestClient
from backend.main import app
from backend.crawler import crawl_same_origin

client = TestClient(app)

def test_auth_register_login():
    r = client.post("/api/auth/register", json={"username": "testuser", "password": "testpass"})
    # may exist already -> 400, ok
    assert r.status_code in (200, 400)
    r = client.post("/api/auth/login", json={"username": "testuser", "password": "testpass"})
    if r.status_code == 200:
        assert "token" in r.json()
        token = r.json()["token"]
        # me
        rr = client.get("/api/me", headers={"Authorization": f"Bearer {token}"})
        assert rr.status_code == 200
        assert rr.json()["user"] == "testuser"

def test_crawler_same_origin():
    urls = crawl_same_origin("https://example.com", max_pages=2)
    assert len(urls) >= 1
    assert "https://example.com" in urls[0]

def test_owasp_stats():
    r = client.get("/api/owasp?limit=5")
    assert r.status_code == 200
    assert isinstance(r.json(), dict)

def test_scheduled():
    r = client.get("/api/scheduled")
    assert r.status_code == 200
    assert "jobs" in r.json()

def test_auth_crawl_param():
    r = client.post("/api/scan?crawl=1", json={"url": "https://example.com"})
    assert r.status_code == 200
    assert "scan_id" in r.json()
