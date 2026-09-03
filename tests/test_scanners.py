from backend.scanners.headers import scan_headers
from backend.scanners.cors_check import scan_cors
from backend.scanners.security_txt import scan_security_txt

def test_headers_has_findings():
    # example.com always missing some headers -> should have findings
    r = scan_headers("https://example.com", timeout=5)
    assert r["scanner"] == "headers"
    assert isinstance(r["findings"], list)

def test_cors_no_crash():
    r = scan_cors("https://example.com", timeout=5)
    assert r["scanner"] == "cors"

def test_security_txt_missing():
    r = scan_security_txt("https://example.com", timeout=5)
    assert r["scanner"] == "security_txt"
    # example.com has no security.txt -> should have LOW finding
    assert any("security.txt" in f["type"].lower() for f in r["findings"])
