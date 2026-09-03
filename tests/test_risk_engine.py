from backend.risk_engine import calculate_risk, aggregate_findings, sort_findings, get_summary
from backend.models import Finding, Severity

def test_risk_low():
    f = [Finding(type="Missing X-Content-Type-Options", severity=Severity.LOW, score=5, fix="fix")]
    score, level = calculate_risk(f)
    assert score == 5
    assert level.value == "LOW"

def test_risk_high_capped():
    f = [Finding(type=f"Vuln {i}", severity=Severity.HIGH, score=25, fix="fix") for i in range(6)]
    score, level = calculate_risk(f)
    assert score == 100
    assert level.value == "HIGH"

def test_owasp_bonus():
    f = [Finding(type="XSS", severity=Severity.HIGH, score=25, fix="fix", owasp_category="A03:2021 - Injection")]
    score, level = calculate_risk(f)
    assert score == 30  # 25+5 bonus
    assert level.value == "LOW"

def test_dedup():
    r1 = {"scanner":"test","findings":[{"type":"Dup","severity":"HIGH","score":25,"fix":"fix","description":"","owasp_category":""}]}
    r2 = {"scanner":"test","findings":[{"type":"Dup","severity":"HIGH","score":25,"fix":"fix","description":"","owasp_category":""}]}
    findings = aggregate_findings([r1, r2])
    assert len(findings) == 1

def test_sort():
    low = Finding(type="low", severity=Severity.LOW, score=5, fix="fix")
    high = Finding(type="high", severity=Severity.HIGH, score=25, fix="fix")
    crit = Finding(type="crit", severity=Severity.CRITICAL, score=40, fix="fix")
    sorted_f = sort_findings([low, crit, high])
    assert sorted_f[0].severity == Severity.CRITICAL

def test_summary():
    f = [Finding(type="a", severity=Severity.MEDIUM, score=15, fix="fix")]
    s = get_summary(f)
    assert s["risk_score"] > 0
    assert s["by_severity"]["MEDIUM"] == 1
