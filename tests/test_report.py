"""Testy metryk raportu (m.in. redukcja MTTD) i serializacji JSON."""

import json

from anomaly_engine.model import CollectorResult, Finding, Observation, Severity
from anomaly_engine.report import ScanReport


def _report(findings, scan_s, manual_s):
    res = [CollectorResult(
        name="processes", return_code=0,
        observations=[Observation("processes", "process_root", {"pid": "1"})],
        sentinel_ok=True, reported_count=1,
    )]
    return ScanReport(
        findings=findings, results=res,
        scan_duration_s=scan_s, manual_mttd_s=manual_s,
        baseline_source="test",
    )


def test_mttd_reduction():
    r = _report([], scan_s=3.0, manual_s=10.0)
    assert r.mttd_reduction_pct() == 70.0


def test_mttd_reduction_floor_zero():
    r = _report([], scan_s=20.0, manual_s=10.0)
    assert r.mttd_reduction_pct() == 0.0


def test_checkpoint_count():
    r = _report([], scan_s=1.0, manual_s=10.0)
    assert r.checkpoint_count() == 1


def test_severity_counts_and_max():
    findings = [
        Finding("a", Severity.CRITICAL, "cp", "t", "d"),
        Finding("b", Severity.LOW, "cp", "t", "d"),
        Finding("c", Severity.LOW, "cp", "t", "d"),
    ]
    r = _report(findings, scan_s=1.0, manual_s=10.0)
    counts = r.severity_counts()
    assert counts["CRITICAL"] == 1
    assert counts["LOW"] == 2
    assert r.max_severity() is Severity.CRITICAL


def test_json_roundtrip():
    findings = [Finding("a", Severity.HIGH, "cp", "tytuł", "detal", {"k": "v"}, "napraw")]
    r = _report(findings, scan_s=3.0, manual_s=10.0)
    data = json.loads(r.to_json())
    assert data["metrics"]["mttd_reduction_pct"] == 70.0
    assert data["findings"][0]["severity"] == "HIGH"
    assert data["metrics"]["findings_total"] == 1
