"""Testy jednostkowe reguł analizy dynamicznej."""

from anomaly_engine.baseline import Baseline
from anomaly_engine.model import Severity
from anomaly_engine import rules


def _ids(findings):
    return {f.rule_id for f in findings}


def test_deleted_exe_is_critical(make):
    res = [make("processes", [("process_deleted_exe",
                               {"pid": "1337", "comm": "x", "exe": "/tmp/x (deleted)"})])]
    findings = rules.rule_deleted_exe(res, Baseline.default())
    assert len(findings) == 1
    assert findings[0].severity is Severity.CRITICAL


def test_uid0_whitelist(make):
    res = [make("users", [
        ("user_uid0", {"user": "root", "uid": "0"}),
        ("user_uid0", {"user": "backdoor", "uid": "0"}),
    ])]
    findings = rules.rule_uid0(res, Baseline.default())
    # root jest na whiteliście domyślnej; tylko 'backdoor' powinien się pojawić.
    assert len(findings) == 1
    assert findings[0].evidence["user"] == "backdoor"
    assert findings[0].severity is Severity.CRITICAL


def test_new_suid_severity_depends_on_baseline(make):
    res = [make("filesystem", [("fs_suid",
                                {"path": "/tmp/evil", "owner": "root", "mode": "4755"})])]

    # Bez baseline: INFO (nie znamy „dobrych" SUID-ów).
    default_findings = rules.rule_new_suid(res, Baseline.default())
    assert default_findings[0].severity is Severity.INFO

    # Z baseline zawierającym inne SUID-y: /tmp/evil to odchylenie => HIGH.
    b = Baseline(known_suid=["/usr/bin/sudo"], loaded_from_file=True)
    hi = rules.rule_new_suid(res, b)
    assert hi[0].severity is Severity.HIGH


def test_known_suid_not_flagged(make):
    res = [make("filesystem", [("fs_suid",
                                {"path": "/usr/bin/sudo", "owner": "root", "mode": "4755"})])]
    b = Baseline(known_suid=["/usr/bin/sudo"], loaded_from_file=True)
    assert rules.rule_new_suid(res, b) == []


def test_listen_port_baseline(make):
    res = [make("network", [
        ("net_listen", {"proto": "tcp", "port": "22", "comm": "sshd"}),
        ("net_listen", {"proto": "tcp", "port": "4444", "comm": "nc"}),
    ])]
    b = Baseline(allowed_listen_ports=[22], loaded_from_file=True)
    findings = rules.rule_listen_port(res, b)
    assert len(findings) == 1
    assert findings[0].evidence["port"] == "4444"


def test_sysctl_aslr_deviation_is_high(make):
    res = [make("system", [("sys_aslr", {"value": "0"})])]
    findings = rules.rule_sysctl(res, Baseline.default())
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].evidence == {"actual": "0", "expected": "2"}


def test_sysctl_aslr_ok(make):
    res = [make("system", [("sys_aslr", {"value": "2"})])]
    assert rules.rule_sysctl(res, Baseline.default()) == []


def test_core_pattern_pipe(make):
    res = [make("system", [("sys_core_pattern", {"value": "|/usr/bin/evil %p"})])]
    findings = rules.rule_core_pattern(res, Baseline.default())
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM


def test_collector_integrity_flags_bad_collector(make):
    good = make("processes", [("process_root", {"pid": "1", "comm": "init"})])
    bad = make("network", [], rc=1, sentinel=False)
    findings = rules.rule_collector_integrity([good, bad], Baseline.default())
    assert len(findings) == 1
    assert findings[0].checkpoint == "collector:network"
    assert findings[0].severity is Severity.HIGH


def test_collector_integrity_count_mismatch(make):
    # sentinel deklaruje 5, ale odebrano 1 obserwację => niespójność.
    bad = make("users", [("user_uid0", {"user": "x", "uid": "0"})],
               reported=5)
    findings = rules.rule_collector_integrity([bad], Baseline.default())
    assert len(findings) == 1
    assert "niespójna" in findings[0].detail.lower() or "niespójn" in findings[0].detail.lower()


def test_evaluate_sorts_by_severity(make):
    res = [make("mix", [
        ("fs_orphan", {"path": "/etc/x", "uid": "9999", "gid": "9999"}),  # LOW
        ("process_deleted_exe", {"pid": "1", "comm": "x", "exe": "y (deleted)"}),  # CRITICAL
    ])]
    findings = rules.evaluate(res, Baseline.default())
    assert findings[0].severity is Severity.CRITICAL
    assert findings[-1].severity is Severity.LOW
