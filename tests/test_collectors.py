"""Testy parsowania wyjścia kolektorów i walidacji odpowiedzi."""

from anomaly_engine import collectors as C
from anomaly_engine.model import CollectorResult, Observation


def test_parse_record_basic():
    obs = C._parse_record("fs_suid\tpath=/usr/bin/sudo\towner=root\tmode=4755", "filesystem")
    assert obs.checkpoint == "fs_suid"
    assert obs.get("path") == "/usr/bin/sudo"
    assert obs.get("mode") == "4755"


def test_parse_output_with_sentinel():
    stdout = (
        "process_root\tpid=1\tcomm=init\n"
        "process_root\tpid=2\tcomm=kthreadd\n"
        "__COLLECTOR_OK__ name=processes observations=2 rc=0\n"
    )
    obs, ok, reported = C.parse_output("processes", stdout)
    assert len(obs) == 2
    assert ok is True
    assert reported == 2


def test_parse_output_missing_sentinel():
    stdout = "process_root\tpid=1\tcomm=init\n"
    obs, ok, reported = C.parse_output("processes", stdout)
    assert ok is False
    assert reported == -1


def test_validity_requires_sentinel_and_count():
    valid = CollectorResult(
        name="x", return_code=0,
        observations=[Observation("x", "cp", {})],
        sentinel_ok=True, reported_count=1,
    )
    assert valid.valid is True

    truncated = CollectorResult(
        name="x", return_code=0,
        observations=[Observation("x", "cp", {})],
        sentinel_ok=True, reported_count=9,  # deklaracja != rzeczywistość
    )
    assert truncated.valid is False

    crashed = CollectorResult(name="x", return_code=1, sentinel_ok=False)
    assert crashed.valid is False


def test_missing_collector_script(tmp_path):
    res = C.run_collector("nieistnieje", base_dir=tmp_path)
    assert res.return_code == 127
    assert res.valid is False
