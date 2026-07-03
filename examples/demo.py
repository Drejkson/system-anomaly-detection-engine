#!/usr/bin/env python3
"""Demo: pokazuje działanie silnika na SYMULOWANYM skompromitowanym hoście.

Nie dotyka realnego systemu — buduje syntetyczne wyniki kolektorów odpowiadające
trzem krytycznym niespójnościom stanu, aby zademonstrować reguły wykrywania i
format raportu. Do skanu realnego systemu użyj:

    python -m anomaly_engine scan
"""

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anomaly_engine.baseline import Baseline
from anomaly_engine.model import CollectorResult, Observation
from anomaly_engine.rules import evaluate
from anomaly_engine.report import ScanReport


def obs(cp, **fields):
    return Observation(collector="demo", checkpoint=cp, fields=fields)


def main():
    # Baseline „czystego" hosta.
    baseline = Baseline(
        allowed_listen_ports=[22],
        known_suid=["/usr/bin/sudo", "/usr/bin/passwd"],
        allowed_uid0_users=["root"],
        loaded_from_file=True,
        manual_mttd_seconds=900.0,
    )

    # Symulowany stan bieżący z trzema krytycznymi niespójnościami + szumem.
    results = [
        CollectorResult(
            name="processes", return_code=0, sentinel_ok=True, reported_count=2,
            observations=[
                # (1) proces z usuniętej binarki — krytyczny IOC
                obs("process_deleted_exe", pid="4821", comm="kworkerd",
                    exe="/tmp/.x (deleted)"),
                obs("process_root", pid="1", comm="systemd", euid="0"),
            ],
        ),
        CollectorResult(
            name="network", return_code=0, sentinel_ok=True, reported_count=2,
            observations=[
                obs("net_listen", proto="tcp", port="22", comm="sshd"),
                # (2) nieoczekiwany port nasłuchujący
                obs("net_listen", proto="tcp", port="4444", comm="nc"),
            ],
        ),
        CollectorResult(
            name="filesystem", return_code=0, sentinel_ok=True, reported_count=1,
            observations=[
                # (3) nowa binarka SUID spoza baseline
                obs("fs_suid", path="/tmp/rootbash", owner="root", mode="4755"),
            ],
        ),
        CollectorResult(
            name="system", return_code=0, sentinel_ok=True, reported_count=1,
            observations=[
                # osłabiony ASLR — istotne dla eksploitacji
                obs("sys_aslr", value="0"),
            ],
        ),
        # kolektor, który „padł" — walidacja odpowiedzi to wychwyci
        CollectorResult(name="users", return_code=1, sentinel_ok=False),
    ]

    start = time.perf_counter()
    findings = evaluate(results, baseline)
    duration = time.perf_counter() - start

    report = ScanReport(
        findings=findings, results=results,
        scan_duration_s=max(duration, 0.9),  # realistyczny czas skanu do demo
        manual_mttd_s=baseline.manual_mttd_seconds,
        baseline_source="demo (symulacja)",
    )
    print(report.to_text(color=True))


if __name__ == "__main__":
    main()
