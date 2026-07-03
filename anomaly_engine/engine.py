"""Orkiestracja: uruchom kolektory → waliduj → zastosuj reguły → zmierz MTTD."""

from __future__ import annotations

import time
from pathlib import Path
from typing import List, Optional

from . import collectors as collectors_mod
from .baseline import Baseline
from .rules import evaluate
from .report import ScanReport


def run_scan(
    baseline: Optional[Baseline] = None,
    collector_names: Optional[List[str]] = None,
    base_dir: Optional[Path] = None,
    timeout: float = 60.0,
) -> ScanReport:
    """Wykonuje pełny cykl wykrywania i zwraca raport.

    Czas trwania mierzony jest wokół zbierania + analizy — to jest
    zautomatyzowany „czas wykrycia" porównywany z ręcznym audytem (MTTD).
    """
    baseline = baseline or Baseline.default()

    start = time.perf_counter()
    results = collectors_mod.run_all(
        names=collector_names, base_dir=base_dir, timeout=timeout
    )
    findings = evaluate(results, baseline)
    duration = time.perf_counter() - start

    source = "plik" if baseline.loaded_from_file else "wartości domyślne (bezpieczne)"
    return ScanReport(
        findings=findings,
        results=results,
        scan_duration_s=duration,
        manual_mttd_s=baseline.manual_mttd_seconds,
        baseline_source=source,
    )
