"""Uruchamianie kolektorów Bash i parsowanie ich wyjścia z walidacją odpowiedzi.

Każdy kolektor przestrzega kontraktu zdefiniowanego w ``collectors/_lib.sh``:
rekordy obserwacji rozdzielone tabulacjami plus linia-sentinel
``__COLLECTOR_OK__``. Ten moduł egzekwuje ten kontrakt i zamienia surowe
wyjście na obiekty :class:`Observation` / :class:`CollectorResult`.
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import List, Optional

from .model import CollectorResult, Observation

SENTINEL_PREFIX = "__COLLECTOR_OK__"

# Kolejność ma znaczenie tylko dla czytelności raportu.
DEFAULT_COLLECTORS = [
    "processes",
    "network",
    "filesystem",
    "users",
    "system",
]


def collectors_dir() -> Path:
    """Ścieżka do katalogu ``collectors/`` względem korzenia repozytorium."""
    return Path(__file__).resolve().parent.parent / "collectors"


def _parse_record(line: str, collector: str) -> Optional[Observation]:
    """Parsuje jeden rekord obserwacji ``id\\tk=v\\tk=v``."""
    parts = line.split("\t")
    checkpoint = parts[0].strip()
    if not checkpoint:
        return None
    fields = {}
    for token in parts[1:]:
        if "=" in token:
            key, value = token.split("=", 1)
            fields[key.strip()] = value.strip()
        elif token.strip():
            # Token bez '=' zachowujemy jako flagę (wartość pusta).
            fields[token.strip()] = ""
    return Observation(collector=collector, checkpoint=checkpoint, fields=fields)


def parse_output(name: str, stdout: str) -> tuple[List[Observation], bool, int]:
    """Zwraca (obserwacje, czy_sentinel_ok, zadeklarowana_liczba)."""
    observations: List[Observation] = []
    sentinel_ok = False
    reported = -1

    for raw in stdout.splitlines():
        if not raw.strip():
            continue
        if raw.startswith(SENTINEL_PREFIX):
            sentinel_ok = True
            # __COLLECTOR_OK__ name=<n> observations=<N> rc=0
            for token in raw.split()[1:]:
                if token.startswith("observations="):
                    try:
                        reported = int(token.split("=", 1)[1])
                    except ValueError:
                        reported = -1
            continue
        obs = _parse_record(raw, name)
        if obs is not None:
            observations.append(obs)

    return observations, sentinel_ok, reported


def run_collector(
    name: str,
    base_dir: Optional[Path] = None,
    timeout: float = 60.0,
) -> CollectorResult:
    """Uruchamia jeden kolektor Bash i zwraca zwalidowany wynik."""
    base = base_dir or collectors_dir()
    script = base / f"{name}.sh"

    if not script.exists():
        return CollectorResult(
            name=name,
            return_code=127,
            stderr=f"nie znaleziono kolektora: {script}",
        )

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            ["bash", str(script)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C"},
        )
        stdout, stderr, rc = proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as exc:
        return CollectorResult(
            name=name,
            return_code=124,
            stderr=f"timeout po {timeout}s: {exc}",
            duration_s=time.perf_counter() - start,
        )
    except Exception as exc:  # pragma: no cover - obrona przed nietypowym środowiskiem
        return CollectorResult(
            name=name,
            return_code=1,
            stderr=str(exc),
            duration_s=time.perf_counter() - start,
        )

    duration = time.perf_counter() - start
    observations, sentinel_ok, reported = parse_output(name, stdout)

    return CollectorResult(
        name=name,
        return_code=rc,
        observations=observations,
        sentinel_ok=sentinel_ok,
        reported_count=reported,
        stderr=stderr.strip(),
        duration_s=duration,
    )


def run_all(
    names: Optional[List[str]] = None,
    base_dir: Optional[Path] = None,
    timeout: float = 60.0,
) -> List[CollectorResult]:
    """Uruchamia wszystkie (lub wskazane) kolektory sekwencyjnie."""
    selected = names or DEFAULT_COLLECTORS
    return [run_collector(n, base_dir=base_dir, timeout=timeout) for n in selected]
