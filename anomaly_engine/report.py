"""Budowanie i formatowanie raportu skanu (JSON + czytelny tekst)."""

from __future__ import annotations

import datetime as _dt
import json
import socket
from dataclasses import dataclass, field
from typing import Dict, List

from .model import CollectorResult, Finding, Severity

# Kody kolorów ANSI dla wyjścia terminalowego.
_COLORS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


@dataclass
class ScanReport:
    findings: List[Finding]
    results: List[CollectorResult]
    scan_duration_s: float
    manual_mttd_s: float
    baseline_source: str
    started_at: str = field(default_factory=lambda: _dt.datetime.now().isoformat(timespec="seconds"))
    hostname: str = field(default_factory=socket.gethostname)

    # ------------------------------------------------------------------
    # Metryki
    # ------------------------------------------------------------------
    def checkpoint_count(self) -> int:
        """Liczba unikalnych punktów kontrolnych, które faktycznie zaobserwowano."""
        seen = set()
        for res in self.results:
            for obs in res.observations:
                seen.add(obs.checkpoint)
        return len(seen)

    def severity_counts(self) -> Dict[str, int]:
        counts = {s.label(): 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.label()] += 1
        return counts

    def mttd_reduction_pct(self) -> float:
        """Redukcja średniego czasu wykrycia względem audytu ręcznego."""
        if self.manual_mttd_s <= 0:
            return 0.0
        reduction = (self.manual_mttd_s - self.scan_duration_s) / self.manual_mttd_s
        return max(0.0, round(reduction * 100, 1))

    # ------------------------------------------------------------------
    # Serializacja
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "hostname": self.hostname,
            "started_at": self.started_at,
            "baseline_source": self.baseline_source,
            "metrics": {
                "checkpoints_observed": self.checkpoint_count(),
                "collectors_run": len(self.results),
                "collectors_valid": sum(1 for r in self.results if r.valid),
                "findings_total": len(self.findings),
                "severity_counts": self.severity_counts(),
                "scan_duration_s": round(self.scan_duration_s, 3),
                "manual_mttd_s": self.manual_mttd_s,
                "mttd_reduction_pct": self.mttd_reduction_pct(),
            },
            "collectors": [
                {
                    "name": r.name,
                    "valid": r.valid,
                    "return_code": r.return_code,
                    "observations": len(r.observations),
                    "duration_s": round(r.duration_s, 3),
                }
                for r in self.results
            ],
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Widok tekstowy
    # ------------------------------------------------------------------
    def to_text(self, color: bool = True) -> str:
        lines: List[str] = []
        lines.append("=" * 70)
        lines.append("  SILNIK WYKRYWANIA ANOMALII — RAPORT SKANU")
        lines.append("=" * 70)
        lines.append(f"Host:            {self.hostname}")
        lines.append(f"Czas:            {self.started_at}")
        lines.append(f"Baseline:        {self.baseline_source}")
        lines.append(f"Punkty kontrolne (zaobserwowane): {self.checkpoint_count()}")
        valid = sum(1 for r in self.results if r.valid)
        lines.append(f"Kolektory:       {valid}/{len(self.results)} przeszło walidację odpowiedzi")
        lines.append(
            f"Czas skanu:      {self.scan_duration_s:.2f}s "
            f"(audyt ręczny ~{self.manual_mttd_s:.0f}s → redukcja MTTD "
            f"{self.mttd_reduction_pct():.0f}%)"
        )

        counts = self.severity_counts()
        summary = "  ".join(f"{k}: {counts[k]}" for k in
                            ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
        lines.append(f"Znaleziska:      {len(self.findings)}  ({summary})")
        lines.append("-" * 70)

        if not self.findings:
            lines.append("Brak anomalii — stan spójny z baseline.")
        for f in self.findings:
            tag = f"[{f.severity.label()}]"
            if color and f.severity in _COLORS:
                tag = f"{_COLORS[f.severity]}{tag}{_RESET}"
            lines.append(f"{tag} {f.title}")
            lines.append(f"      {f.detail}")
            if f.evidence:
                ev = ", ".join(f"{k}={v}" for k, v in f.evidence.items() if v)
                if ev:
                    lines.append(f"      dowód: {ev}")
            if f.remediation:
                lines.append(f"      naprawa: {f.remediation}")
            lines.append("")

        lines.append("=" * 70)
        return "\n".join(lines)

    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)
