"""Modele danych współdzielone przez cały silnik."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Dict, List


class Severity(enum.IntEnum):
    """Poziomy istotności, uporządkowane rosnąco wg wagi.

    Wartość liczbowa pozwala łatwo sortować i progować (np. exit code, gdy
    znaleziono coś >= HIGH).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def label(self) -> str:
        return self.name


@dataclass
class Observation:
    """Pojedynczy rekord stanu wyemitowany przez kolektor."""

    collector: str
    checkpoint: str
    fields: Dict[str, str] = field(default_factory=dict)

    def get(self, key: str, default: str = "") -> str:
        return self.fields.get(key, default)


@dataclass
class CollectorResult:
    """Wynik uruchomienia jednego kolektora wraz z metadanymi walidacji."""

    name: str
    return_code: int
    observations: List[Observation] = field(default_factory=list)
    sentinel_ok: bool = False
    reported_count: int = -1  # liczba obserwacji zadeklarowana w sentinelu
    stderr: str = ""
    duration_s: float = 0.0

    @property
    def valid(self) -> bool:
        """Kolektor uznajemy za wiarygodny, gdy zwrócił kod 0, wypisał sentinel
        i deklarowana liczba obserwacji zgadza się z faktyczną (spójność
        odpowiedzi — brak zgodności może wskazywać na obcięcie/manipulację)."""
        return (
            self.return_code == 0
            and self.sentinel_ok
            and self.reported_count == len(self.observations)
        )


@dataclass
class Finding:
    """Pojedyncze znalezisko (anomalia) wykryte przez regułę."""

    rule_id: str
    severity: Severity
    checkpoint: str
    title: str
    detail: str
    evidence: Dict[str, str] = field(default_factory=dict)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.label(),
            "checkpoint": self.checkpoint,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }
