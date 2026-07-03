"""Wczytywanie i tworzenie baseline (zatwierdzonego stanu odniesienia).

Baseline opisuje „stan znany jako dobry". Reguły porównują z nim stan bieżący —
odchylenie to kandydat na anomalię. Gdy baseline nie zostanie podany, silnik
korzysta z bezpiecznych wartości domyślnych (patrz :data:`SECURE_DEFAULTS`),
dzięki czemu działa od razu, choć z większą liczbą trafień informacyjnych.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from .model import CollectorResult

# Oczekiwane, utwardzone wartości ustawień jądra (istotne dla eksploitacji).
SECURE_DEFAULTS: Dict[str, str] = {
    "sys_aslr": "2",            # pełny ASLR
    "sys_ptrace_scope": "1",    # ograniczony ptrace
    "sys_dmesg_restrict": "1",  # dmesg tylko dla roota
    "sys_kptr_restrict": "1",   # ukryte adresy jądra
}


@dataclass
class Baseline:
    allowed_listen_ports: List[int] = field(default_factory=list)
    known_suid: List[str] = field(default_factory=list)
    known_modules: List[str] = field(default_factory=list)
    known_cron: List[str] = field(default_factory=list)
    allowed_uid0_users: List[str] = field(default_factory=lambda: ["root"])
    expected_sysctl: Dict[str, str] = field(default_factory=lambda: dict(SECURE_DEFAULTS))
    # Czas ręcznego wykrycia (audyt manualny) w sekundach — do wyliczenia
    # redukcji średniego czasu wykrycia (MTTD).
    manual_mttd_seconds: float = 900.0
    # Czy baseline został wczytany z pliku (False => tryb wartości domyślnych).
    loaded_from_file: bool = False

    @classmethod
    def load(cls, path: Path) -> "Baseline":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        b = cls(
            allowed_listen_ports=[int(p) for p in data.get("allowed_listen_ports", [])],
            known_suid=list(data.get("known_suid", [])),
            known_modules=list(data.get("known_modules", [])),
            known_cron=list(data.get("known_cron", [])),
            allowed_uid0_users=list(data.get("allowed_uid0_users", ["root"])),
            expected_sysctl={**SECURE_DEFAULTS, **data.get("expected_sysctl", {})},
            manual_mttd_seconds=float(data.get("manual_mttd_seconds", 900.0)),
            loaded_from_file=True,
        )
        return b

    @classmethod
    def default(cls) -> "Baseline":
        return cls()

    def to_dict(self) -> dict:
        return {
            "allowed_listen_ports": sorted(set(self.allowed_listen_ports)),
            "known_suid": sorted(set(self.known_suid)),
            "known_modules": sorted(set(self.known_modules)),
            "known_cron": sorted(set(self.known_cron)),
            "allowed_uid0_users": sorted(set(self.allowed_uid0_users)),
            "expected_sysctl": self.expected_sysctl,
            "manual_mttd_seconds": self.manual_mttd_seconds,
        }


def capture(results: List[CollectorResult], manual_mttd_seconds: float = 900.0) -> Baseline:
    """Buduje baseline z bieżących obserwacji (do zatwierdzenia jako „dobry stan")."""
    ports: List[int] = []
    suid: List[str] = []
    modules: List[str] = []
    cron: List[str] = []
    uid0 = ["root"]
    sysctl = dict(SECURE_DEFAULTS)

    for res in results:
        for obs in res.observations:
            cp = obs.checkpoint
            if cp == "net_listen":
                try:
                    ports.append(int(obs.get("port")))
                except ValueError:
                    pass
            elif cp == "fs_suid":
                suid.append(obs.get("path"))
            elif cp == "sys_module":
                modules.append(obs.get("name"))
            elif cp == "sys_cron":
                cron.append(obs.get("entry"))
            elif cp == "user_uid0":
                uid0.append(obs.get("user"))
            elif cp in SECURE_DEFAULTS:
                # Uchwyć realny stan sysctl jako oczekiwany (o ile użytkownik
                # zatwierdza obecny system jako czysty).
                sysctl[cp] = obs.get("value", sysctl.get(cp, ""))

    return Baseline(
        allowed_listen_ports=sorted(set(ports)),
        known_suid=sorted(set(filter(None, suid))),
        known_modules=sorted(set(filter(None, modules))),
        known_cron=sorted(set(filter(None, cron))),
        allowed_uid0_users=sorted(set(filter(None, uid0))),
        expected_sysctl=sysctl,
        manual_mttd_seconds=manual_mttd_seconds,
        loaded_from_file=True,
    )
