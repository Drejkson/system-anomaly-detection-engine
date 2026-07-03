"""Silnik wykrywania anomalii i błędów stanu systemu.

Pakiet orkiestruje zestaw kolektorów Bash zbierających stan systemu w 20+
punktach kontrolnych, waliduje ich odpowiedzi (walidacja odpowiedzi), a
następnie stosuje reguły analizy dynamicznej porównujące stan bieżący z
zatwierdzonym baseline, aby wykryć niespójności stanowiące potencjalną
powierzchnię ataku.
"""

__version__ = "1.0.0"

from .model import Finding, Observation, CollectorResult, Severity  # noqa: F401
