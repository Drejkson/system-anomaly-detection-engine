"""Wspólne narzędzia testowe: budowanie syntetycznych wyników kolektorów."""

import sys
from pathlib import Path

import pytest

# Dodaj korzeń repozytorium do ścieżki, aby importować pakiet bez instalacji.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from anomaly_engine.model import CollectorResult, Observation  # noqa: E402


def make_result(name: str, observations, *, rc: int = 0, sentinel: bool = True,
                reported=None) -> CollectorResult:
    """Tworzy CollectorResult z listy krotek (checkpoint, {pola})."""
    obs = [Observation(collector=name, checkpoint=cp, fields=dict(f))
           for cp, f in observations]
    return CollectorResult(
        name=name,
        return_code=rc,
        observations=obs,
        sentinel_ok=sentinel,
        reported_count=len(obs) if reported is None else reported,
    )


@pytest.fixture
def make():
    return make_result
