"""Interfejs wiersza poleceń silnika wykrywania anomalii.

Przykłady:
    python -m anomaly_engine scan                 # skan z bezpiecznymi domyślnymi
    python -m anomaly_engine scan -b baza.json     # skan względem baseline
    python -m anomaly_engine scan --json -o raport.json
    python -m anomaly_engine capture -o baza.json  # zapisz bieżący stan jako baseline
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .baseline import Baseline, capture
from .collectors import DEFAULT_COLLECTORS, run_all
from .engine import run_scan
from .model import Severity


def _severity_from_name(name: str) -> Severity:
    return Severity[name.upper()]


def cmd_scan(args: argparse.Namespace) -> int:
    baseline = Baseline.load(Path(args.baseline)) if args.baseline else Baseline.default()
    if args.manual_mttd is not None:
        baseline.manual_mttd_seconds = args.manual_mttd

    names = args.collectors.split(",") if args.collectors else None
    report = run_scan(
        baseline=baseline,
        collector_names=names,
        base_dir=Path(args.collectors_dir) if args.collectors_dir else None,
        timeout=args.timeout,
    )

    output = report.to_json() if args.json else report.to_text(color=not args.no_color)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Zapisano raport do: {args.output}", file=sys.stderr)
    else:
        print(output)

    # Kod wyjścia: 0 gdy wszystko poniżej progu, 1 gdy próg osiągnięty
    # (przydatne w CI/monitoringu).
    threshold = _severity_from_name(args.fail_on)
    return 1 if report.max_severity() >= threshold and report.findings else 0


def cmd_capture(args: argparse.Namespace) -> int:
    names = args.collectors.split(",") if args.collectors else None
    results = run_all(
        names=names,
        base_dir=Path(args.collectors_dir) if args.collectors_dir else None,
        timeout=args.timeout,
    )
    baseline = capture(results, manual_mttd_seconds=args.manual_mttd or 900.0)
    out = args.output or "baseline.json"
    Path(out).write_text(
        __import__("json").dumps(baseline.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    observed = sum(len(r.observations) for r in results)
    print(f"Zapisano baseline ({observed} obserwacji) do: {out}", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="anomaly_engine",
        description="Silnik wykrywania anomalii i błędów stanu systemu.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-c", "--collectors",
                        help=f"lista kolektorów po przecinku (domyślnie: {','.join(DEFAULT_COLLECTORS)})")
    common.add_argument("--collectors-dir", help="katalog ze skryptami kolektorów")
    common.add_argument("--timeout", type=float, default=60.0,
                        help="limit czasu na kolektor w sekundach (domyślnie 60)")
    common.add_argument("--manual-mttd", type=float, default=None,
                        help="czas ręcznego audytu w sekundach (do metryki redukcji MTTD)")

    s = sub.add_parser("scan", parents=[common], help="uruchom skan wykrywania anomalii")
    s.add_argument("-b", "--baseline", help="ścieżka do pliku baseline JSON")
    s.add_argument("--json", action="store_true", help="wyjście w formacie JSON")
    s.add_argument("-o", "--output", help="zapisz raport do pliku zamiast stdout")
    s.add_argument("--no-color", action="store_true", help="wyłącz kolory ANSI")
    s.add_argument("--fail-on", default="HIGH",
                   choices=[x.name for x in Severity],
                   help="minimalna istotność powodująca kod wyjścia 1 (domyślnie HIGH)")
    s.set_defaults(func=cmd_scan)

    c = sub.add_parser("capture", parents=[common],
                       help="zapisz bieżący stan systemu jako baseline")
    c.add_argument("-o", "--output", help="plik wyjściowy (domyślnie baseline.json)")
    c.set_defaults(func=cmd_capture)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
