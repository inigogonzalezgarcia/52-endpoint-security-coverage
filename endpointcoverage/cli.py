"""Command line: `demo` writes the fictional Tailspin Aerospace exports to sample_data/ and builds the outputs; `review` runs on your
own exports."""
from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from . import report, simulate
from .checks import review, summary
from .model import load, parse_dt

OUTPUTS = ("report.html", "review-pack.md", "device-coverage.csv", "gaps.csv", "reconciliation.csv", "coverage-summary.csv",
           "elevations-review.csv", "exceptions-review.csv", "findings.csv", "actions.csv")


def run(data: Path, out: Path, title: str | None = None, as_of: datetime | None = None) -> dict:
    d = load(data, as_of)
    rv = review(d)
    title = title or f"{d.settings.organisation} · Endpoint security coverage, {d.as_of:%d %B %Y}"
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.html").write_text(report.render_html(d, rv, title), encoding="utf-8")
    (out / "review-pack.md").write_text(report.pack_md(d, rv, title), encoding="utf-8")
    report.write_devices(rv, out / "device-coverage.csv")
    report.write_gaps(rv, out / "gaps.csv")
    report.write_reconciliation(d, rv, out / "reconciliation.csv")
    report.write_coverage(rv, out / "coverage-summary.csv")
    report.write_elevations(d, rv, out / "elevations-review.csv")
    report.write_exceptions(rv, out / "exceptions-review.csv")
    report.write_findings(rv, out / "findings.csv")
    report.write_actions(rv, out / "actions.csv")
    return summary(d, rv)


def _when(value: str) -> datetime:
    d = parse_dt(value)
    if not d:
        raise argparse.ArgumentTypeError(f"not a date (YYYY-MM-DD or 'YYYY-MM-DD HH:MM'): {value}")
    return d


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="endpointcoverage", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    dm = sub.add_parser("demo", help="write the fictional exports to sample_data/ and build the outputs")
    dm.add_argument("--data", type=Path, default=Path("sample_data"))
    dm.add_argument("--out", type=Path, default=Path("output"))
    rv = sub.add_parser("review", help="build the outputs from your own exports")
    rv.add_argument("data", type=Path, nargs="?", help="folder with inventory.csv, intune.csv, defender.csv and the optional files")
    rv.add_argument("--data", dest="data_opt", type=Path, help="same as the positional folder")
    rv.add_argument("--out", type=Path, default=Path("output"))
    rv.add_argument("--title", help="title of the report and the pack")
    rv.add_argument("--as-of", type=_when, help="review date (default: settings.json, or now)")
    a = p.parse_args(argv)
    if a.cmd == "demo":
        simulate.write(a.data)
        sm = run(a.data, a.out, f"{simulate.ORG} · Endpoint security coverage, 13 November 2026")
    else:
        folder = a.data or a.data_opt
        if not folder:
            print("error: give the folder with inventory.csv, intune.csv and defender.csv", file=sys.stderr)
            return 2
        try:
            sm = run(folder, a.out, a.title, a.as_of)
        except (FileNotFoundError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    pct = "–" if sm["pct"] is None else f"{sm['pct']:.1f} %"
    prev = "" if sm["prev_pct"] is None else f" (last review {sm['prev_pct']:.1f} %)"
    print(f"{sm['status']} · {sm['scope']} devices in scope · fully protected {pct}{prev} · {sm['unmanaged']} not managed · "
          f"{sm['no_edr']} without working EDR · {sm['unencrypted']} not encrypted · {sm['admins']} with standing admins · "
          f"{sm['unsupported']} on an unsupported OS · {sm['unknown']} not in the inventory · {sm['red']} red and {sm['amber']} amber findings")
    print(f"outputs in {a.out}/: {', '.join(OUTPUTS)}")
    return 0
