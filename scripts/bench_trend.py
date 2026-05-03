#!/usr/bin/env python3
"""
bench_trend.py — pull, summarize, and plot benchmark trends from
gh-pages.

Source of truth: the `Bench` workflow runs criterion benches on every
push to main + weekly cron, publishes per-bench history to gh-pages
via `benchmark-action/github-action-benchmark@v1`. The published JS
file at https://cirisai.github.io/CIRISPersist/dev/bench/data.js wraps
a JSON object with `entries[<group>] = [{commit, benches: [{name,
value, unit}, ...]}, ...]` shape.

This script:

1. Fetches `data.js`, strips the `window.BENCHMARK_DATA = ` wrapper,
   loads the JSON.
2. Prints a per-bench summary: first-vs-last-value, % change, min/max,
   noise floor (max-min spread relative to median).
3. Renders a per-bench time-series plot — one row per bench, with the
   noise band shaded and significant commits annotated.
4. Optionally writes a Markdown report (`--md`) for pasting into PRs
   or the CHANGELOG.

Usage:
    python3 scripts/bench_trend.py             # summary table
    python3 scripts/bench_trend.py --plot out.png    # PNG plot
    python3 scripts/bench_trend.py --md report.md    # MD report
    python3 scripts/bench_trend.py --since 2026-05-02  # filter

Dependencies: matplotlib (only required with --plot). Standard-library
otherwise.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

DATA_URL = "https://cirisai.github.io/CIRISPersist/dev/bench/data.js"
GROUP_NAME = "ciris-persist criterion benchmarks"

# Alert threshold matches `.github/workflows/bench.yml`: 110% means
# 10% slower than baseline. Surface anything past that.
ALERT_PCT = 10.0


def fetch_data(url: str = DATA_URL) -> dict:
    """Download `data.js`, strip the `window.BENCHMARK_DATA = ` prefix,
    parse the JSON. Returns the top-level dict (`{lastUpdate, repoUrl,
    xAxis, oneChartGroups, entries}`)."""
    with urllib.request.urlopen(url, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    # The action emits `window.BENCHMARK_DATA = {...};` (sometimes
    # without a trailing semicolon). Strip both.
    prefix = "window.BENCHMARK_DATA = "
    if not text.startswith(prefix):
        raise SystemExit(f"unexpected data.js prefix: {text[:60]!r}")
    payload = text[len(prefix):].rstrip().rstrip(";")
    return json.loads(payload)


def runs_for_group(data: dict, group: str = GROUP_NAME) -> list[dict]:
    """Pull the run-list for the named bench group. The action keys
    each `name:` field on the workflow yaml as a separate group; we
    only have one."""
    entries = data.get("entries", {})
    if group not in entries:
        avail = list(entries.keys())
        raise SystemExit(f"group {group!r} not found; available: {avail}")
    return entries[group]


def filter_runs(runs: list[dict], since: str | None) -> list[dict]:
    """Optional time filter. `since` is YYYY-MM-DD; runs with
    commit.timestamp before that date are dropped."""
    if not since:
        return runs
    cutoff = datetime.fromisoformat(since)
    return [
        r for r in runs
        if datetime.fromisoformat(r["commit"]["timestamp"][:19]) >= cutoff
    ]


def per_bench_series(runs: list[dict]) -> dict[str, list[tuple]]:
    """Pivot runs from {commit, benches:[{name, value}]} to
    `{name: [(timestamp, value, sha, message)]}`. Iterates every run's
    bench list; benches that didn't exist in older runs simply have
    shorter series."""
    series: dict[str, list[tuple]] = {}
    for r in runs:
        ts = r["commit"]["timestamp"]
        sha = r["commit"]["id"][:8]
        msg = r["commit"]["message"].split("\n")[0]
        for b in r["benches"]:
            series.setdefault(b["name"], []).append((ts, b["value"], b["unit"], sha, msg))
    return series


def summarize(series: dict[str, list[tuple]]) -> list[dict]:
    """Per-bench summary stats. Returned rows feed both the text table
    and the markdown report. Includes:
      - first/last/min/max
      - delta% (last vs first)
      - noise%: (max-min) / median * 100. >50% means runner-bound.
      - Hot/cold flags using the alert threshold.
    """
    rows = []
    for name, points in sorted(series.items()):
        vals = [p[1] for p in points]
        if not vals:
            continue
        first, last = vals[0], vals[-1]
        med = statistics.median(vals)
        delta = (last - first) / first * 100.0 if first > 0 else 0.0
        noise = (max(vals) - min(vals)) / med * 100.0 if med > 0 else 0.0
        flag = "regress" if delta > ALERT_PCT else "improve" if delta < -ALERT_PCT else "stable"
        # If noise dominates the delta, downgrade the regress/improve
        # call: the change is indistinguishable from runner jitter.
        if abs(delta) < noise / 2:
            flag = f"{flag}*noisy"
        rows.append({
            "name": name,
            "unit": points[-1][2],
            "first": first,
            "last": last,
            "min": min(vals),
            "max": max(vals),
            "median": med,
            "delta_pct": delta,
            "noise_pct": noise,
            "n_runs": len(points),
            "flag": flag,
        })
    return rows


def fmt_ns(ns: float) -> str:
    """Compact ns/µs/ms display so the table aligns nicely across
    benches that span microseconds (canonicalize) → milliseconds
    (queue_submit)."""
    if ns >= 1e6:
        return f"{ns / 1e6:.2f}ms"
    if ns >= 1e3:
        return f"{ns / 1e3:.1f}µs"
    return f"{ns:.0f}ns"


def print_table(rows: list[dict]) -> None:
    """Plain-text table. Width-tuned for an 80-col terminal."""
    print(f"{'bench':<32} {'first':>10} {'last':>10} {'Δ%':>7} {'noise%':>7} {'runs':>5}  flag")
    print("-" * 88)
    for r in rows:
        print(
            f"{r['name']:<32} "
            f"{fmt_ns(r['first']):>10} {fmt_ns(r['last']):>10} "
            f"{r['delta_pct']:+6.1f}% {r['noise_pct']:6.1f}% "
            f"{r['n_runs']:>5}  {r['flag']}"
        )


def write_markdown(rows: list[dict], path: Path, runs: list[dict]) -> None:
    """Markdown report — paste into a PR or CHANGELOG. Includes the
    commit window so readers know which range is summarized."""
    first_run = runs[0]["commit"]
    last_run = runs[-1]["commit"]
    with path.open("w") as f:
        f.write(f"# Bench trend: {first_run['id'][:8]} → {last_run['id'][:8]}\n\n")
        f.write(f"- {len(runs)} runs across "
                f"{first_run['timestamp'][:10]} → {last_run['timestamp'][:10]}\n")
        f.write(f"- Source: <{DATA_URL}>\n")
        f.write(f"- Alert threshold: ±{ALERT_PCT}% (matches "
                f"`.github/workflows/bench.yml`)\n\n")
        f.write("| bench | first | last | Δ% | noise% | runs | flag |\n")
        f.write("|---|---:|---:|---:|---:|---:|---|\n")
        for r in rows:
            f.write(
                f"| `{r['name']}` "
                f"| {fmt_ns(r['first'])} | {fmt_ns(r['last'])} "
                f"| {r['delta_pct']:+.1f}% | {r['noise_pct']:.1f}% "
                f"| {r['n_runs']} | {r['flag']} |\n"
            )
        f.write(
            "\n**Reading the flags:**\n\n"
            f"- `regress` / `improve` — last value differs from first by >{ALERT_PCT}%\n"
            "- `*noisy` suffix — the spread between min and max exceeds twice the\n"
            "  delta, so the change is indistinguishable from runner jitter.\n"
            "- `stable` — within ±10% of the first run.\n"
        )


def plot(rows: list[dict], series: dict[str, list[tuple]], out_path: Path) -> None:
    """Per-bench time-series plot. One subplot row per bench. Shaded
    band = min/max envelope; line = run-by-run value; vertical markers
    on the version-bump commits (commits whose message starts with
    a digit-dot pattern)."""
    try:
        import matplotlib.pyplot as plt
        import matplotlib.dates as mdates
    except ImportError:
        raise SystemExit("matplotlib required for --plot; install with `pip install matplotlib`")

    n = len(rows)
    fig, axes = plt.subplots(n, 1, figsize=(11, 1.6 * n), sharex=True)
    if n == 1:
        axes = [axes]
    for ax, r in zip(axes, rows):
        points = series[r["name"]]
        ts = [datetime.fromisoformat(p[0][:19]) for p in points]
        vals = [p[1] for p in points]
        ax.plot(ts, vals, marker=".", linewidth=1, color="#1f77b4")
        ax.axhline(r["min"], color="#999", linestyle=":", linewidth=0.5)
        ax.axhline(r["max"], color="#999", linestyle=":", linewidth=0.5)
        ax.fill_between(ts, r["min"], r["max"], alpha=0.08, color="#1f77b4")
        # Annotate version commits (release messages start "0.x.y" or "v0.x.y").
        for t, v, _, _, msg in points:
            if msg and (msg[0].isdigit() or (msg.startswith("v") and len(msg) > 1 and msg[1].isdigit())):
                head = msg.split(" — ")[0].split(":")[0].strip()
                ax.annotate(
                    head, (datetime.fromisoformat(t[:19]), v),
                    textcoords="offset points", xytext=(2, 4),
                    fontsize=7, color="#444", rotation=15,
                )
        title = f"{r['name']}  ({r['delta_pct']:+.1f}%, noise {r['noise_pct']:.0f}%, {r['flag']})"
        ax.set_title(title, fontsize=9, loc="left")
        ax.set_ylabel(r["unit"], fontsize=8)
        ax.tick_params(axis="both", labelsize=7)
        ax.grid(alpha=0.2)
    axes[-1].xaxis.set_major_formatter(mdates.DateFormatter("%m-%d %H:%M"))
    fig.autofmt_xdate()
    fig.suptitle(
        f"CIRISPersist criterion benches — {len(series[rows[0]['name']])} runs",
        fontsize=11, y=1.001,
    )
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    print(f"wrote {out_path}", file=sys.stderr)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default=DATA_URL,
                   help="bench data.js URL (default: gh-pages production)")
    p.add_argument("--since", help="filter runs to commits at/after YYYY-MM-DD")
    p.add_argument("--plot", type=Path, help="write per-bench PNG plot to this path")
    p.add_argument("--md", type=Path, help="write Markdown report to this path")
    p.add_argument("--json", action="store_true",
                   help="emit machine-readable JSON summary instead of the text table")
    args = p.parse_args()

    data = fetch_data(args.url)
    runs = filter_runs(runs_for_group(data), args.since)
    if not runs:
        raise SystemExit("no runs to analyze (maybe the --since filter is too strict?)")

    series = per_bench_series(runs)
    rows = summarize(series)

    if args.json:
        print(json.dumps(rows, indent=2))
    else:
        print_table(rows)

    if args.md:
        write_markdown(rows, args.md, runs)
        print(f"wrote {args.md}", file=sys.stderr)

    if args.plot:
        plot(rows, series, args.plot)

    return 0


if __name__ == "__main__":
    sys.exit(main())
