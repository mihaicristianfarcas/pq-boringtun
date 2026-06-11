#!/usr/bin/env python3
"""
Render the measurement CSVs into LaTeX `tabular` blocks for direct paste
into the thesis chapters. Stdlib only -- no pandas, no jinja.

Usage:
    paper/tools/render_tables.py mtu       < paper/measurements/netns-mtu-sweep.csv
    paper/tools/render_tables.py rtt-loss  < paper/measurements/netns-rtt-loss-matrix.csv
    paper/tools/render_tables.py dos       < paper/measurements/netns-dos-flood.csv
    paper/tools/render_tables.py mlkem-sweep platform_label \\
        < paper/measurements/<criterion-text-summary>

For convenience also:
    paper/tools/render_tables.py all       # reads all three default paths,
                                           # writes paper/measurements/tables.tex

Tables use booktabs (\\toprule, \\midrule, \\bottomrule). Add
`\\usepackage{booktabs}` to the thesis preamble if it isn't there yet.
"""

from __future__ import annotations

import csv
import io
import os
import sys
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PATHS = {
    "mtu":      REPO_ROOT / "paper/measurements/netns-mtu-sweep.csv",
    "rtt-loss": REPO_ROOT / "paper/measurements/netns-rtt-loss-matrix.csv",
    "dos":      REPO_ROOT / "paper/measurements/netns-dos-flood.csv",
}


# ---------------------------------------------------------------------------
#  helpers
# ---------------------------------------------------------------------------

def fmt_pct(rate: str) -> str:
    """0.95 -> '95\\%' ; NaN -> '--'."""
    try:
        return f"{float(rate) * 100:.0f}\\%"
    except (TypeError, ValueError):
        return "--"


def fmt_ms(value: str) -> str:
    """Float ms with one decimal; NaN -> '--'."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "--"
    if v != v:  # NaN
        return "--"
    return f"{v:.1f}"


def fmt_us(value: str) -> str:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return "--"
    if v != v:
        return "--"
    return f"{v:.2f}"


def tex_escape(s: str) -> str:
    """Escape the handful of LaTeX-special chars that can appear in our cells."""
    return (
        s.replace("\\", r"\textbackslash{}")
         .replace("_", r"\_")
         .replace("&", r"\&")
         .replace("%", r"\%")
         .replace("#", r"\#")
    )


def read_rows(stream: Iterable[str]) -> list[dict]:
    reader = csv.DictReader(stream)
    return [dict(row) for row in reader]


# ---------------------------------------------------------------------------
#  table renderers
# ---------------------------------------------------------------------------

def render_mtu(rows: list[dict]) -> str:
    """
    Input columns:
        mode, mtu, drop_frags, trials, successes, success_rate, p50_rtt_ms

    Output: one row per (mtu, drop) with vanilla & hybrid columns side-by-side.
    """
    # Group by (mtu, drop_frags). Within each group expect 'vanilla' and 'pq'.
    by_key: dict[tuple[int, str], dict[str, dict]] = {}
    for r in rows:
        key = (int(r["mtu"]), r["drop_frags"])
        by_key.setdefault(key, {})[r["mode"]] = r

    out = io.StringIO()
    out.write(r"""\begin{table}[t]
\centering
\caption{Handshake success rate and median first-packet latency across
the path-MTU sweep, with and without an IP-fragment-dropping middlebox.
Latency includes the handshake cost; values are over 10 trials per cell.}
\label{tab:mtu-sweep}
\begin{tabular}{rlrcrc}
\toprule
 & & \multicolumn{2}{c}{Vanilla} & \multicolumn{2}{c}{Hybrid} \\
\cmidrule(lr){3-4}\cmidrule(lr){5-6}
MTU (B) & Drop frags & Success & $p_{50}$ (ms) & Success & $p_{50}$ (ms) \\
\midrule
""")
    drop_order = {"none": 0, "drop_frags": 1}
    for key in sorted(by_key.keys(), key=lambda k: (-k[0], drop_order.get(k[1], 9))):
        mtu, drop = key
        cell = by_key[key]
        v = cell.get("vanilla", {})
        p = cell.get("pq", {})
        out.write(
            f"{mtu} & {tex_escape(drop)} & "
            f"{fmt_pct(v.get('success_rate', 'NaN'))} & {fmt_ms(v.get('p50_rtt_ms', 'NaN'))} & "
            f"{fmt_pct(p.get('success_rate', 'NaN'))} & {fmt_ms(p.get('p50_rtt_ms', 'NaN'))} "
            r"\\" + "\n"
        )
    out.write(r"""\bottomrule
\end{tabular}
\end{table}
""")
    return out.getvalue()


def render_rtt_loss(rows: list[dict]) -> str:
    """
    Input columns:
        mode, delay_ms, loss_pct, trials, successes, success_rate,
        p50_rtt_ms, p95_rtt_ms
    """
    by_key: dict[tuple[float, float], dict[str, dict]] = {}
    for r in rows:
        key = (float(r["delay_ms"]), float(r["loss_pct"]))
        by_key.setdefault(key, {})[r["mode"]] = r

    out = io.StringIO()
    out.write(r"""\begin{table}[t]
\centering
\caption{Handshake completion latency under injected one-way delay and
symmetric packet loss. First-packet ping RTT subsumes the handshake
cost. Values are 20 trials per cell at 1500-byte MTU.}
\label{tab:rtt-loss-matrix}
\begin{tabular}{rrcrrcrr}
\toprule
 & & \multicolumn{3}{c}{Vanilla} & \multicolumn{3}{c}{Hybrid} \\
\cmidrule(lr){3-5}\cmidrule(lr){6-8}
Delay (ms) & Loss (\%) & Success & $p_{50}$ & $p_{95}$ & Success & $p_{50}$ & $p_{95}$ \\
\midrule
""")
    for key in sorted(by_key.keys()):
        delay, loss = key
        cell = by_key[key]
        v = cell.get("vanilla", {})
        p = cell.get("pq", {})
        out.write(
            f"{delay:.0f} & {loss:g} & "
            f"{fmt_pct(v.get('success_rate', 'NaN'))} & {fmt_ms(v.get('p50_rtt_ms', 'NaN'))} & {fmt_ms(v.get('p95_rtt_ms', 'NaN'))} & "
            f"{fmt_pct(p.get('success_rate', 'NaN'))} & {fmt_ms(p.get('p50_rtt_ms', 'NaN'))} & {fmt_ms(p.get('p95_rtt_ms', 'NaN'))} "
            r"\\" + "\n"
        )
    out.write(r"""\bottomrule
\end{tabular}
\end{table}
""")
    return out.getvalue()


def render_dos(rows: list[dict]) -> str:
    """
    Input columns:
        mode, mac1, target_pps, duration_sec, packets_sent, cpu_sec,
        cpu_per_pkt_us
    """
    out = io.StringIO()
    out.write(r"""\begin{table}[t]
\centering
\caption{Responder CPU cost under a 10-second saturating handshake-init
flood, by handshake mode and MAC1 validity. \emph{cpu/pkt} is the
responder CPU time per received init packet; the asymmetry between
\emph{invalid} and \emph{valid} confirms MAC1 rejection short-circuits
before the ML-KEM Encaps step.}
\label{tab:dos-flood}
\begin{tabular}{llrrr}
\toprule
Mode & MAC1 & Packets sent & CPU (s) & cpu/pkt ($\mu$s) \\
\midrule
""")
    # Sort: vanilla before pq, invalid before valid, so the table reads
    # in increasing-asymmetry order.
    order = {"vanilla": 0, "pq": 1, "invalid": 0, "valid": 1}
    for r in sorted(rows, key=lambda x: (order.get(x["mode"], 9), order.get(x["mac1"], 9))):
        out.write(
            f"{r['mode']} & {r['mac1']} & "
            f"{int(r.get('packets_sent', 0)):,} & "
            f"{fmt_ms(r.get('cpu_sec', 'NaN'))} & "
            f"{fmt_us(r.get('cpu_per_pkt_us', 'NaN'))} "
            r"\\" + "\n"
        )
    out.write(r"""\bottomrule
\end{tabular}
\end{table}
""")
    return out.getvalue()


# ---------------------------------------------------------------------------
#  ML-KEM sweep -- not a CSV; parses the text summary grep
# ---------------------------------------------------------------------------

def render_mlkem_sweep(stream: Iterable[str], platform_label: str) -> str:
    """
    Reads the compact `grep -E "^[a-z0-9_/]+ +time:"` summary from a
    Criterion run and renders the ML-KEM 512/768/1024 rows.

    Example input line (Criterion's standard format):

        mlkem768/keygen         time:   [23.821 us 23.846 us 23.870 us]

    The middle estimate is the point; the brackets are the 95 % CI.
    """
    cells: dict[tuple[str, str], tuple[float, float, float]] = {}
    for line in stream:
        line = line.strip()
        if not line.startswith("mlkem"):
            continue
        head, _, rest = line.partition("time:")
        head = head.strip()
        if "/" not in head:
            continue
        param, op = head.split("/", 1)
        # rest looks like:  [23.821 us 23.846 us 23.870 us]
        rest = rest.strip().strip("[]")
        toks = [t for t in rest.split() if t and t != "us"]
        if len(toks) >= 3:
            try:
                lo, mid, hi = float(toks[0]), float(toks[1]), float(toks[2])
            except ValueError:
                continue
            cells[(param.strip(), op.strip())] = (lo, mid, hi)

    out = io.StringIO()
    out.write(r"""\begin{table}[t]
\centering
\caption{ML-KEM parameter-set latency (""" + platform_label + r""")
across all three FIPS-203 security levels. Values are Criterion
bootstrapped 95\,\% CIs over 1000 samples; the middle column of each
group is the point estimate.}
\label{tab:mlkem-sweep-""" + platform_label.lower().replace(" ", "-") + r"""}
\begin{tabular}{lrrr}
\toprule
Param set & Keygen ($\mu$s) & Encaps ($\mu$s) & Decaps ($\mu$s) \\
\midrule
""")
    for param in ("mlkem512", "mlkem768", "mlkem1024"):
        pretty = {
            "mlkem512": "ML-KEM-512",
            "mlkem768": "ML-KEM-768",
            "mlkem1024": "ML-KEM-1024",
        }[param]
        row_parts = [pretty]
        for op in ("keygen", "encaps", "decaps"):
            if (param, op) in cells:
                lo, mid, hi = cells[(param, op)]
                row_parts.append(f"{mid:.2f} [{lo:.2f}, {hi:.2f}]")
            else:
                row_parts.append("--")
        out.write(" & ".join(row_parts) + r" \\" + "\n")
    out.write(r"""\bottomrule
\end{tabular}
\end{table}
""")
    return out.getvalue()


# ---------------------------------------------------------------------------
#  main
# ---------------------------------------------------------------------------

RENDERERS = {
    "mtu":      lambda s: render_mtu(read_rows(s)),
    "rtt-loss": lambda s: render_rtt_loss(read_rows(s)),
    "dos":      lambda s: render_dos(read_rows(s)),
}


def render_all_to_file() -> Path:
    out_path = REPO_ROOT / "paper/measurements/tables.tex"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as out:
        out.write("% Auto-generated by paper/tools/render_tables.py\n")
        out.write("% Re-run after pasting new CSV measurements.\n\n")
        for kind, path in DEFAULT_PATHS.items():
            if not path.exists():
                out.write(f"% --- {kind}: SKIPPED ({path} not found) ---\n\n")
                continue
            with path.open() as src:
                out.write(f"% --- {kind} (from {path.relative_to(REPO_ROOT)}) ---\n")
                out.write(RENDERERS[kind](src))
                out.write("\n")
    return out_path


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2

    cmd = argv[1]
    if cmd == "all":
        path = render_all_to_file()
        print(f"wrote {path}")
        return 0
    if cmd == "mlkem-sweep":
        platform = argv[2] if len(argv) >= 3 else "platform"
        sys.stdout.write(render_mlkem_sweep(sys.stdin, platform))
        return 0
    if cmd in RENDERERS:
        sys.stdout.write(RENDERERS[cmd](sys.stdin))
        return 0
    print(f"unknown command: {cmd}", file=sys.stderr)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
