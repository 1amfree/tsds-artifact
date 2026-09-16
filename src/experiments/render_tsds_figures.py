#!/usr/bin/env python3
"""Render publication-style TSDS result figures.

The figures are designed for LNCS single-column papers: vector PDF output,
color-blind friendly palette, compact annotations, and no dashboard-style
decorative panels.
"""

from __future__ import annotations

import argparse
import csv
from pathlib import Path
from typing import Dict, List


DEFAULT_INPUT = Path("experiment_reports/full_firmware_campaign_current_tsds_20260627/full_campaign_per_target.csv")
DEFAULT_OUT = Path("../overleaf_cli/Contribution_Title/tsds_evidence_profile.pdf")


TARGET_LABELS = {
    "asus_rt_be57": "ASUS RT-BE57",
    "dir878": "D-Link DIR-878",
    "r6400v2": "Netgear R6400v2",
    "r7000": "Netgear R7000",
    "tenda_ac15": "Tenda AC15",
    "tenda_ac18": "Tenda AC18",
    "tenda_w20e": "Tenda W20E",
    "xr300": "Netgear XR300",
}


def load_rows(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return [row for row in csv.DictReader(f) if row.get("target") != "TOTAL"]


def as_int(value: str) -> int:
    return int(float(value or 0))


def row_count(row: Dict[str, str]) -> int:
    return as_int(row.get("records") or row.get("evaluated") or row.get("Rec.") or 0)


def pct(count: int, total: int) -> float:
    return 100.0 * count / total if total else 0.0


def render(input_csv: Path, output_pdf: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    rows = load_rows(input_csv)
    labels = [TARGET_LABELS.get(row["target"], row["target"]) for row in rows]
    records = np.array([row_count(row) for row in rows], dtype=float)
    values = {
        "SV-SAT": np.array([pct(as_int(row["vulnerable"]), row_count(row)) for row in rows]),
        "M-Filt.": np.array([pct(as_int(row["filtered"]), row_count(row)) for row in rows]),
        "NoT": np.array([pct(as_int(row["no_taint_sink"]), row_count(row)) for row in rows]),
        "Residual": np.array(
            [
                pct(as_int(row["unreachable"]) + as_int(row["timeout"]), row_count(row))
                for row in rows
            ]
        ),
    }
    colors = {
        "SV-SAT": "#CC6677",
        "M-Filt.": "#117733",
        "NoT": "#88CCEE",
        "Residual": "#999999",
    }
    hatch = {"SV-SAT": "", "M-Filt.": "///", "NoT": "", "Residual": "\\\\"}

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 7.2,
            "axes.labelsize": 7.2,
            "axes.titlesize": 7.5,
            "xtick.labelsize": 6.5,
            "ytick.labelsize": 6.8,
            "legend.fontsize": 6.6,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
        }
    )

    fig, ax = plt.subplots(figsize=(6.6, 2.95))
    y = np.arange(len(rows))
    left = np.zeros(len(rows))
    for name in ["SV-SAT", "M-Filt.", "NoT", "Residual"]:
        ax.barh(
            y,
            values[name],
            left=left,
            height=0.64,
            label=name,
            color=colors[name],
            edgecolor="white",
            linewidth=0.45,
            hatch=hatch[name],
        )
        left += values[name]

    ax.set_yticks(y)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.set_xlabel("Share of analyzed records (%)")
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.grid(axis="x", color="#d0d0d0", linewidth=0.45, alpha=0.9)
    ax.set_axisbelow(True)
    for spine in ["top", "right", "left"]:
        ax.spines[spine].set_visible(False)
    ax.spines["bottom"].set_linewidth(0.5)
    ax.tick_params(axis="y", length=0)
    ax.tick_params(axis="x", width=0.5, length=2.5)

    for yi, rec in enumerate(records.astype(int)):
        ax.text(101.0, yi, f"n={rec}", va="center", ha="left", fontsize=6.2, color="#444444")

    legend = ax.legend(
        ncol=4,
        loc="lower center",
        bbox_to_anchor=(0.5, 1.02),
        frameon=False,
        handlelength=1.3,
        columnspacing=1.4,
        borderaxespad=0.0,
    )
    for patch in legend.get_patches():
        patch.set_height(5)

    total = {
        "vuln": sum(as_int(row["vulnerable"]) for row in rows),
        "filtered": sum(as_int(row["filtered"]) for row in rows),
        "notaint": sum(as_int(row["no_taint_sink"]) for row in rows),
        "resid": sum(as_int(row["unreachable"]) + as_int(row["timeout"]) for row in rows),
        "records": sum(row_count(row) for row in rows),
        "partial": sum(as_int(row.get("partial_vulnerable", 0)) for row in rows),
    }
    note = (
        f"Total: {total['records']} records; {total['vuln']} SV-SAT, "
        f"{total['filtered']} M-Filt., {total['notaint']} NoT, "
        f"{total['resid']} residual. Partial-filter profiles are a subset of SV-SAT records."
    )
    fig.text(0.01, 0.01, note, ha="left", va="bottom", fontsize=6.3, color="#333333")
    fig.subplots_adjust(left=0.22, right=0.92, top=0.83, bottom=0.19)
    output_pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_pdf, format="pdf", bbox_inches="tight", pad_inches=0.015)
    fig.savefig(output_pdf.with_suffix(".png"), dpi=220, bbox_inches="tight", pad_inches=0.015)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default=str(DEFAULT_INPUT))
    parser.add_argument("--output", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    render(Path(args.input).resolve(), Path(args.output).resolve())


if __name__ == "__main__":
    main()
