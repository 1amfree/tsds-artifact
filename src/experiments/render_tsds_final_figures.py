#!/usr/bin/env python3
"""Render the data-driven figures used by the ICECCS TSDS manuscript.

The renderer consumes only the accepted R7 campaign and its integrity audit.
It checks the paper-facing totals before producing LNCS-width vector PDFs and
color/grayscale previews for visual review.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "experiment_reports" / "tsds_v20_release_20260718_r7_v8"
DEFAULT_TARGETS = (
    RELEASE
    / "tsds_v20_accepted_repeat_20260718_r7"
    / "campaign"
    / "full_campaign_per_target.csv"
)
DEFAULT_VECTORS = (
    RELEASE
    / "tsds_v20_accepted_repeat_20260718_r7"
    / "vector_decision_integrity"
    / "vector_decision_integrity_audit.json"
)
DEFAULT_OUTPUT = ROOT / "overleaf_TSDS_cscloud2026" / "figures"


COLORS = {
    "direct_sat": "#C2410C",      # Terracotta / burnt orange
    "conditioned_sat": "#D97706", # Coral Amber
    "reached_sink": "#1E3A8A",    # Navy
    "static_evidence": "#059669", # Emerald
    "residual": "#94A3B8",        # Cool Slate / Inconclusive
    "sat": "#D97706",             # Coral Amber for vector profile
    "unsat": "#1E3A8A",           # Navy
    "inconclusive": "#94A3B8",    # Inconclusive
    "ink": "#1E293B",             # Dark Slate Ink
    "grid": "#E2E8F0",            # Subtle Slate Grid
    "line": "#CBD5E1",            # Connecting line
}

EXPECTED = {
    "records": 518,
    "vector_sat": 85,
    "direct_vector_sat": 51,
    "conditioned_vector_sat": 34,
    "matrix_unsat": 3,
    "no_modeled_source": 58,
    "static_source_inference": 15,
    "static_warning_reduction": 120,
    "residual": 237,
    "vector_sat_cells": 679,
    "matrix_unsat_cells": 292,
    "inconclusive_cells": 151,
}


def _configure_matplotlib() -> None:
    import matplotlib as mpl

    mpl.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 8.0,
            "axes.labelsize": 8.0,
            "axes.titlesize": 8.5,
            "xtick.labelsize": 7.2,
            "ytick.labelsize": 7.2,
            "legend.fontsize": 6.8,
            "pdf.fonttype": 42,
            "ps.fonttype": 42,
            "axes.linewidth": 0.50,
            "hatch.linewidth": 0.40,
            "lines.linewidth": 0.65,
            "grid.color": "#E2E8F0",
            "grid.linestyle": "--",
            "grid.linewidth": 0.50,
            "savefig.dpi": 320,
        }
    )


def _save(fig: Any, output: Path) -> None:
    import matplotlib.pyplot as plt
    from PIL import Image

    output.parent.mkdir(parents=True, exist_ok=True)
    # Exact IEEE single-column canvas without bounding box shifts.
    save_kw = {"bbox_inches": None, "pad_inches": 0, "facecolor": "white"}
    fig.savefig(output, format="pdf", **save_kw)
    preview = output.with_suffix(".png")
    fig.savefig(preview, dpi=320, **save_kw)

    grayscale = output.with_name(output.stem + "_gray.png")
    with Image.open(preview) as image:
        image.convert("L").save(grayscale, dpi=(320, 320))
    plt.close(fig)


def _load_target_rows(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    selected = [row for row in rows if row.get("target") != "TOTAL"]
    if len(selected) != 8:
        raise ValueError(f"expected eight firmware rows, found {len(selected)}")
    return selected


def _int(row: dict[str, str], field: str) -> int:
    return int(float(row.get(field, "0") or 0))


def _validate_target_totals(rows: list[dict[str, str]]) -> None:
    fields = {
        "records": "evaluated",
        "vector_sat": "vector_sat",
        "matrix_unsat": "matrix_unsat",
        "no_modeled_source": "no_modeled_source",
        "static_source_inference": "static_source_inference",
        "static_warning_reduction": "static_warning_reduction",
        "residual": "contract_residual",
    }
    for name, field in fields.items():
        observed = sum(_int(row, field) for row in rows)
        if observed != EXPECTED[name]:
            raise ValueError(f"{field}: expected {EXPECTED[name]}, observed {observed}")


def _load_positive_modes(campaign: Path) -> dict[str, tuple[int, int]]:
    modes: dict[str, tuple[int, int]] = {}
    for path in sorted(campaign.glob("*.results.jsonl")):
        target = path.name.removesuffix(".results.jsonl")
        direct = 0
        conditioned = 0
        with path.open("r", encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("verdict") != "VECTOR_SAT":
                    continue
                if record.get("evidence_provenance") == "DIRECT_SINK_BYTE":
                    direct += 1
                elif record.get("evidence_provenance") == "SINK_RECONCILED":
                    conditioned += 1
                else:
                    raise ValueError(
                        f"unknown positive evidence mode in {path}: "
                        f"{record.get('evidence_provenance')}"
                    )
        modes[target] = (direct, conditioned)
    return modes


def render_per_target(path: Path, output: Path, campaign: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    rows = _load_target_rows(path)
    _validate_target_totals(rows)
    modes = _load_positive_modes(campaign)
    direct = np.array([modes[row["target"]][0] for row in rows])
    conditioned = np.array([modes[row["target"]][1] for row in rows])
    if int(direct.sum()) != EXPECTED["direct_vector_sat"]:
        raise ValueError(f"direct positive total is {direct.sum()}, expected 51")
    if int(conditioned.sum()) != EXPECTED["conditioned_vector_sat"]:
        raise ValueError(
            f"conditioned positive total is {conditioned.sum()}, expected 34"
        )

    labels = [row["label"] for row in rows]
    records = np.array([_int(row, "evaluated") for row in rows])
    reached_reduction = np.array(
        [_int(row, "matrix_unsat") + _int(row, "no_modeled_source") for row in rows]
    )
    static_evidence = np.array(
        [
            _int(row, "static_source_inference")
            + _int(row, "static_warning_reduction")
            for row in rows
        ]
    )
    residual = np.array([_int(row, "contract_residual") for row in rows])
    non_residual_pct = 100.0 * (records - residual) / records
    aggregate_pct = 100.0 * (EXPECTED["records"] - EXPECTED["residual"]) / EXPECTED["records"]

    _configure_matplotlib()
    fig, (ax_count, ax_rate) = plt.subplots(
        1,
        2,
        figsize=(3.50, 2.50),
        sharey=True,
        gridspec_kw={"width_ratios": [2.50, 1.0], "wspace": 0.12},
    )
    y = np.arange(len(rows))
    left = np.zeros(len(rows), dtype=float)
    series = [
        ("Direct SV-SAT", direct, COLORS["direct_sat"], ""),
        ("Conditioned CT-SAT", conditioned, COLORS["conditioned_sat"], "xx"),
        ("Reached-sink", reached_reduction, COLORS["reached_sink"], "///"),
        ("Static evidence", static_evidence, COLORS["static_evidence"], ".."),
        ("Residual", residual, COLORS["residual"], "\\\\"),
    ]
    for label, values, color, hatch in series:
        ax_count.barh(
            y,
            values,
            left=left,
            height=0.60,
            color=color,
            edgecolor="white",
            linewidth=0.35,
            hatch=hatch,
            label=label,
        )
        left += values

    ax_count.set_yticks(y, labels)
    ax_count.invert_yaxis()
    ax_count.set_xlim(0, 185)
    ax_count.set_xticks([0, 50, 100, 150])
    ax_count.set_xlabel("Records (N)", fontsize=7.8)
    ax_count.set_title("(a) Evidence composition", loc="left", fontweight="bold", fontsize=8.2, pad=3)
    ax_count.grid(axis="x", color=COLORS["grid"], linewidth=0.5, linestyle="--")
    ax_count.set_axisbelow(True)
    ax_count.tick_params(axis="y", length=0, pad=2)
    ax_count.tick_params(axis="x", labelsize=7.2)
    for yi, total in enumerate(records):
        ax_count.text(total + 2.5, yi, str(total), va="center", ha="left", fontsize=6.6, color="#1E293B")

    # Data pill badge in panel (a)
    ax_count.text(
        175,
        0.50,
        "Total N = 518",
        ha="right",
        va="center",
        fontsize=6.3,
        fontweight="bold",
        color="#1E3A8A",
        bbox=dict(boxstyle="round,pad=0.20", facecolor="#F8FAFC", edgecolor="#CBD5E1", lw=0.45),
    )

    # Panel (b) Coverage
    ax_rate.axvline(aggregate_pct, color="#475569", linestyle="--", linewidth=0.65)
    ax_rate.text(
        aggregate_pct,
        1.50,
        "Agg. 54.2%",
        ha="center",
        va="center",
        fontsize=6.1,
        fontweight="bold",
        color="#1E3A8A",
        bbox=dict(boxstyle="round,pad=0.20", facecolor="#EFF6FF", edgecolor="#BFDBFE", lw=0.45),
    )
    ax_rate.hlines(y, 0, non_residual_pct, color=COLORS["line"], linewidth=0.65)
    ax_rate.scatter(
        non_residual_pct,
        y,
        s=18,
        color="#1E3A8A",
        edgecolor="white",
        linewidth=0.35,
        zorder=3,
    )
    for yi, value in enumerate(non_residual_pct):
        ax_rate.text(
            value + 2.5,
            yi,
            f"{value:.0f}%",
            ha="left",
            va="center",
            fontsize=6.6,
            color="#1E293B",
        )
    ax_rate.set_xlim(0, 105)
    ax_rate.set_xticks([0, 50, 100])
    ax_rate.set_xlabel("Coverage (%)", fontsize=7.8)
    ax_rate.set_title("(b) Coverage", loc="left", fontweight="bold", fontsize=8.2, pad=4)
    ax_rate.grid(axis="x", color=COLORS["grid"], linewidth=0.5, linestyle="--")
    ax_rate.set_axisbelow(True)
    ax_rate.tick_params(axis="y", length=0)
    ax_rate.tick_params(axis="x", labelsize=7.2)

    ax_count.set_ylim(len(rows) - 0.5, -0.90)
    for ax in (ax_count, ax_rate):
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.spines["bottom"].set_color("#64748B")
        ax.spines["bottom"].set_linewidth(0.50)

    handles, legend_labels = ax_count.get_legend_handles_labels()
    fig.legend(
        handles,
        legend_labels,
        ncol=3,
        loc="upper center",
        bbox_to_anchor=(0.50, 0.99),
        frameon=False,
        fontsize=6.6,
        handlelength=1.1,
        handleheight=0.6,
        handletextpad=0.25,
        columnspacing=0.7,
        labelspacing=0.25,
    )
    fig.subplots_adjust(left=0.24, right=0.98, top=0.76, bottom=0.15)
    _save(fig, output)


VECTOR_ORDER = [
    ("semicolon", ";"),
    ("newline", "newline"),
    ("pipe", "|"),
    ("background_ampersand", "&"),
    ("backtick_substitution", "backtick"),
    ("dollar_substitution", "\\$()"),
    ("dollar_expansion", "\\$"),
    ("output_redirection", ">"),
    ("input_redirection", "<"),
    ("ifs_word_splitting", "\\${IFS}"),
    ("tab_word_splitting", "tab"),
]


def render_vector_profile(path: Path, output: Path) -> None:
    import matplotlib.pyplot as plt
    import numpy as np

    audit = json.loads(path.read_text(encoding="utf-8"))
    if audit.get("records_with_decisions") != 102:
        raise ValueError("matrix-profiled record count is not 102")
    outcomes = audit["decision_outcomes"]
    checks = {
        "vector_sat_cells": outcomes["VECTOR_SAT"],
        "matrix_unsat_cells": outcomes["MATRIX_UNSAT"],
        "inconclusive_cells": outcomes["INCONCLUSIVE"],
    }
    for name, observed in checks.items():
        if observed != EXPECTED[name]:
            raise ValueError(f"{name}: expected {EXPECTED[name]}, observed {observed}")

    labels: list[str] = []
    sat: list[int] = []
    unsat: list[int] = []
    inconclusive: list[int] = []
    for vector_id, label in VECTOR_ORDER:
        row = audit["per_vector"][vector_id]
        labels.append(label)
        sat.append(int(row["VECTOR_SAT"]))
        unsat.append(int(row["MATRIX_UNSAT"]))
        inconclusive.append(int(row["INCONCLUSIVE"]))
    if any(a + b + c != 102 for a, b, c in zip(sat, unsat, inconclusive)):
        raise ValueError("each vector row must contain 102 decisions")

    _configure_matplotlib()
    fig, (ax_count, ax_share) = plt.subplots(
        1,
        2,
        figsize=(3.50, 2.50),
        sharey=True,
        gridspec_kw={"width_ratios": [2.35, 1.0], "wspace": 0.14},
    )
    y = np.arange(len(labels))
    sat_arr = np.asarray(sat)
    unsat_arr = np.asarray(unsat)
    inc_arr = np.asarray(inconclusive)

    ax_count.barh(
        y,
        sat_arr,
        height=0.60,
        color=COLORS["sat"],
        edgecolor="white",
        linewidth=0.35,
        label="SAT",
    )
    ax_count.barh(
        y,
        unsat_arr,
        left=sat_arr,
        height=0.60,
        color=COLORS["unsat"],
        edgecolor="white",
        linewidth=0.35,
        hatch="///",
        label="UNSAT",
    )
    ax_count.barh(
        y,
        inc_arr,
        left=sat_arr + unsat_arr,
        height=0.60,
        color=COLORS["inconclusive"],
        edgecolor="white",
        linewidth=0.35,
        hatch="\\\\",
        label="Inconclusive",
    )

    for yi, values in enumerate(zip(sat, unsat, inconclusive)):
        start = 0
        for value in values:
            if value >= 13:
                ax_count.text(
                    start + value / 2,
                    yi,
                    str(value),
                    ha="center",
                    va="center",
                    fontsize=6.3,
                    fontweight="bold",
                    color="white",
                )
            start += value

    ax_count.set_yticks(y, labels)
    ax_count.invert_yaxis()
    ax_count.set_xlim(0, 102)
    ax_count.set_xticks([0, 25, 50, 75, 102], ["0", "25", "50", "75", "102"])
    ax_count.set_xlabel("Matrix decisions", fontsize=7.8)
    ax_count.set_title("(a) Decision profile", loc="left", fontweight="bold", fontsize=8.2, pad=4)
    ax_count.tick_params(axis="y", length=0, pad=2)
    ax_count.tick_params(axis="x", labelsize=7.2)

    # Data pill badge in panel (a)
    ax_count.text(
        98,
        -0.45,
        "Total N = 1,122",
        ha="right",
        va="bottom",
        fontsize=6.2,
        fontweight="bold",
        color="#1E3A8A",
        bbox=dict(boxstyle="round,pad=0.18", facecolor="#F8FAFC", edgecolor="#CBD5E1", lw=0.45),
    )

    sat_share = 100.0 * sat_arr / 102.0
    ax_share.hlines(y, 0, sat_share, color=COLORS["line"], linewidth=0.65)
    ax_share.scatter(
        sat_share,
        y,
        s=18,
        color=COLORS["sat"],
        edgecolor="white",
        linewidth=0.35,
        zorder=3,
    )
    for yi, value in enumerate(sat_share):
        ax_share.text(
            value + 2.5,
            yi,
            f"{value:.0f}%",
            ha="left",
            va="center",
            fontsize=6.6,
            color="#1E293B",
        )
    ax_share.set_xlim(0, 105)
    ax_share.set_xticks([0, 50, 100])
    ax_share.set_xlabel("SAT share (%)", fontsize=7.8)
    ax_share.set_title("(b) SAT share", loc="left", fontweight="bold", fontsize=8.2, pad=4)
    ax_share.tick_params(axis="y", length=0)
    ax_share.tick_params(axis="x", labelsize=7.2)

    # Substitution peak badge in panel (b)
    ax_share.text(
        26,
        5.0,
        "Subst. ~82%",
        ha="center",
        va="center",
        fontsize=6.0,
        fontweight="bold",
        color="#B45309",
        bbox=dict(boxstyle="round,pad=0.18", facecolor="#FFFBEB", edgecolor="#FDE68A", lw=0.45),
    )

    for ax in (ax_count, ax_share):
        ax.grid(axis="x", color=COLORS["grid"], linewidth=0.5, linestyle="--")
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.spines["bottom"].set_color("#64748B")
        ax.spines["bottom"].set_linewidth(0.50)
    for boundary in (3.5, 6.5, 8.5):
        ax_count.axhline(boundary, color="#CBD5E1", linewidth=0.55, linestyle=":")
        ax_share.axhline(boundary, color="#CBD5E1", linewidth=0.55, linestyle=":")

    handles, legend_labels = ax_count.get_legend_handles_labels()
    fig.legend(
        handles,
        legend_labels,
        ncol=3,
        loc="upper center",
        bbox_to_anchor=(0.50, 0.99),
        frameon=False,
        fontsize=7.0,
        handlelength=1.1,
        handleheight=0.6,
        handletextpad=0.25,
        columnspacing=1.2,
    )
    ax_count.set_ylim(len(labels) - 0.5, -0.90)
    fig.subplots_adjust(left=0.16, right=0.98, top=0.82, bottom=0.15)
    _save(fig, output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS)
    parser.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--no-sync", action="store_true", help="Disable syncing to sibling overleaf directories")
    args = parser.parse_args()

    out_dir = args.output_dir.resolve()
    render_per_target(
        args.targets.resolve(),
        out_dir / "per_target_profile.pdf",
        args.targets.resolve().parent,
    )
    render_vector_profile(args.vectors.resolve(), out_dir / "vector_profile.pdf")

    if not args.no_sync:
        import shutil
        siblings = [
            ROOT / "overleaf_TSDS_final" / "figures",
            ROOT / "overleaf_TSDS_saner2027" / "figures",
        ]
        files = [
            "per_target_profile.pdf",
            "per_target_profile.png",
            "per_target_profile_gray.png",
            "vector_profile.pdf",
            "vector_profile.png",
            "vector_profile_gray.png",
        ]
        for sib in siblings:
            if sib.exists() and sib.resolve() != out_dir:
                for f in files:
                    src = out_dir / f
                    if src.exists():
                        shutil.copy2(src, sib / f)


if __name__ == "__main__":
    main()


