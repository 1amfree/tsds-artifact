#!/usr/bin/env python3
"""Build a safe canary-validation plan for the strongest TSDS candidates.

The plan is intentionally not an exploit recipe.  It prefers sink-intercept
validation, where firmware command sinks are hooked or replaced so the command
argument is logged and no shell side effect is executed.  A real canary command
should only be used later in isolated emulation or on owned hardware.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List


DEFAULT_CANDIDATES = Path("experiment_reports/poc_validation_candidates_v9_20260626/poc_validation_candidates.csv")
DEFAULT_REPRO = Path("experiment_reports/poc_candidate_repro_v9_20260626/candidate_repro.csv")
DEFAULT_OUT = Path("experiment_reports/canary_validation_plan_v9_20260626")


STATIC_STRING_CLUES: Dict[str, Dict[str, List[str]]] = {
    "poc-02": {
        "entry_clues": [
            "start_DDNS_ipv6",
            "stop_DDNS_ipv6",
            "upadte_DDNS_ipv6",
            "inadyn",
            "/var/inadyn%d.conf",
            "/var/run/inadyn.pid",
        ],
        "configuration_clues": [
            "DDNSEnabled",
            "DDNSProvider",
            "DDNSAccount",
            "DDNSPassword",
            "DDNSTimeout",
            "DDNSv6_%d",
        ],
    },
    "poc-06": {
        "entry_clues": [
            "webs_Tenda_CGI_BIN_Handler",
            "formSetFirewallCfg",
            "SetFirewallCfg",
            "GetFirewallCfg",
            "GetDdosDefenceList",
        ],
        "configuration_clues": [
            "lan.mask",
            "lan.ip",
            "lan.webport",
            "firewall.pingwan",
            "security.ddos.map",
            "security.ipop.map",
        ],
    },
    "poc-07": {
        "entry_clues": [
            "formSetSambaConf",
            "formGetSambaConf",
            "SetSambaCfg",
            "GetSambaCfg",
            "smbd",
            "samba_ok",
            "/tmp/smbpasswd",
        ],
        "configuration_clues": [
            "usb.samba.guest.user",
            "usb.samba.enable",
            "usb.samba.pwd",
            "usb.samba.guest.pwd",
            "usb.samba.user",
        ],
    },
}


RECOMMENDED_IDS = ["poc-06", "poc-07", "poc-02"]


def load_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def as_int(value: Any) -> int:
    if value in (None, ""):
        return 0
    try:
        return int(value)
    except Exception:
        try:
            return int(float(value))
        except Exception:
            return 0


def short(value: Any, limit: int = 120) -> str:
    text = str(value or "").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def split_clues(value: str) -> List[str]:
    return [item.strip() for item in str(value or "").split(";") if item.strip()]


def validation_priority(candidate: Dict[str, str], repro: Dict[str, str]) -> int:
    score = 0
    if candidate.get("readiness") == "high":
        score += 80
    if candidate.get("source_function", "").startswith("form"):
        score += 35
    if candidate.get("analysis_recovery") in {"static_direct_source_fallback", "static_sink_template_fallback"}:
        score += 20
    if split_clues(candidate.get("source_clues", "")):
        score += 10
    if repro.get("repro_verdict") == "PASS":
        score += 20
    if candidate.get("functional_theme") in {"firewall-iptables", "samba", "ddns", "macfilter"}:
        score += 10
    return score


def task_kind(candidate: Dict[str, str]) -> str:
    source = candidate.get("source_function", "")
    theme = candidate.get("functional_theme", "")
    if source.startswith("form"):
        return "web-handler sink-intercept canary"
    if theme == "ddns":
        return "service-configuration sink-intercept canary"
    return "firmware-routine sink-intercept canary"


def fixture_strategy(candidate: Dict[str, str]) -> str:
    cid = candidate["candidate_id"]
    keys = STATIC_STRING_CLUES.get(cid, {}).get("configuration_clues") or split_clues(candidate.get("source_clues", ""))
    if candidate.get("source_function", "").startswith("form"):
        return (
            "Map the firmware Web handler to its local CGI/action dispatcher in isolated emulation; "
            "seed only the listed configuration keys with a unique inert token, then intercept the command sink."
        )
    if candidate.get("functional_theme") == "ddns":
        return (
            "Seed DDNS NVRAM/configuration keys and invoke the local service routine inside the emulated firmware; "
            "intercept the command sink and disable outbound network effects."
        )
    return (
        "Recover the local trigger or directly invoke the routine in a harness; intercept the command sink before any shell execution."
    )


def safe_observation(candidate: Dict[str, str], token: str) -> str:
    return (
        f"Observe token {token} in the intercepted sink argument at {candidate.get('sink_function')}@"
        f"{candidate.get('sink_addr')} and verify that the command template matches the TSDS preview; "
        "do not execute the intercepted command."
    )


def build_task(candidate: Dict[str, str], repro: Dict[str, str], rank: int) -> Dict[str, Any]:
    cid = candidate["candidate_id"]
    token = f"TSDS_CANARY_{cid.upper().replace('-', '_')}"
    static = STATIC_STRING_CLUES.get(cid, {})
    source_keys = static.get("configuration_clues") or split_clues(candidate.get("source_clues", ""))
    entry_clues = static.get("entry_clues") or [candidate.get("source_function", "")]
    return {
        "rank": rank,
        "candidate_id": cid,
        "target": candidate.get("target", ""),
        "functional_theme": candidate.get("functional_theme", ""),
        "task_kind": task_kind(candidate),
        "readiness": candidate.get("readiness", ""),
        "evidence_type": candidate.get("evidence_type", ""),
        "source_function": candidate.get("source_function", ""),
        "sink": f"{candidate.get('sink_function')}@{candidate.get('sink_addr')}",
        "closure_idx": candidate.get("closure_idx", ""),
        "closure_ordinal": candidate.get("closure_ordinal", ""),
        "source_keys": "; ".join(source_keys),
        "entry_clues": "; ".join(entry_clues),
        "tsds_preview": short(candidate.get("command_preview", ""), 180),
        "repro_verdict": repro.get("repro_verdict", ""),
        "repro_signature": (
            f"{repro.get('expected_status', '')}; "
            f"{repro.get('expected_vulnerable_vectors', '')} SAT / "
            f"{repro.get('expected_secure_vectors', '')} UNSAT"
        ),
        "canary_token": token,
        "primary_validation": "sink-intercept logging; no shell execution",
        "fixture_strategy": fixture_strategy(candidate),
        "safe_observation": safe_observation(candidate, token),
        "required_artifacts": (
            "firmware rootfs or rehosted service, handler/service trigger map, sink interception log, "
            "TSDS result JSONL, timestamped run transcript"
        ),
        "non_goals": (
            "Do not test against public devices, do not execute destructive commands, "
            "and do not count the result as device-confirmed unless an isolated canary effect is observed."
        ),
        "priority_score": validation_priority(candidate, repro),
    }


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fields: List[str] = []
    for row in rows:
        for key in row:
            if key not in fields:
                fields.append(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def markdown(tasks: List[Dict[str, Any]], all_count: int) -> str:
    lines = [
        "# TSDS Safe Canary Validation Plan",
        "",
        "This plan prepares the next validation step for selected TSDS candidates. It is not an exploit guide. The first validation mode is sink-intercept logging: command sinks are hooked or replaced so command arguments are recorded without invoking a shell.",
        "",
        f"- Candidate worklist size: `{all_count}`",
        f"- Selected first-wave tasks: `{len(tasks)}`",
        "- First-wave selection: high-readiness cases with clear configuration keys, reproduced TSDS signatures, and diverse firmware/function themes.",
        "",
        "| Rank | ID | Target | Theme | Kind | Repro | Observation |",
        "|---:|---|---|---|---|---|---|",
    ]
    for task in tasks:
        lines.append(
            f"| {task['rank']} | `{task['candidate_id']}` | {task['target']} | `{task['functional_theme']}` | {task['task_kind']} | `{task['repro_signature']}` | {short(task['safe_observation'], 120)} |"
        )
    lines.extend(["", "## Task Details", ""])
    for task in tasks:
        lines.extend(
            [
                f"### {task['rank']}. {task['candidate_id']} -- {task['target']} / {task['functional_theme']}",
                "",
                f"- Evidence: `{task['evidence_type']}`; reproduced signature: `{task['repro_signature']}`.",
                f"- Source to sink: `{task['source_function']}` -> `{task['sink']}`; closure `{task['closure_ordinal']}`.",
                f"- Entry clues: `{task['entry_clues']}`.",
                f"- Source/configuration keys: `{task['source_keys']}`.",
                f"- TSDS preview: `{task['tsds_preview']}`.",
                f"- Canary token: `{task['canary_token']}`.",
                f"- Primary validation: {task['primary_validation']}.",
                f"- Fixture strategy: {task['fixture_strategy']}",
                f"- Expected safe observation: {task['safe_observation']}",
                f"- Required artifacts: {task['required_artifacts']}.",
                f"- Boundary: {task['non_goals']}",
                "",
            ]
        )
    lines.extend(
        [
            "## Evidence Boundary",
            "",
            "A completed sink-intercept task can support analyzer-to-emulation consistency, because it shows that the rehosted or harnessed firmware reaches the same command-construction point with the canary token present in the intercepted sink argument. It still should not be reported as a device-confirmed vulnerability unless a separate isolated canary-effect run is performed and documented.",
            "",
        ]
    )
    return "\n".join(lines)


def latex_table(tasks: List[Dict[str, Any]]) -> str:
    lines = [
        "% Auto-generated by experiments/build_canary_validation_plan.py",
        "\\begin{tabularx}{\\textwidth}{@{}lP{0.18\\textwidth}P{0.15\\textwidth}P{0.19\\textwidth}Y@{}}",
        "\\toprule",
        "ID & Target & Theme & Validation mode & Evidence\\\\",
        "\\midrule",
    ]
    for task in tasks:
        evidence = f"{task['repro_signature']}; sink-intercept only"
        lines.append(
            "{} & {} & {} & {} & {}\\\\".format(
                task["candidate_id"],
                task["target"].replace("&", "\\&"),
                task["functional_theme"].replace("_", "\\_"),
                task["task_kind"].replace("&", "\\&"),
                evidence.replace("&", "\\&"),
            )
        )
    lines.extend(["\\bottomrule", "\\end{tabularx}", ""])
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--candidate-csv", default=str(DEFAULT_CANDIDATES))
    parser.add_argument("--repro-csv", default=str(DEFAULT_REPRO))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT))
    parser.add_argument("--ids", nargs="*", default=RECOMMENDED_IDS)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    candidates = {row["candidate_id"]: row for row in load_csv(root / args.candidate_csv)}
    repro = {row["candidate_id"]: row for row in load_csv(root / args.repro_csv)}
    tasks: List[Dict[str, Any]] = []
    for cid in args.ids:
        if cid not in candidates:
            raise KeyError(f"candidate not found: {cid}")
        tasks.append(build_task(candidates[cid], repro.get(cid, {}), len(tasks) + 1))
    out_dir = (root / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "canary_validation_tasks.csv", tasks)
    (out_dir / "canary_validation_tasks.json").write_text(json.dumps(tasks, indent=2), encoding="utf-8")
    (out_dir / "canary_validation_plan.md").write_text(markdown(tasks, len(candidates)), encoding="utf-8")
    (out_dir / "canary_validation_table.tex").write_text(latex_table(tasks), encoding="utf-8")
    summary = {
        "candidate_worklist_size": len(candidates),
        "selected": len(tasks),
        "selected_ids": [task["candidate_id"] for task in tasks],
        "targets": sorted({task["target"] for task in tasks}),
        "themes": [task["functional_theme"] for task in tasks],
        "validation_boundary": "sink-intercept canary plan only; not device-confirmed",
        "out_dir": str(out_dir),
    }
    (out_dir / "canary_validation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
