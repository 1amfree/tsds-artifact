"""Deterministic statistical summaries for TSDS validation artifacts.

The functions in this module have no third-party dependency.  They are kept
separate from the experiment CLIs so that an artifact reviewer can recompute
agreement and paired-comparison uncertainty from the serialized observations.
"""

from __future__ import annotations

import math
import random
from collections import Counter
from typing import Any, Callable, Iterable, Sequence


DEFAULT_BOOTSTRAP_SEED = 0x54534453
DEFAULT_BOOTSTRAP_REPLICATES = 10_000


def _round(value: float | None, digits: int = 4) -> float | None:
    return None if value is None else round(float(value), digits)


def percentile(values: Sequence[float], probability: float) -> float:
    """Return a linearly interpolated percentile for an ordered statistic."""

    if not values:
        raise ValueError("percentile requires at least one value")
    if not 0.0 <= probability <= 1.0:
        raise ValueError("probability must be in [0, 1]")
    ordered = sorted(float(value) for value in values)
    position = probability * (len(ordered) - 1)
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def percentile_interval(
    values: Sequence[float], confidence: float = 0.95
) -> list[float] | None:
    if not values:
        return None
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    tail = (1.0 - confidence) / 2.0
    return [
        round(percentile(values, tail), 4),
        round(percentile(values, 1.0 - tail), 4),
    ]


def cohen_kappa_components(
    pairs: Sequence[tuple[str, str]], labels: Sequence[str]
) -> tuple[float | None, float | None, float | None]:
    """Return kappa, observed agreement, and chance agreement."""

    if not pairs:
        return None, None, None
    total = len(pairs)
    observed = sum(left == right for left, right in pairs) / total
    left_counts = Counter(left for left, _ in pairs)
    right_counts = Counter(right for _, right in pairs)
    expected = sum(
        (left_counts[label] / total) * (right_counts[label] / total)
        for label in labels
    )
    if math.isclose(expected, 1.0):
        kappa = 1.0 if math.isclose(observed, 1.0) else None
    else:
        kappa = (observed - expected) / (1.0 - expected)
    return kappa, observed, expected


def agreement_statistics(
    pairs: Iterable[tuple[str, str]],
    labels: Sequence[str],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Compute confusion, label-specific agreement, and a bootstrap kappa CI.

    Resampling is paired and deterministic: each replicate samples annotation
    pairs, preserving the dependence between the two auditors' labels.
    """

    rows = list(pairs)
    label_order = tuple(str(label) for label in labels)
    if bootstrap_replicates < 0:
        raise ValueError("bootstrap_replicates must be non-negative")
    unknown = sorted(
        {value for pair in rows for value in pair if value not in label_order}
    )
    if unknown:
        raise ValueError("labels outside the declared label set: " + ", ".join(unknown))

    matrix = {
        left: {right: 0 for right in label_order}
        for left in label_order
    }
    for left, right in rows:
        matrix[left][right] += 1

    kappa, observed, expected = cohen_kappa_components(rows, label_order)
    per_label: dict[str, dict[str, Any]] = {}
    for label in label_order:
        both = matrix[label][label]
        left_total = sum(matrix[label].values())
        right_total = sum(matrix[left][label] for left in label_order)
        denominator = left_total + right_total
        specific = (2.0 * both / denominator) if denominator else None
        per_label[label] = {
            "auditor_a_count": left_total,
            "auditor_b_count": right_total,
            "joint_count": both,
            "specific_agreement": _round(specific),
        }

    bootstrap_values: list[float] = []
    if rows and bootstrap_replicates:
        rng = random.Random(bootstrap_seed)
        for _ in range(bootstrap_replicates):
            sample = [rows[rng.randrange(len(rows))] for _ in rows]
            value, _, _ = cohen_kappa_components(sample, label_order)
            if value is not None and math.isfinite(value):
                bootstrap_values.append(value)

    return {
        "records": len(rows),
        "cohen_kappa": _round(kappa),
        "cohen_kappa_bootstrap_95": percentile_interval(bootstrap_values),
        "observed_agreement": _round(observed),
        "expected_agreement": _round(expected),
        "bootstrap": {
            "method": "paired_percentile",
            "confidence": 0.95,
            "seed": bootstrap_seed,
            "requested_replicates": bootstrap_replicates,
            "valid_replicates": len(bootstrap_values),
        },
        "confusion_matrix": matrix,
        "per_label": per_label,
    }


def _accuracy(predictions: Sequence[tuple[bool, bool]]) -> float | None:
    if not predictions:
        return None
    return sum(predicted == truth for predicted, truth in predictions) / len(predictions)


def _f1(predictions: Sequence[tuple[bool, bool]]) -> float | None:
    if not predictions:
        return None
    tp = sum(predicted and truth for predicted, truth in predictions)
    fp = sum(predicted and not truth for predicted, truth in predictions)
    fn = sum(not predicted and truth for predicted, truth in predictions)
    denominator = 2 * tp + fp + fn
    return (2 * tp / denominator) if denominator else None


def _paired_metric_delta(
    rows: Sequence[tuple[bool, bool, bool]],
    metric: Callable[[Sequence[tuple[bool, bool]]], float | None],
) -> float | None:
    left = metric([(left_prediction, truth) for left_prediction, _, truth in rows])
    right = metric([(right_prediction, truth) for _, right_prediction, truth in rows])
    if left is None or right is None:
        return None
    return left - right


def paired_bootstrap_differences(
    rows: Iterable[tuple[bool, bool, bool]],
    *,
    bootstrap_replicates: int = DEFAULT_BOOTSTRAP_REPLICATES,
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Estimate paired TSDS-minus-comparator metric differences.

    Each row is ``(tsds_prediction, comparator_prediction, ground_truth)``.
    The confidence intervals supplement, rather than replace, the exact
    McNemar test used by the comparison gate.
    """

    observations = list(rows)
    if bootstrap_replicates < 0:
        raise ValueError("bootstrap_replicates must be non-negative")
    metrics = {"accuracy": _accuracy, "f1": _f1}
    samples: dict[str, list[float]] = {name: [] for name in metrics}
    rng = random.Random(bootstrap_seed)
    if observations:
        for _ in range(bootstrap_replicates):
            sample = [
                observations[rng.randrange(len(observations))]
                for _ in observations
            ]
            for name, metric in metrics.items():
                delta = _paired_metric_delta(sample, metric)
                if delta is not None and math.isfinite(delta):
                    samples[name].append(delta)

    result: dict[str, Any] = {
        "method": "paired_percentile",
        "confidence": 0.95,
        "seed": bootstrap_seed,
        "requested_replicates": bootstrap_replicates,
        "records": len(observations),
        "metrics": {},
    }
    for name, metric in metrics.items():
        point = _paired_metric_delta(observations, metric)
        values = samples[name]
        result["metrics"][name] = {
            "tsds_minus_external": _round(point),
            "bootstrap_95": percentile_interval(values),
            "valid_replicates": len(values),
            "probability_greater_than_zero": (
                _round(sum(value > 0 for value in values) / len(values))
                if values
                else None
            ),
        }
    return result
