"""CVSS 3.x base score computed from the 8 base metrics (formula of the FIRST specification, section 7).

Used by model M1: it predicts each base metric from the CVE record, then this formula gives the score
and so the severity class.
"""

from __future__ import annotations

import itertools
import math

import numpy as np

# Base metric -> possible values. The order of the values is the order of the probability columns.
METRICS = {
    "AV": ["N", "A", "L", "P"],  # attack vector: network, adjacent, local, physical
    "AC": ["L", "H"],  # attack complexity
    "PR": ["N", "L", "H"],  # privileges required
    "UI": ["N", "R"],  # user interaction
    "S": ["U", "C"],  # scope: unchanged, changed
    "C": ["H", "L", "N"],  # confidentiality impact
    "I": ["H", "L", "N"],  # integrity impact
    "A": ["H", "L", "N"],  # availability impact
}
WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR_WEIGHTS = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}  # depends on the scope


def roundup(value: float) -> float:
    """Smallest number with one decimal that is >= value (as defined by the specification)."""
    scaled = round(value * 100000)
    return scaled / 100000.0 if scaled % 10000 == 0 else (math.floor(scaled / 10000) + 1) / 10.0


def base_score(av: str, ac: str, pr: str, ui: str, s: str, c: str, i: str, a: str) -> float:
    cia = WEIGHTS["CIA"]
    iss = 1 - (1 - cia[c]) * (1 - cia[i]) * (1 - cia[a])
    impact = 6.42 * iss if s == "U" else 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    exploitability = 8.22 * WEIGHTS["AV"][av] * WEIGHTS["AC"][ac] * PR_WEIGHTS[s][pr] * WEIGHTS["UI"][ui]
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return roundup(min(total, 10)) if s == "U" else roundup(min(1.08 * total, 10))


def severity(score: float) -> str:
    if score == 0:
        return "NONE"
    return "LOW" if score < 4 else "MEDIUM" if score < 7 else "HIGH" if score < 9 else "CRITICAL"


def parse_vector(vector) -> dict | None:
    """'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> {'AV': 'N', ...}; None when a base metric is missing."""
    try:
        parts = dict(part.split(":", 1) for part in str(vector).split("/")[1:])
        values = {metric: parts[metric] for metric in METRICS}
    except (KeyError, ValueError):
        return None
    return values if all(values[metric] in METRICS[metric] for metric in METRICS) else None


# The 2,592 possible base vectors, with their severity class
_VECTORS = list(itertools.product(*METRICS.values()))
_VECTOR_CLASS = np.array([severity(base_score(*vector)) for vector in _VECTORS])
_VECTOR_INDEX = np.array([[METRICS[m].index(v) for m, v in zip(METRICS, vector)] for vector in _VECTORS])


def class_probabilities(metric_probabilities: dict, classes: list[str], block: int = 4000) -> np.ndarray:
    """P(severity class) for each row, from the probabilities of the values of each base metric.

    metric_probabilities: {metric: array (rows, values) in the order of METRICS[metric]}.
    Every possible vector gets the product of the probabilities of its 8 values (metrics taken as independent);
    the probability of a class is the sum over the vectors whose score falls in that class.
    Rows are processed by blocks to limit memory (rows x 2,592 vectors).
    """
    rows = len(next(iter(metric_probabilities.values())))
    result = np.zeros((rows, len(classes)))
    for start in range(0, rows, block):
        joint = np.ones((min(block, rows - start), len(_VECTORS)))
        for column, metric in enumerate(METRICS):
            joint *= metric_probabilities[metric][start:start + block][:, _VECTOR_INDEX[:, column]]
        for position, name in enumerate(classes):
            result[start:start + block, position] = joint[:, _VECTOR_CLASS == name].sum(axis=1)
    return result / result.sum(axis=1, keepdims=True)
