"""Model M1 (FR-23): CVSS severity class of a CVE, for the CVEs that have no CVSS score.

Plain pandas / scikit-learn code without Django, shared by the commands (train_m1, score_m1, with the
Django database connection) and the notebook ml/notebooks/m1_final.ipynb (with a psycopg connection).

Labels: CVSS 3.x scores only (a single CVSS version, FR-23), 3.1 before 3.0. Two kinds of scorers do not
score alike (the NVD gives another class than the CNA for about half of the CVEs they both score, see the
notebook), so M1 learns both and is told which one to imitate:
  scorer "cna"      the CNA scored its own CVE
  scorer "analyst"  an independent analyst scored it: CISA ADP, else the NVD
A CVE scored by both gives two training rows. A CVE without any score has no CNA score, so M1 predicts
the score an analyst would give. The class NONE (score 0) is too rare to learn and is left out.

Features: what the CNA publishes in the CVE record, so they also exist for a CVE without any score.
  description   TF-IDF of words and pairs of words
  title         TF-IDF of the title of the record (often the product and the kind of vulnerability)
  products      affected vendors and products: "v=fortinet", "p=fortinet/fortios"
  cwes          CWE identifiers given by the CNA: "CWE-79"
  assigner      the CNA that published the record: "cna=wordfence"
  scorer        "scorer=cna" or "scorer=analyst"
  scorer_words  words of the description prefixed by who scores: the CNA itself ("wordfence::unauthenticated")
                or "analyst::unauthenticated". Each scorer has its own way of reading the same words

Method: TF-IDF + logistic regression (FR-23), two views of the same features combined:
  direct   one classifier for the severity class
  metrics  one classifier per CVSS base metric (AV, AC, PR, UI, S, C, I, A); the official CVSS formula
           (ml/cvss.py) turns their probabilities into the probability of each class

Evaluation: one row per CVE, the score of its CNA when there is one, else the analyst's.
"""

from __future__ import annotations

import os
import time
from datetime import date

import numpy as np
import pandas as pd
from joblib import Parallel, delayed
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import CountVectorizer, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix, f1_score

from . import cvss

CLASSES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]  # ordered: an error of one class is less serious
FEATURES = ["description", "title", "products", "cwes", "assigner", "scorer", "scorer_words"]
FEATURE_SETS = {  # compared in the notebook, on the validation period (direct view only)
    "text only": ["description"],
    "text + products": ["description", "products"],
    "text + products + CWE + CNA": ["description", "products", "cwes", "assigner"],
    "text + products + CWE + CNA + title": ["description", "products", "cwes", "assigner", "title"],
    "text + products + CWE + CNA + title + scorer and its words": FEATURES,
}
ANALYST = "analyst"  # scorer of a CVE that its CNA did not score: CISA ADP, else the NVD

# Default periods: the test period is the one of the Sprint 1 baseline (m1_baseline.ipynb)
SINCE = "2018-01-01"  # earlier records have less reliable dates (risk R3)
VALID_FROM = "2024-07-01"
TEST_FROM = "2025-07-01"
REGULARIZATION = 2.0  # C of the logistic regressions (chosen on the validation period: 0.5, 1, 2, 4 tried)
METRIC_WEIGHTS = [0.0, 0.5, 0.7, 1.0]  # share of the metrics view tried on the validation period (0 = direct only)
MIN_DF = 3  # a word, product, CWE or CNA must appear in at least MIN_DF CVEs of the training data
SCORER_WORDS_MIN_DF = 10  # same rule for a (scorer, word) pair
TOLERANCE = 1e-3  # stopping tolerance of the solver: 3 times faster than the default, same scores
JOBS = min(4, os.cpu_count() or 1)  # the 9 logistic regressions of a model are fitted in parallel threads
RANDOM_STATE = 42
TARGET_MACRO_F1 = 0.70  # indicative target of FR-23

# One row per CVE with its features. {where} is replaced by a condition on the CVE (alias v).
FEATURES_SQL = """
SELECT v.id, v.cve_id, v.published_at, v.description, v.title, v.assigner,
       COALESCE((SELECT string_agg(DISTINCT p.vendor || '/' || p.name, '|')
                 FROM cti_affectedproduct a JOIN cti_product p ON p.id = a.product_id
                 WHERE a.vulnerability_id = v.id), '') AS products,
       COALESCE((SELECT string_agg(DISTINCT w.cwe_id, '|')
                 FROM cti_vulnerabilityweakness vw JOIN cti_weakness w ON w.id = vw.weakness_id
                 WHERE vw.vulnerability_id = v.id AND vw.provider = 'CNA'), '') AS cwes
       {label_columns}
FROM cti_vulnerability v
{label_join}
WHERE {where}
"""

# One CVSS 3.x score per CVE and scorer: the CNA's, and the analyst's (CISA ADP, else the NVD)
LABEL_JOIN = """
JOIN (
    SELECT DISTINCT ON (vulnerability_id, scorer) vulnerability_id, scorer, severity, provider, vector
    FROM (
        SELECT vulnerability_id, severity, provider, vector, version,
               CASE WHEN provider = 'CNA' THEN 'cna' ELSE 'analyst' END AS scorer
        FROM cti_cvssmetric
        WHERE version IN ('3.0', '3.1')
    ) AS scores
    ORDER BY vulnerability_id, scorer, CASE provider WHEN 'NVD' THEN 1 ELSE 0 END, version DESC
) AS label ON label.vulnerability_id = v.id
"""

# CVEs scored with CVSS 3.x by two providers, counted by pair of classes (notebook: do the providers agree?)
AGREEMENT_SQL = """
WITH score AS (
    SELECT DISTINCT ON (vulnerability_id, provider) vulnerability_id, provider, severity
    FROM cti_cvssmetric
    WHERE version IN ('3.0', '3.1')
    ORDER BY vulnerability_id, provider, version DESC
)
SELECT a.provider AS provider_a, b.provider AS provider_b, a.severity AS severity_a, b.severity AS severity_b,
       (v.published_at >= %s) AS in_test_period, count(*) AS cves
FROM score a
JOIN score b ON b.vulnerability_id = a.vulnerability_id AND a.provider < b.provider
JOIN cti_vulnerability v ON v.id = a.vulnerability_id
WHERE v.published_at >= %s AND a.severity <> 'NONE' AND b.severity <> 'NONE'
GROUP BY 1, 2, 3, 4, 5
"""


# ---- data -------------------------------------------------------------------------
def query(connection, sql: str, params=None) -> pd.DataFrame:
    """Runs a SELECT on a DB-API connection (Django's or psycopg's) and returns a DataFrame."""
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        columns = [column[0] for column in cursor.description]
        return pd.DataFrame(cursor.fetchall(), columns=columns)


def scorer_words(scorer: str, assigner: str, description: str) -> str:
    """('cna', 'wordfence', 'Stored XSS in ...') -> 'wordfence::in wordfence::stored wordfence::xss ...';
    with the scorer 'analyst': 'analyst::in analyst::stored analyst::xss ...'."""
    prefix = assigner if scorer == "cna" else ANALYST
    if not prefix:
        return ""
    return " ".join(sorted({f"{prefix}::{word}" for word in description.lower().split()}))


def _clean(data: pd.DataFrame) -> pd.DataFrame:
    for column in ("description", "title", "products", "cwes", "assigner"):
        data[column] = data[column].fillna("")
    data["published_at"] = pd.to_datetime(data["published_at"], utc=True)
    if "scorer" not in data:  # CVEs to predict: no score at all, so the analyst's score is asked for
        data["scorer"] = ANALYST
    data["scorer_words"] = [
        scorer_words(s, a, d) for s, a, d in zip(data["scorer"], data["assigner"], data["description"])
    ]
    if "vector" in data:  # labelled data: one column per CVSS base metric, empty when the vector is unreadable
        parsed = [cvss.parse_vector(vector) for vector in data["vector"]]
        for metric in cvss.METRICS:
            data[metric] = [values[metric] if values else None for values in parsed]
        # Evaluation row of each CVE: the score of its CNA when there is one, else the analyst's
        by_cna = set(data.loc[data["scorer"] == "cna", "cve_id"])
        data["main"] = (data["scorer"] == "cna") | ~data["cve_id"].isin(by_cna)
    return data


def load_labelled(connection, since: str = SINCE) -> pd.DataFrame:
    """CVEs with a CVSS 3.x score, published since `since`, one row per CVE and scorer:
    features, label, label_provider, scorer, base metrics and main (evaluation row of the CVE)."""
    sql = FEATURES_SQL.format(
        label_columns=", label.severity AS label, label.provider AS label_provider, label.scorer AS scorer,"
                      " label.vector AS vector",
        label_join=LABEL_JOIN,
        where="label.severity <> 'NONE' AND v.published_at >= %s",
    )
    return _clean(query(connection, sql, [since])).sort_values("published_at", kind="stable").reset_index(drop=True)


def load_features(connection, vulnerability_ids: list[int]) -> pd.DataFrame:
    """Features of the given CVEs (no label, scorer = analyst): used for scoring."""
    sql = FEATURES_SQL.format(label_columns="", label_join="", where="v.id = ANY(%s)")
    return _clean(query(connection, sql, [list(vulnerability_ids)]))


def split(data: pd.DataFrame, valid_from: str = VALID_FROM, test_from: str = TEST_FROM):
    """Time-based split (never random): fit < valid_from <= validation < test_from <= test."""
    valid_start, test_start = pd.Timestamp(valid_from, tz="UTC"), pd.Timestamp(test_from, tz="UTC")
    fit = data[data.published_at < valid_start]
    valid = data[(data.published_at >= valid_start) & (data.published_at < test_start)]
    test = data[data.published_at >= test_start]
    return fit, valid, test


def quarter_starts(test_from: str, last_day: pd.Timestamp) -> list[pd.Timestamp]:
    """Start of each period of 3 months, from test_from to the last publication date."""
    starts, start = [], pd.Timestamp(test_from, tz="UTC")
    while start <= last_day:
        starts.append(start)
        start = start + pd.DateOffset(months=3)
    return starts


def agreement(connection, since: str = SINCE, test_from: str = TEST_FROM) -> pd.DataFrame:
    """When two providers score the same CVE with CVSS 3.x: share of CVEs with the same class,
    and macro-F1 of the first provider read as a prediction of the second."""
    counts = query(connection, AGREEMENT_SQL, [test_from, since])
    rows = []
    for period, part in ((f"since {since}", counts), (f"since {test_from} (test period)", counts[counts.in_test_period])):
        for (first, second), pair in part.groupby(["provider_a", "provider_b"]):
            repeat = pair.cves.to_numpy().astype(int)
            answer, truth = np.repeat(pair.severity_a.to_numpy(), repeat), np.repeat(pair.severity_b.to_numpy(), repeat)
            rows.append({"period": period, "providers": f"{first} vs {second}", "cves": len(truth),
                         "same_class": round(float((truth == answer).mean()), 3), "macro_f1": macro_f1(truth, answer)})
    return pd.DataFrame(rows)


# ---- model ------------------------------------------------------------------------
def split_tokens(value: str) -> list[str]:
    """'CWE-79|CWE-89' -> ['CWE-79', 'CWE-89']."""
    return [token for token in value.split("|") if token]


def product_tokens(value: str) -> list[str]:
    """'fortinet/fortios|fortinet/fortiproxy' -> vendor and product tokens."""
    tokens = set()
    for item in split_tokens(value):
        tokens.add("v=" + item.split("/", 1)[0])
        tokens.add("p=" + item)
    return sorted(tokens)


def assigner_tokens(value: str) -> list[str]:
    return ["cna=" + value] if value else []


def scorer_tokens(value: str) -> list[str]:
    return ["scorer=" + value]


def space_tokens(value: str) -> list[str]:
    return value.split()


def combine(direct: np.ndarray, metrics: np.ndarray | None, weight: float) -> np.ndarray:
    """P(class) from the two views: weighted geometric mean (weight = share of the metrics view)."""
    if metrics is None or weight == 0:
        return direct
    log_p = weight * np.log(metrics + 1e-9) + (1 - weight) * np.log(direct + 1e-9)
    p = np.exp(log_p - log_p.max(axis=1, keepdims=True))
    return p / p.sum(axis=1, keepdims=True)


def to_classes(probabilities: np.ndarray) -> np.ndarray:
    return np.array(CLASSES)[probabilities.argmax(axis=1)]


class SeverityModel:
    """M1: TF-IDF features, a logistic regression for the severity class and one per CVSS base metric.

    metric_weight: share of the metrics view in the final probabilities (0 = direct view only).
    with_metrics=False trains the direct view only (quick comparison of feature sets).
    """

    def __init__(self, features=FEATURES, metric_weight: float = 0.7, with_metrics: bool = True,
                 min_df: int = MIN_DF, scorer_words_min_df: int = SCORER_WORDS_MIN_DF):
        self.features, self.metric_weight, self.with_metrics = list(features), metric_weight, with_metrics
        self.min_df, self.scorer_words_min_df = min_df, scorer_words_min_df

    def _vectorizers(self) -> dict:
        def tokens(tokenizer):
            return CountVectorizer(
                tokenizer=tokenizer, token_pattern=None, lowercase=False, binary=True, min_df=self.min_df
            )

        def text(max_features):
            return TfidfVectorizer(ngram_range=(1, 2), min_df=self.min_df, max_features=max_features,
                                   sublinear_tf=True, strip_accents="unicode")

        return {
            "description": text(200_000),
            "title": text(100_000),
            "products": tokens(product_tokens),
            "cwes": tokens(split_tokens),
            "assigner": tokens(assigner_tokens),
            "scorer": CountVectorizer(tokenizer=scorer_tokens, token_pattern=None, lowercase=False, binary=True),
            "scorer_words": TfidfVectorizer(tokenizer=space_tokens, token_pattern=None, lowercase=False,
                                            min_df=self.scorer_words_min_df, sublinear_tf=True),
        }

    @staticmethod
    def _regression(**options) -> LogisticRegression:
        return LogisticRegression(C=REGULARIZATION, max_iter=2000, tol=TOLERANCE, random_state=RANDOM_STATE, **options)

    def fit(self, data: pd.DataFrame) -> "SeverityModel":
        vectorizers = self._vectorizers()
        self.vectorizer = ColumnTransformer([(name, vectorizers[name], name) for name in self.features])
        X = self.vectorizer.fit_transform(data)
        # balanced: the rare classes (LOW, CRITICAL) weigh as much as the others, as in the macro-F1
        fits = {"direct": delayed(self._regression(class_weight="balanced").fit)(X, data["label"])}
        constant = {}
        if self.with_metrics:
            known = data["AV"].notna().to_numpy()  # rows with a readable CVSS vector
            X_known = X[known]
            for metric in cvss.METRICS:
                values = data.loc[known, metric]
                if values.nunique() == 1:  # a metric with a single value in the training data needs no model
                    constant[metric] = values.iloc[0]
                else:
                    fits[metric] = delayed(self._regression().fit)(X_known, values)
        fitted = dict(zip(fits, Parallel(n_jobs=JOBS, prefer="threads")(fits.values())))
        self.direct = fitted.pop("direct")
        self.metric_models = {metric: fitted.get(metric, constant.get(metric)) for metric in cvss.METRICS}
        if not self.with_metrics:
            self.metric_models = {}
        return self

    def views(self, data: pd.DataFrame) -> tuple[np.ndarray, np.ndarray | None]:
        """P(class) of each view, columns in the order of CLASSES: (direct, metrics or None)."""
        X = self.vectorizer.transform(data)
        direct = np.zeros((X.shape[0], len(CLASSES)))
        direct[:, [CLASSES.index(name) for name in self.direct.classes_]] = self.direct.predict_proba(X)
        if not self.metric_models:
            return direct, None
        by_metric = {}
        for metric, values in cvss.METRICS.items():
            model = self.metric_models[metric]
            by_metric[metric] = np.zeros((X.shape[0], len(values)))
            if isinstance(model, str):
                by_metric[metric][:, values.index(model)] = 1.0
            else:
                by_metric[metric][:, [values.index(value) for value in model.classes_]] = model.predict_proba(X)
        return direct, cvss.class_probabilities(by_metric, CLASSES)

    def predict_proba(self, data: pd.DataFrame) -> np.ndarray:
        return combine(*self.views(data), self.metric_weight)

    def predict(self, data: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
        """Predicted class and its probability (confidence) for each row."""
        probabilities = self.predict_proba(data)
        return to_classes(probabilities), probabilities.max(axis=1)


# ---- evaluation -------------------------------------------------------------------
def macro_f1(truth, predicted) -> float:
    return round(float(f1_score(truth, predicted, labels=CLASSES, average="macro", zero_division=0)), 3)


def evaluate(truth, predicted) -> dict:
    """macro-F1 (FR-23), accuracy, F1 by class, share right or one class away, confusion matrix."""
    truth, predicted = np.asarray(truth), np.asarray(predicted)
    order = {name: i for i, name in enumerate(CLASSES)}
    distance = np.abs(np.vectorize(order.get)(truth) - np.vectorize(order.get)(predicted))
    by_class = f1_score(truth, predicted, labels=CLASSES, average=None, zero_division=0)
    return {
        "macro_f1": macro_f1(truth, predicted),
        "accuracy": round(float((truth == predicted).mean()), 3),
        "right_or_one_class_away": round(float((distance <= 1).mean()), 3),
        "f1_by_class": {name: round(float(score), 3) for name, score in zip(CLASSES, by_class)},
        "confusion_matrix": {  # rows = true class, columns = predicted class, in the order of CLASSES
            "classes": CLASSES,
            "counts": confusion_matrix(truth, predicted, labels=CLASSES).tolist(),
        },
    }


def by_scorer(part: pd.DataFrame, predicted) -> dict:
    """Scores by origin of the label. "not scored by the CNA" are the CVEs that look like those M1 predicts."""
    truth, predicted = part.label.to_numpy(), np.asarray(predicted)
    groups = {
        "scored by the CNA": (part.scorer == "cna").to_numpy(),
        "not scored by the CNA": (part.scorer == ANALYST).to_numpy(),
        "label of CISA ADP": (part.label_provider == "CISA_ADP").to_numpy(),
        "label of the NVD": (part.label_provider == "NVD").to_numpy(),
    }
    return {
        name: {"cves": int(mask.sum()), "macro_f1": macro_f1(truth[mask], predicted[mask]),
               "accuracy": round(float((truth[mask] == predicted[mask]).mean()), 3)}
        for name, mask in groups.items() if mask.any()
    }


def by_confidence(truth, predicted, confidences, shares=(1.0, 0.8, 0.6, 0.4)) -> list[dict]:
    """Scores of the most confident predictions: is the confidence shown to the analyst useful?"""
    truth, predicted, confidences = np.asarray(truth), np.asarray(predicted), np.asarray(confidences)
    order = np.argsort(-confidences)
    rows = []
    for share in shares:
        kept = order[: max(1, int(len(order) * share))]
        rows.append({
            "share": share, "min_confidence": round(float(confidences[kept[-1]]), 2),
            "macro_f1": macro_f1(truth[kept], predicted[kept]),
            "accuracy": round(float((truth[kept] == predicted[kept]).mean()), 3),
        })
    return rows


# ---- training ---------------------------------------------------------------------
def train(data: pd.DataFrame, *, valid_from: str = VALID_FROM, test_from: str = TEST_FROM,
          weights=METRIC_WEIGHTS, each_quarter: bool = True, log=print, **model_options) -> tuple[SeverityModel, dict]:
    """Chooses the settings on the validation period, evaluates on the test period, then refits on all the data.

    Models learn from every row (both scorers); they are evaluated on the main row of each CVE.
    The test period is measured in two ways:
      strict split            one model trained before the test period predicts all of it (never retrained)
      retrained each quarter  each period of 3 months is predicted by a model trained on the CVEs published
                              before it (skipped with each_quarter=False)
    Returns the model to deploy (refit on every labelled CVE, same settings) and its metrics.
    """
    started = time.monotonic()

    def step(message: str) -> None:
        log(f"[{(time.monotonic() - started) / 60:4.1f} min] {message}")

    fit, valid, test = split(data, valid_from, test_from)
    valid, test = valid[valid.main], test[test.main]  # one row per CVE
    if min(len(fit), len(valid), len(test)) == 0:
        raise ValueError(f"Empty period: fit {len(fit)}, validation {len(valid)}, test {len(test)} labelled CVEs")
    step(f"labelled CVEs: fit {fit.cve_id.nunique():,}, validation {len(valid):,}, test {len(test):,}")

    # 1. Share of the metrics view, chosen on the validation period
    direct, metrics = SeverityModel(**model_options).fit(fit).views(valid)
    validation = {weight: macro_f1(valid.label, to_classes(combine(direct, metrics, weight))) for weight in weights}
    best = max(validation, key=validation.get)
    step(f"validation macro-F1 by share of the metrics view: {validation} -> {best}")

    # 2. Test period
    starts = quarter_starts(test_from, data.published_at.max())
    quarters, retrained = [], []
    for number, start in enumerate(starts if each_quarter else starts[:1]):
        in_quarter = (test.published_at >= start).to_numpy()
        if number + 1 < len(starts):
            in_quarter = in_quarter & (test.published_at < starts[number + 1]).to_numpy()
        part = test[in_quarter]
        if number > 0 and part.empty:
            continue
        before = data[data.published_at < start]
        model = SeverityModel(metric_weight=best, **model_options).fit(before)
        if number == 0:  # strict split: the model trained before the test period predicts all of it
            strict_classes, strict_confidences = model.predict(test)
            strict = evaluate(test.label, strict_classes)
            step(f"test, strict split (trained before {test_from}): macro-F1 {strict['macro_f1']}")
            text_only = SeverityModel(["description"], with_metrics=False, **model_options).fit(before[before.main])
            reference = evaluate(test.label, text_only.predict(test)[0])
            step(f"test, reference (description only, same split): macro-F1 {reference['macro_f1']}")
            if part.empty:
                continue
            classes = strict_classes[in_quarter]
        else:
            classes = model.predict(part)[0]
        quarters.append({"from": start.date().isoformat(), "trained_on": int(before.cve_id.nunique()),
                         "cves": len(part), "macro_f1": macro_f1(part.label, classes),
                         "accuracy": round(float((part.label.to_numpy() == classes).mean()), 3)})
        retrained.append(pd.DataFrame({"label": part.label.to_numpy(), "predicted": classes}))
        if each_quarter:
            step(f"test, quarter from {quarters[-1]['from']} (trained on {quarters[-1]['trained_on']:,} CVEs): "
                 f"macro-F1 {quarters[-1]['macro_f1']}")

    if each_quarter:
        retrained = pd.concat(retrained)
        all_quarters = evaluate(retrained.label, retrained.predicted)
        step(f"test, retrained each quarter: macro-F1 {all_quarters['macro_f1']}")

    # 3. Model put in production: same settings, refit on every labelled CVE
    deployed = SeverityModel(metric_weight=best, **model_options).fit(data)
    step(f"final model fitted on {data.cve_id.nunique():,} CVEs")
    first_day, last_day = data.published_at.min().date().isoformat(), data.published_at.max().date().isoformat()
    result = {
        **strict,  # headline numbers: strict split
        "target_macro_f1": TARGET_MACRO_F1,
        "meets_target": strict["macro_f1"] >= TARGET_MACRO_F1,
        "reference_text_only": {key: reference[key] for key in ("macro_f1", "accuracy", "right_or_one_class_away")},
        "by_scorer": by_scorer(test, strict_classes),
        "by_confidence": by_confidence(test.label, strict_classes, strict_confidences),
        "features": list(FEATURES),
        "C": REGULARIZATION,
        "metric_weight": best,
        "validation_macro_f1_by_metric_weight": {str(weight): score for weight, score in validation.items()},
        "label": "CVSS 3.x severity of the CNA, else of CISA ADP, else of the NVD",
        "periods": {
            "fit": f"{first_day} to {valid_from}",
            "validation": f"{valid_from} to {test_from}",
            "test": f"{test_from} to {last_day}",
            "deployed_fit": f"{first_day} to {last_day}",
        },
        "sizes": {"fit": int(fit.cve_id.nunique()), "validation": len(valid), "test": len(test),
                  "deployed_fit": int(data.cve_id.nunique()), "deployed_fit_rows": len(data)},
        "trained_on": date.today().isoformat(),
    }
    if each_quarter:
        result["retrained_each_quarter"] = {
            **{key: value for key, value in all_quarters.items() if key != "confusion_matrix"}, "quarters": quarters,
        }
    return deployed, result
