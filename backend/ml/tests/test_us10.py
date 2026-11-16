"""Acceptance tests of US10: a predicted severity for the CVEs without any CVSS score (FR-06, FR-23, FR-26, UC19)."""

import io
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from django.core.management import call_command
from django.db import connection
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone as django_timezone

from accounts.models import Role
from accounts.tests.test_us01 import make_user
from alerts.priority import factors
from cti.models import (
    AffectedProduct,
    CVSSMetric,
    Product,
    ScoreProvider,
    Vulnerability,
    VulnerabilityWeakness,
    Weakness,
)
from cti.services import refresh_effective_severity
from ml import cvss, m1
from ml.models import MLModel, MLTask, SeverityPrediction
from ml.scoring import score_severity
from pipeline.models import RunStatus
from pipeline.services import ensure_sources, run_pipeline
from pipeline.tests.factories import cve_doc, write_bulk_zip
from pipeline.warehouse import refresh_warehouse

# Each class has its own words, title, product, CWE, CNA and CVSS vector, so that a tiny model learns them
CLASS_FEATURES = {
    "LOW": ("minor information disclosure in the logs", "Notes log disclosure", ("acme", "notes"), "CWE-532",
            "acme", "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),
    "MEDIUM": ("stored cross site scripting in the profile page", "Forms plugin stored XSS", ("wpplugin", "forms"),
               "CWE-79", "wordfence", "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    "HIGH": ("sql injection by an authenticated user", "Store SQL injection", ("shopcart", "store"), "CWE-89",
             "vuldb", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 8.8),
    "CRITICAL": ("unauthenticated remote code execution in the gateway", "FortiOS gateway RCE", ("fortinet", "fortios"),
                 "CWE-78", "fortinet", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
}
DAYS = {"fit": datetime(2023, 1, 1, tzinfo=timezone.utc), "valid": datetime(2024, 9, 1, tzinfo=timezone.utc),
        "test": datetime(2025, 9, 1, tzinfo=timezone.utc)}
TINY = {"min_df": 1, "scorer_words_min_df": 1}  # model options for a few rows


def labelled_cve(cve_id, severity, published, provider=ScoreProvider.CNA, version="3.1"):
    """A CVE whose record looks like the class `severity`, with a CVSS score of that class."""
    words, title, (vendor, name), cwe_id, assigner, vector, score = CLASS_FEATURES[severity]
    vulnerability = Vulnerability.objects.create(
        cve_id=cve_id, description=f"{words} ({cve_id})", title=title, published_at=published, assigner=assigner,
        source_updated_at=published,
    )
    product, _ = Product.objects.get_or_create(vendor=vendor, name=name)
    AffectedProduct.objects.create(vulnerability=vulnerability, product=product)
    weakness, _ = Weakness.objects.get_or_create(cwe_id=cwe_id)
    VulnerabilityWeakness.objects.create(vulnerability=vulnerability, weakness=weakness, provider=ScoreProvider.CNA)
    CVSSMetric.objects.create(vulnerability=vulnerability, provider=provider, version=version, base_score=score,
                              severity=severity, vector=vector)
    return vulnerability


def unscored_cve(cve_id, like, published=datetime(2026, 10, 1, tzinfo=timezone.utc)):
    """A CVE without any CVSS score whose record looks like the class `like`."""
    vulnerability = labelled_cve(cve_id, like, published)
    vulnerability.cvss_metrics.all().delete()
    return vulnerability


def training_set(per_class=10):
    """`per_class` CVEs per class in each period (fit, validation, test): half scored by their CNA,
    half by CISA ADP only."""
    n = 0
    for period, day in DAYS.items():
        for severity in m1.CLASSES:
            for i in range(per_class):
                n += 1
                provider = ScoreProvider.CNA if i % 2 else ScoreProvider.CISA_ADP
                labelled_cve(f"CVE-2023-{n:04d}", severity, day + timedelta(days=i), provider=provider)


def synthetic_frame():
    """6 CVEs per class and period, without the database (tests of ml.m1 alone): 3 scored by their CNA,
    3 by CISA ADP only."""
    rows = []
    for period, day in DAYS.items():
        for severity in m1.CLASSES:
            words, title, (vendor, name), cwe_id, assigner, vector, score = CLASS_FEATURES[severity]
            for i in range(6):
                rows.append({"cve_id": f"CVE-{period}-{severity}-{i}", "description": f"{words} {i}", "title": title,
                             "products": f"{vendor}/{name}", "cwes": cwe_id, "assigner": assigner,
                             "published_at": pd.Timestamp(day + timedelta(days=i)), "label": severity,
                             "label_provider": "CNA" if i < 3 else "CISA_ADP", "scorer": "cna" if i < 3 else "analyst",
                             "vector": vector})
    return m1._clean(pd.DataFrame(rows))


def register_model(folder: Path, version="1", activate=True) -> MLModel:
    """Trains a tiny M1 on synthetic_frame() and registers it, like the train_m1 command."""
    model, metrics = m1.train(synthetic_frame(), log=lambda message: None, **TINY)
    artifact = f"m1_severity_v{version}.joblib"
    joblib.dump(model, folder / artifact)
    registered = MLModel.objects.create(name="m1-severity", task=MLTask.SEVERITY, version=version, algorithm="test",
                                        metrics=metrics, artifact=artifact, trained_at=django_timezone.now())
    if activate:
        registered.activate()
    return registered


class CvssFormulaTests(TestCase):
    """ml.cvss: the official CVSS 3.1 base score formula."""

    def score(self, vector):
        return cvss.base_score(*cvss.parse_vector(vector).values())

    def test_known_vectors(self):
        self.assertEqual(self.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(self.score("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"), 5.4)  # scope changed
        self.assertEqual(self.score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"), 7.8)
        self.assertEqual(self.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(self.score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0.0)  # no impact
        self.assertEqual([cvss.severity(score) for score in (0, 3.9, 4.0, 6.9, 7.0, 8.9, 9.0)],
                         ["NONE", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL"])

    def test_unreadable_vector(self):
        self.assertIsNone(cvss.parse_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P"))  # CVSS 2
        self.assertIsNone(cvss.parse_vector(""))
        self.assertIsNone(cvss.parse_vector(None))

    def test_class_probabilities_of_certain_metrics(self):
        certain = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")  # 8.8 HIGH
        probabilities = {metric: np.array([[float(value == certain[metric]) for value in values]])
                         for metric, values in cvss.METRICS.items()}
        self.assertEqual(cvss.class_probabilities(probabilities, m1.CLASSES).round(6).tolist(), [[0, 0, 1, 0]])


class M1CodeTests(TestCase):
    """ml.m1 without the database: features, time-based split, the two views, metrics."""

    def test_tokens(self):
        self.assertEqual(m1.product_tokens("fortinet/fortios|fortinet/fortiproxy"),
                         ["p=fortinet/fortios", "p=fortinet/fortiproxy", "v=fortinet"])
        self.assertEqual(m1.split_tokens("CWE-79|CWE-89"), ["CWE-79", "CWE-89"])
        self.assertEqual(m1.assigner_tokens("wordfence"), ["cna=wordfence"])
        self.assertEqual(m1.assigner_tokens(""), [])
        self.assertEqual(m1.scorer_tokens("analyst"), ["scorer=analyst"])
        # the words are read through the eyes of who scores: the CNA itself, or an analyst
        self.assertEqual(m1.scorer_words("cna", "wordfence", "Stored XSS, stored"), "wordfence::stored wordfence::xss,")
        self.assertEqual(m1.scorer_words("analyst", "wordfence", "Stored XSS"), "analyst::stored analyst::xss")

    def test_split_is_time_based(self):
        fit, valid, test = m1.split(synthetic_frame(), "2024-07-01", "2025-07-01")
        self.assertEqual((len(fit), len(valid), len(test)), (24, 24, 24))
        self.assertLess(fit.published_at.max(), valid.published_at.min())
        self.assertLess(valid.published_at.max(), test.published_at.min())
        last_day = pd.Timestamp("2026-02-10", tz="UTC")
        self.assertEqual([day.date().isoformat() for day in m1.quarter_starts("2025-07-01", last_day)],
                         ["2025-07-01", "2025-10-01", "2026-01-01"])

    def test_both_views_predict_the_class(self):
        data = synthetic_frame()
        model = m1.SeverityModel(metric_weight=0.7, **TINY).fit(data)
        direct, metrics = model.views(data)
        self.assertEqual(list(m1.to_classes(direct)), list(data.label))
        self.assertEqual(list(m1.to_classes(metrics)), list(data.label))  # 8 base metrics -> CVSS formula -> class
        classes, confidences = model.predict(data.head(1))
        self.assertEqual(classes[0], "LOW")
        self.assertTrue(0.25 < confidences[0] <= 1)
        self.assertEqual(list(m1.combine(direct, metrics, 0)[0]), list(direct[0]))
        direct_only = m1.SeverityModel(["description"], with_metrics=False, **TINY).fit(data)
        self.assertIsNone(direct_only.views(data)[1])

    def test_train_reports_macro_f1_on_the_test_period(self):
        model, metrics = m1.train(synthetic_frame(), log=lambda message: None, **TINY)
        self.assertEqual(metrics["macro_f1"], 1.0)  # each class has its own words
        self.assertEqual(metrics["sizes"], {"fit": 24, "validation": 24, "test": 24, "deployed_fit": 72,
                                            "deployed_fit_rows": 72})
        self.assertEqual(set(metrics["validation_macro_f1_by_metric_weight"]), {"0.0", "0.5", "0.7", "1.0"})
        self.assertEqual(metrics["confusion_matrix"]["classes"], m1.CLASSES)
        self.assertEqual(metrics["reference_text_only"]["macro_f1"], 1.0)
        self.assertEqual(metrics["by_scorer"]["scored by the CNA"], {"cves": 12, "macro_f1": 1.0, "accuracy": 1.0})
        self.assertEqual(metrics["by_scorer"]["not scored by the CNA"]["cves"], 12)
        self.assertEqual([row["share"] for row in metrics["by_confidence"]], [1.0, 0.8, 0.6, 0.4])
        # one quarter in this test period: its model is trained on fit + validation
        quarters = metrics["retrained_each_quarter"]["quarters"]
        self.assertEqual([(q["from"], q["trained_on"], q["cves"]) for q in quarters], [("2025-07-01", 48, 24)])
        self.assertEqual(metrics["retrained_each_quarter"]["macro_f1"], 1.0)
        self.assertEqual(model.predict(synthetic_frame().tail(1))[0][0], "CRITICAL")

    def test_each_quarter_is_predicted_by_a_model_trained_before_it(self):
        data = synthetic_frame()
        later = data[data.published_at >= "2025-07-01"].copy()
        later["published_at"] += pd.Timedelta(days=60)  # a second quarter in the test period
        later["cve_id"] += "-later"
        both = pd.concat([data, later], ignore_index=True)
        quarters = m1.train(both, log=lambda message: None, **TINY)[1]["retrained_each_quarter"]["quarters"]
        self.assertEqual([(q["from"], q["trained_on"], q["cves"]) for q in quarters],
                         [("2025-07-01", 48, 24), ("2025-10-01", 72, 24)])
        self.assertNotIn("retrained_each_quarter", m1.train(both, each_quarter=False, log=lambda m: None, **TINY)[1])

    def test_a_cve_scored_by_both_is_learned_twice_and_evaluated_once(self):
        data = synthetic_frame()
        test_period = data.published_at >= "2025-07-01"
        second = data[test_period & (data.scorer == "cna")].copy()  # the same CVEs, also scored by an analyst
        second["scorer"], second["label_provider"] = "analyst", "NVD"
        both = m1._clean(pd.concat([data, second], ignore_index=True))
        self.assertEqual(int(both.main.sum()), 72)  # main row: the CNA's score when there is one
        self.assertEqual(set(both[~both.main].scorer), {"analyst"})
        metrics = m1.train(both, log=lambda message: None, **TINY)[1]
        self.assertEqual((metrics["sizes"]["test"], metrics["sizes"]["deployed_fit"], metrics["sizes"]["deployed_fit_rows"]),
                         (24, 72, 84))

    def test_errors_one_class_away_are_counted(self):
        metrics = m1.evaluate(["LOW", "HIGH", "CRITICAL"], ["MEDIUM", "LOW", "CRITICAL"])
        self.assertEqual(metrics["accuracy"], 0.333)
        self.assertEqual(metrics["right_or_one_class_away"], 0.667)  # HIGH -> LOW is two classes away

    def test_scores_by_scorer_and_by_confidence(self):
        part = pd.DataFrame({"label": ["LOW", "HIGH", "HIGH", "CRITICAL"], "scorer": ["cna", "cna", "analyst", "analyst"],
                             "label_provider": ["CNA", "CNA", "NVD", "CISA_ADP"]})
        scores = m1.by_scorer(part, ["LOW", "HIGH", "LOW", "CRITICAL"])
        self.assertEqual((scores["scored by the CNA"]["cves"], scores["scored by the CNA"]["accuracy"]), (2, 1.0))
        self.assertEqual((scores["not scored by the CNA"]["cves"], scores["not scored by the CNA"]["accuracy"]), (2, 0.5))
        self.assertEqual(scores["label of the NVD"]["accuracy"], 0.0)
        rows = m1.by_confidence(["LOW", "HIGH", "HIGH", "LOW"], ["LOW", "HIGH", "LOW", "HIGH"], [0.9, 0.8, 0.4, 0.3],
                                shares=(1.0, 0.5))
        self.assertEqual([(row["min_confidence"], row["accuracy"]) for row in rows], [(0.3, 0.5), (0.8, 1.0)])

    def test_an_empty_period_is_refused(self):
        with self.assertRaises(ValueError):
            m1.train(synthetic_frame(), test_from="2030-01-01", log=lambda message: None, **TINY)


class DatasetTests(TestCase):
    """Labels and features read from the operational schema."""

    def test_one_cvss3_label_per_cve_and_scorer(self):
        day = DAYS["fit"]
        both = labelled_cve("CVE-2023-0001", "MEDIUM", day)  # the CNA says MEDIUM, the NVD says HIGH
        CVSSMetric.objects.create(vulnerability=both, provider=ScoreProvider.NVD, version="3.1", base_score=7.5,
                                  severity="HIGH", vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
        adp = labelled_cve("CVE-2023-0002", "HIGH", day, provider=ScoreProvider.CISA_ADP)  # CISA ADP before the NVD
        CVSSMetric.objects.create(vulnerability=adp, provider=ScoreProvider.NVD, version="3.1", base_score=9.8,
                                  severity="CRITICAL")
        labelled_cve("CVE-2023-0003", "CRITICAL", day, provider=ScoreProvider.NVD)  # scored by the NVD only
        labelled_cve("CVE-2023-0004", "LOW", day, version="4.0")  # no CVSS 3.x: not labelled
        labelled_cve("CVE-2017-0005", "LOW", datetime(2017, 6, 1, tzinfo=timezone.utc))  # before SINCE
        none = labelled_cve("CVE-2023-0006", "LOW", day)
        none.cvss_metrics.update(severity="NONE", base_score=0)
        data = m1.load_labelled(connection).sort_values(["cve_id", "scorer"])
        rows = list(zip(data.cve_id, data.scorer, data.label, data.label_provider, data.main))
        self.assertEqual(rows, [
            ("CVE-2023-0001", "analyst", "HIGH", "NVD", False),   # second training row of this CVE
            ("CVE-2023-0001", "cna", "MEDIUM", "CNA", True),      # evaluation row: the CNA's score
            ("CVE-2023-0002", "analyst", "HIGH", "CISA_ADP", True),
            ("CVE-2023-0003", "analyst", "CRITICAL", "NVD", True),
        ])
        # base metrics of the vector that goes with each label
        cna_row = data[(data.cve_id == "CVE-2023-0001") & (data.scorer == "cna")].iloc[0]
        self.assertEqual((cna_row.AV, cna_row.PR, cna_row.UI, cna_row.S, cna_row.C), ("N", "L", "R", "C", "L"))
        self.assertIn("wordfence::stored", cna_row.scorer_words)
        nvd_row = data[(data.cve_id == "CVE-2023-0001") & (data.scorer == "analyst")].iloc[0]
        self.assertEqual((nvd_row.PR, nvd_row.S, nvd_row.C), ("N", "U", "H"))
        self.assertIn("analyst::stored", nvd_row.scorer_words)

    def test_features_come_from_the_cna_record_and_ask_for_the_analyst_score(self):
        vulnerability = unscored_cve("CVE-2026-0001", "CRITICAL")
        weakness = Weakness.objects.create(cwe_id="CWE-20")
        VulnerabilityWeakness.objects.create(vulnerability=vulnerability, weakness=weakness, provider=ScoreProvider.NVD)
        row = m1.load_features(connection, [vulnerability.pk]).iloc[0]
        self.assertEqual((row.title, row.products, row.cwes, row.assigner),
                         ("FortiOS gateway RCE", "fortinet/fortios", "CWE-78", "fortinet"))  # not the NVD's CWE-20
        self.assertEqual(row.scorer, "analyst")
        self.assertIn("analyst::unauthenticated", row.scorer_words)

    def test_agreement_between_two_providers(self):
        day = DAYS["fit"]
        for number, nvd_severity in enumerate(["MEDIUM", "HIGH", "HIGH", "HIGH"]):  # the CNA says MEDIUM each time
            vulnerability = labelled_cve(f"CVE-2023-01{number:02d}", "MEDIUM", day)
            CVSSMetric.objects.create(vulnerability=vulnerability, provider=ScoreProvider.NVD, version="3.1",
                                      base_score=7.5, severity=nvd_severity)
        table = m1.agreement(connection)
        self.assertEqual(len(table), 1)  # nothing in the test period
        row = table.iloc[0]
        self.assertEqual((row.providers, row.cves, row.same_class), ("CNA vs NVD", 4, 0.25))


class ModelVersionTests(TestCase):
    def test_one_active_version_per_task(self):
        folder = Path(tempfile.mkdtemp())
        first = register_model(folder, "1")
        second = register_model(folder, "2")
        first.refresh_from_db()
        self.assertEqual((first.is_active, second.is_active), (False, True))
        first.activate()
        second.refresh_from_db()
        self.assertEqual(list(MLModel.objects.filter(is_active=True)), [first])


class TrainCommandTests(TestCase):
    def test_train_m1_registers_a_new_active_version_with_its_metrics(self):
        training_set()  # 10 CVEs per class and period: enough for the default settings
        folder = Path(tempfile.mkdtemp())
        out = io.StringIO()
        with override_settings(ML_MODELS_DIR=folder):
            call_command("train_m1", "--activate", stdout=out)
            call_command("train_m1", "--quick", stdout=io.StringIO())
        model = MLModel.objects.get(version="1")
        self.assertTrue(model.is_active)
        self.assertEqual((model.task, model.name, model.artifact), (MLTask.SEVERITY, "m1-severity", "m1_severity_v1.joblib"))
        self.assertTrue((folder / "m1_severity_v1.joblib").exists())
        saved = json.loads((folder / "m1_severity_v1_metrics.json").read_text())
        self.assertEqual(saved["macro_f1"], model.metrics["macro_f1"])
        self.assertEqual(model.metrics["sizes"]["test"], 40)
        self.assertEqual(model.metrics["retrained_each_quarter"]["quarters"][0]["trained_on"], 80)
        self.assertIn("test macro-F1 1.0 with the strict split, 1.0 retrained each quarter", out.getvalue())
        second = MLModel.objects.get(version="2")
        self.assertFalse(second.is_active)  # a new version is not active by default
        self.assertNotIn("retrained_each_quarter", second.metrics)  # --quick


class ScoringTests(TestCase):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.settings_override = override_settings(ML_MODELS_DIR=self.folder)
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.model = register_model(self.folder)
        self.unscored = unscored_cve("CVE-2026-0001", "CRITICAL")
        self.scored = labelled_cve("CVE-2026-0002", "MEDIUM", datetime(2026, 10, 1, tzinfo=timezone.utc))

    def test_prediction_stores_model_version_and_confidence(self):
        result = score_severity()
        self.assertEqual((result.model, result.scored), (self.model, 1))
        prediction = SeverityPrediction.objects.get()
        self.assertEqual((prediction.vulnerability, prediction.model.version), (self.unscored, "1"))
        self.assertEqual(prediction.predicted_severity, "CRITICAL")
        self.assertTrue(0 < prediction.confidence <= 1)

    def test_scoring_is_incremental(self):
        score_severity()
        self.assertEqual(score_severity().scored, 0)
        Vulnerability.objects.filter(pk=self.unscored.pk).update(source_updated_at=django_timezone.now())
        self.assertEqual(score_severity().scored, 1)  # updated record: predicted again
        self.assertEqual(score_severity(rescore=True).scored, 1)
        self.assertEqual(SeverityPrediction.objects.count(), 1)

    def test_no_active_version_means_no_scoring(self):
        MLModel.objects.update(is_active=False)
        self.assertIsNone(score_severity())

    def test_effective_severity_falls_back_on_the_active_prediction(self):
        score_severity()
        refresh_effective_severity()
        self.unscored.refresh_from_db()
        self.scored.refresh_from_db()
        self.assertEqual((self.unscored.effective_severity, self.unscored.effective_score,
                          self.unscored.is_severity_predicted), ("CRITICAL", None, True))
        self.assertEqual((self.scored.effective_severity, self.scored.is_severity_predicted), ("MEDIUM", False))
        # A CVSS score published later wins over the prediction (FR-06)
        CVSSMetric.objects.create(vulnerability=self.unscored, provider=ScoreProvider.CNA, version="3.1",
                                  base_score=8.8, severity="HIGH")
        refresh_effective_severity()
        self.unscored.refresh_from_db()
        self.assertEqual((self.unscored.effective_severity, self.unscored.effective_score,
                          self.unscored.is_severity_predicted), ("HIGH", 8.8, False))

    def test_deactivated_model_is_not_used(self):
        score_severity()
        refresh_effective_severity()
        MLModel.objects.update(is_active=False)
        refresh_effective_severity()
        self.unscored.refresh_from_db()
        self.assertEqual((self.unscored.effective_severity, self.unscored.is_severity_predicted), ("", False))

    @override_settings(PRIORITY_PREDICTED_SEVERITY={"LOW": 0.2, "MEDIUM": 0.55, "HIGH": 0.8, "CRITICAL": 0.95})
    def test_priority_uses_the_middle_of_the_predicted_class(self):
        score_severity()
        refresh_effective_severity()
        self.unscored.refresh_from_db()
        severity = factors(self.unscored, 4)[0]
        self.assertEqual((severity.value, severity.shown), (0.95, "CRITICAL predicted by M1 (middle of the class)"))

    def test_score_m1_command(self):
        out = io.StringIO()
        call_command("score_m1", stdout=out)
        self.assertIn("severity predicted for 1 CVEs", out.getvalue())
        self.assertTrue(Vulnerability.objects.get(pk=self.unscored.pk).is_severity_predicted)

    def test_warehouse_flags_the_predicted_severity(self):
        score_severity()
        refresh_effective_severity()
        ensure_sources()
        refresh_warehouse()
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT v.cve_id, s.label, f.cvss_score, f.is_severity_predicted
                FROM dw.fact_vulnerability f
                JOIN dw.dim_vulnerability v USING (vuln_key)
                JOIN dw.dim_severity s USING (severity_key)
                ORDER BY v.cve_id
            """)
            rows = cursor.fetchall()
        self.assertEqual(rows, [("CVE-2026-0001", "CRITICAL", None, True), ("CVE-2026-0002", "MEDIUM", 5.4, False)])


class PipelineScoringTests(TestCase):
    """UC19 runs after the loading and before the effective severity, the alerts and the warehouse."""

    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.settings_override = override_settings(ML_MODELS_DIR=self.folder, STAGING_DIR=tempfile.mkdtemp())
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        self.bulk = write_bulk_zip(self.folder / "all_CVEs_at_midnight.zip", [
            cve_doc("CVE-2026-0101", cna_score=None, description="unauthenticated remote code execution in the gateway",
                    affected=(("Fortinet", "FortiOS", "7.2"),), cna_cwes=("CWE-78",)),
        ])

    def run_cve(self):
        out = io.StringIO()
        run = run_pipeline(sources=["cve"], local_file=str(self.bulk), stdout=out)
        return run, out.getvalue()

    def test_new_cve_without_score_gets_a_predicted_severity(self):
        register_model(self.folder)
        run, output = self.run_cve()
        self.assertEqual(run.status, RunStatus.SUCCESS)
        self.assertIn("scoring: m1-severity v1 predicted the severity of 1 CVEs without CVSS score", output)
        vulnerability = Vulnerability.objects.get(cve_id="CVE-2026-0101")
        self.assertEqual((vulnerability.effective_severity, vulnerability.is_severity_predicted), ("CRITICAL", True))

    def test_without_active_model_the_step_is_skipped(self):
        run, output = self.run_cve()
        self.assertEqual(run.status, RunStatus.SUCCESS)
        self.assertIn("scoring: no active M1 version, skipped", output)

    def test_missing_model_file_makes_the_run_partial(self):
        model = register_model(self.folder)
        (self.folder / model.artifact).unlink()
        run, output = self.run_cve()
        self.assertEqual(run.status, RunStatus.PARTIAL)
        self.assertIn("scoring: FAILED - FileNotFoundError", output)
        self.assertTrue(Vulnerability.objects.filter(cve_id="CVE-2026-0101").exists())  # loaded data kept


class ConsoleTests(TestCase):
    """FR-06 / US04: a predicted severity is labeled as predicted, with the model version and the confidence."""

    def setUp(self):
        folder = Path(tempfile.mkdtemp())
        self.settings_override = override_settings(ML_MODELS_DIR=folder)
        self.settings_override.enable()
        self.addCleanup(self.settings_override.disable)
        register_model(folder)
        unscored_cve("CVE-2026-0001", "HIGH")
        score_severity()
        refresh_effective_severity()
        self.client.force_login(make_user("analyst", Role.ANALYST))

    def test_record_shows_the_prediction(self):
        response = self.client.get(reverse("cti:detail", args=["CVE-2026-0001"]))
        page = response.content.decode()
        prediction = SeverityPrediction.objects.get()
        self.assertIn("High · predicted", page)
        self.assertIn("predicted by m1-severity v1", page)
        self.assertIn(f"confidence {round(prediction.confidence * 100)} %", page)
        self.assertEqual(response.context["prediction"], prediction)

    def test_search_labels_the_predicted_severity(self):
        response = self.client.get(reverse("cti:search"), {"severity": "HIGH"})
        self.assertContains(response, "High · predicted")
        # "No CVSS score yet" still lists it: the prediction is not a CVSS score
        response = self.client.get(reverse("cti:search"), {"severity": "UNSCORED"})
        self.assertContains(response, "CVE-2026-0001")
