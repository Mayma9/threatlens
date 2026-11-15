"""Tests of the ThreatFox connector (US05, FR-14): IOCs, malware families, Auth-Key, retries, warehouse."""

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import requests
from django.test import TestCase, override_settings

from cti.models import Indicator, Malware
from pipeline.connectors.threatfox import ThreatFoxConnector, parse_time, platform
from pipeline.models import RunStatus
from pipeline.services import ensure_sources, run_pipeline
from pipeline.warehouse import refresh_warehouse

from .test_warehouse import query


def ioc(ioc_id, value="203.0.113.10:443", *, ioc_type="ip:port", threat_type="botnet_cc", malware="win.cobalt_strike",
        printable="Cobalt Strike", confidence=75, first_seen="2026-11-14 08:29:40 UTC", last_seen=None):
    """One IOC as returned by get_iocs (documentation addresses, never real infrastructure)."""
    return {"id": str(ioc_id), "ioc": value, "threat_type": threat_type, "threat_type_desc": "", "ioc_type": ioc_type,
            "ioc_type_desc": "", "malware": malware, "malware_printable": printable, "malware_alias": None,
            "malware_malpedia": f"https://malpedia.caad.fkie.fraunhofer.de/details/{malware}",
            "confidence_level": confidence, "first_seen": first_seen, "last_seen": last_seen,
            "reference": None, "reporter": "tester", "tags": ["test"]}


def answer(items, status="ok"):
    return {"query_status": status, "data": items}


class ParseTests(TestCase):
    def test_platform_comes_from_the_malpedia_prefix(self):
        self.assertEqual((platform("win.cobalt_strike"), platform("elf.mirai"), platform("apk.hydra"), platform("x.y"),
                          platform("noprefix")), ("Windows", "Linux", "Android", "Other", "Other"))

    def test_threatfox_dates(self):
        self.assertEqual(parse_time("2026-11-14 08:29:40 UTC"), datetime(2026, 11, 14, 8, 29, 40, tzinfo=timezone.utc))
        self.assertIsNone(parse_time("yesterday"))
        self.assertIsNone(parse_time(None))


class ThreatFoxLoadTests(TestCase):
    def setUp(self):
        staging = override_settings(STAGING_DIR=tempfile.mkdtemp())  # one staging folder per test
        staging.enable()
        self.addCleanup(staging.disable)
        self.folder = Path(tempfile.mkdtemp())

    def run_threatfox(self, items, name="threatfox.json"):
        path = self.folder / name
        path.write_text(json.dumps(answer(items)), encoding="utf-8")
        run = run_pipeline(sources=["threatfox"], local_file=str(path))
        return run, run.tasks.get()

    def test_iocs_and_malware_families_are_loaded(self):
        run, task = self.run_threatfox([
            ioc(1),
            ioc(2, "bad.example.com", ioc_type="domain", threat_type="payload_delivery", malware="elf.mirai", printable="Mirai"),
            ioc(3, "a" * 64, ioc_type="sha256_hash", threat_type="payload", malware="unknown", printable="Unknown malware"),
        ])
        self.assertEqual(run.status, RunStatus.SUCCESS)
        self.assertEqual((task.extracted, task.loaded, task.rejected), (3, 3, 0))
        self.assertEqual(task.quality_report["without_malware_family"], 1)
        self.assertEqual(sorted(Malware.objects.values_list("malpedia_id", "name", "category")),
                         [("elf.mirai", "Mirai", "Linux"), ("win.cobalt_strike", "Cobalt Strike", "Windows")])
        cobalt = Indicator.objects.get(threatfox_id=1)
        self.assertEqual((cobalt.value, cobalt.ioc_type, cobalt.threat_type, cobalt.malware.name, cobalt.confidence),
                         ("203.0.113.10:443", "ip:port", "botnet_cc", "Cobalt Strike", 75))
        self.assertEqual(cobalt.first_seen, datetime(2026, 11, 14, 8, 29, 40, tzinfo=timezone.utc))
        self.assertIsNone(Indicator.objects.get(threatfox_id=3).malware)

    def test_invalid_iocs_are_rejected_with_a_reason(self):
        _, task = self.run_threatfox([
            ioc("abc"), ioc(2, ""), ioc(3, threat_type=""), ioc(4, confidence=120), ioc(5, first_seen="yesterday"),
            ioc(6), ioc(6),
        ])
        self.assertEqual((task.loaded, task.rejected), (1, 6))
        self.assertEqual(task.quality_report["rejected_by_reason"], {
            "invalid ThreatFox id": 1, "missing IOC value": 1, "missing IOC type or threat type": 1,
            "confidence outside 0-100": 1, "invalid first_seen date": 1, "duplicate IOC in the file": 1})

    def test_running_again_updates_the_same_ioc(self):
        self.run_threatfox([ioc(1, confidence=50)])
        self.run_threatfox([ioc(1, confidence=100, last_seen="2026-11-15 10:00:00 UTC")], name="again.json")
        self.assertEqual(Indicator.objects.count(), 1)
        indicator = Indicator.objects.get()
        self.assertEqual((indicator.confidence, indicator.last_seen.day), (100, 15))
        self.assertEqual(Malware.objects.count(), 1)

    def test_empty_answer_loads_nothing(self):
        run, task = self.run_threatfox([])
        self.assertEqual((run.status, task.loaded), (RunStatus.SUCCESS, 0))


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code, self.payload = status, payload or {}

    def json(self):
        return self.payload


@override_settings(STAGING_DIR=tempfile.mkdtemp(), ABUSECH_AUTH_KEY="test-auth-key")
class ThreatFoxApiTests(TestCase):
    """Download through the API, with a fake HTTP session (no network in the tests)."""

    def connector(self, responses):
        connector = ThreatFoxConnector()
        connector.sleep = mock.Mock()
        connector.session = mock.Mock()
        connector.session.post.side_effect = responses
        return connector

    def test_request_asks_7_days_with_the_auth_key(self):
        connector = self.connector([FakeResponse(200, answer([ioc(1)]))])
        records = list(connector.transform(connector.extract()))
        self.assertEqual(len(records), 1)
        call = connector.session.post.call_args
        self.assertEqual(call.kwargs["json"], {"query": "get_iocs", "days": 7})
        self.assertEqual(call.kwargs["headers"], {"Auth-Key": "test-auth-key"})

    def test_no_result_is_an_empty_load(self):
        connector = self.connector([FakeResponse(200, {"query_status": "no_result", "data": "nothing"})])
        self.assertEqual(list(connector.transform(connector.extract())), [])

    def test_server_errors_and_cut_responses_are_retried(self):
        connector = self.connector([FakeResponse(503), requests.exceptions.ChunkedEncodingError("cut"),
                                    FakeResponse(200, answer([ioc(1)]))])
        self.assertEqual(len(list(connector.transform(connector.extract()))), 1)
        self.assertEqual([c.args[0] for c in connector.sleep.call_args_list], [10, 20])

    def test_refused_key_fails_at_once(self):
        connector = self.connector([FakeResponse(401)])
        with self.assertRaisesMessage(RuntimeError, "ThreatFox refused the Auth-Key (HTTP 401)"):
            connector.extract()
        connector.sleep.assert_not_called()

    def test_api_error_status_fails(self):
        connector = self.connector([FakeResponse(200, {"query_status": "illegal_days"})])
        with self.assertRaisesMessage(RuntimeError, "query_status='illegal_days'"):
            connector.extract()

    @override_settings(ABUSECH_AUTH_KEY="")
    def test_missing_key_is_explained(self):
        with self.assertRaisesMessage(RuntimeError, "ABUSECH_AUTH_KEY is empty in .env"):
            ThreatFoxConnector().extract()


class WarehouseIocTests(TestCase):
    """FR-14 / FR-20: fact_ioc, dim_indicator, dim_malware and dim_threat_type are rebuilt by the refresh."""

    def test_fact_ioc_has_one_row_per_indicator(self):
        ensure_sources()
        mirai = Malware.objects.create(malpedia_id="elf.mirai", name="Mirai", category="Linux")
        seen = datetime(2026, 11, 14, 8, 0, tzinfo=timezone.utc)
        Indicator.objects.create(threatfox_id=1, value="bad.example.com", ioc_type="domain", threat_type="botnet_cc",
                                 malware=mirai, confidence=80, first_seen=seen)
        Indicator.objects.create(threatfox_id=2, value="b" * 64, ioc_type="sha256_hash", threat_type="payload",
                                 confidence=50, first_seen=seen)
        counts = refresh_warehouse()
        self.assertEqual(counts["fact_ioc"], 2)
        rows = query("""
            SELECT i.ioc_type, m.family, m.category, t.label, s.name, f.first_seen_date_key, f.ioc_count, f.confidence
            FROM dw.fact_ioc f
            JOIN dw.dim_indicator i USING (indicator_key)
            LEFT JOIN dw.dim_malware m USING (malware_key)
            JOIN dw.dim_threat_type t USING (threat_type_key)
            JOIN dw.dim_source s USING (source_key)
            ORDER BY i.ioc_type
        """)
        self.assertEqual(rows, [("domain", "Mirai", "Linux", "botnet_cc", "threatfox", 20261114, 1, 80),
                                ("sha256_hash", None, None, "payload", "threatfox", 20261114, 1, 50)])
        self.assertEqual(query("SELECT description FROM dw.dim_threat_type WHERE label = 'botnet_cc'"),
                         [("Botnet command and control server",)])
