import os
import tempfile
import unittest

from database import CacheDatabase
from main import lookup_ioc
from threat_intel import MissingAPIKeyError, ThreatIntelClient
from validators import IoCType, classify_ioc


class FakeClient(ThreatIntelClient):
    name = "fake"
    supported_types = frozenset({IoCType.IPV4})

    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def query(self, ioc, ioc_type):
        self.calls += 1
        if self.fail:
            raise MissingAPIKeyError("fake: API key not configured.")
        return {"source": "fake", "risk_level": "suspicious", "summary": "s", "details": {}}

    def _fetch(self, *a):
        raise NotImplementedError

    def _summarize(self, *a):
        raise NotImplementedError


class OrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cache = CacheDatabase(os.path.join(self.tmp.name, "c.db"), ttl_hours=24)
        self.cache.initialize()
        self.ioc = classify_ioc("8.8.8.8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_second_lookup_is_served_from_cache(self):
        client = FakeClient()
        first = lookup_ioc(self.ioc, [client], self.cache)
        second = lookup_ioc(self.ioc, [client], self.cache)
        self.assertEqual(client.calls, 1)
        self.assertEqual(first["results"][0]["origin"], "live")
        self.assertEqual(second["results"][0]["origin"], "cache")

    def test_refresh_bypasses_cache_read(self):
        client = FakeClient()
        lookup_ioc(self.ioc, [client], self.cache)
        lookup_ioc(self.ioc, [client], self.cache, read_cache=False)
        self.assertEqual(client.calls, 2)

    def test_provider_failure_is_reported_not_raised_or_cached(self):
        client = FakeClient(fail=True)
        report = lookup_ioc(self.ioc, [client], self.cache)
        self.assertEqual(report["results"], [])
        self.assertEqual(len(report["errors"]), 1)
        self.assertIsNone(self.cache.get("8.8.8.8", "fake"))

    def test_unsupported_type_is_skipped(self):
        report = lookup_ioc(classify_ioc("example.com"), [FakeClient()], self.cache)
        self.assertEqual(len(report["skipped"]), 1)


if __name__ == "__main__":
    unittest.main()