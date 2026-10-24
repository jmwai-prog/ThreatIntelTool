import os
import sqlite3
import tempfile
import time
import unittest

from database import CacheDatabase


class CacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "cache.db")
        self.cache = CacheDatabase(self.path, ttl_hours=24)
        self.cache.initialize()

    def tearDown(self):
        if hasattr(self, 'cache') and self.cache:
            try:
                self.cache.conn.close()
            except Exception:
                pass
        self.tmp._ignore_cleanup_errors = True
        self.tmp.cleanup()

    def test_miss_then_hit(self):
        self.assertIsNone(self.cache.get("8.8.8.8", "mock"))
        self.cache.save("8.8.8.8", "ipv4", "mock", {"risk_level": "clean"})
        hit = self.cache.get("8.8.8.8", "mock")
        self.assertEqual(hit.data, {"risk_level": "clean"})

    def test_expired_entry_is_a_miss(self):
        self.cache.save("8.8.8.8", "ipv4", "mock", {"x": 1})
        old = int(time.time()) - 25 * 3600
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE ioc_cache SET fetched_at = ?", (old,))
        self.assertIsNone(self.cache.get("8.8.8.8", "mock"))
        self.assertEqual(self.cache.purge_expired(), 1)

    def test_corrupt_row_is_discarded(self):
        self.cache.save("8.8.8.8", "ipv4", "mock", {"x": 1})
        with sqlite3.connect(self.path) as conn:
            conn.execute("UPDATE ioc_cache SET response_json = 'not json'")
        self.assertIsNone(self.cache.get("8.8.8.8", "mock"))

    def test_sql_metacharacters_are_inert(self):
        evil = "x'; DROP TABLE ioc_cache;--"
        self.cache.save(evil, "domain", "mock", {"ok": True})
        self.assertTrue(self.cache.get(evil, "mock").data["ok"])


if __name__ == "__main__":
    unittest.main()