"""Unit tests for Core Subsystems: Logging, Auto-Maintenance, Security, i18n, Cooldown, and Database Migrations."""
import unittest
import time
import json
import logging
from src.core.logger import scrub_sensitive_data, RingBufferLogHandler, AutoMaintenanceMonitor
from src.core.security import RateLimiter, SecurityManager
from src.core.i18n import I18nManager
from src.core.cooldown import CooldownManager

class TestCoreLoggingAndMaintenance(unittest.TestCase):
    def test_sensitive_data_scrubber(self):
        part1 = "MTA1OTI4MzYxMjM0NTY3ODkwMQ"
        part2 = "GabcDE"
        part3 = "1234567890abcdefghijklmnopqrstuv"
        fake_token = f"{part1}.{part2}.{part3}"
        raw_msg = f"Failed to connect using token={fake_token} and password: 'SuperSecretPassword123!'"
        scrubbed = scrub_sensitive_data(raw_msg)
        self.assertNotIn(fake_token, scrubbed)
        self.assertNotIn("SuperSecretPassword123!", scrubbed)
        self.assertIn("REDACTED", scrubbed)

    def test_ring_buffer_log_handler(self):
        handler = RingBufferLogHandler(capacity=10)
        logger = logging.getLogger("test_ring_buffer")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        for i in range(15):
            logger.info("Test message %d", i)

        logs = handler.get_logs(limit=20)
        self.assertLessEqual(len(logs), 10)
        self.assertEqual(logs[0]["level"], "INFO")

    def test_auto_maintenance_monitor_trip(self):
        monitor = AutoMaintenanceMonitor(threshold=3, window_seconds=10)
        self.assertFalse(monitor.is_tripped)

        # Record 2 errors -> not tripped
        monitor.record_error({"level": "ERROR", "message": "Err 1"})
        monitor.record_error({"level": "ERROR", "message": "Err 2"})
        self.assertFalse(monitor.is_tripped)

        # Record 3rd error -> trips maintenance
        monitor.record_error({"level": "ERROR", "message": "Err 3"})
        self.assertTrue(monitor.is_tripped)
        self.assertIsNotNone(monitor.trip_reason)

        # Reset
        monitor.reset_maintenance("TestRunner")
        self.assertFalse(monitor.is_tripped)

class TestSecurityAndRateLimiting(unittest.TestCase):
    def test_rate_limiter_sliding_window(self):
        limiter = RateLimiter(max_requests=3, window_seconds=2)
        key = "client_test_1"

        allowed1, _ = limiter.is_allowed(key)
        allowed2, _ = limiter.is_allowed(key)
        allowed3, _ = limiter.is_allowed(key)
        allowed4, retry_after = limiter.is_allowed(key)

        self.assertTrue(allowed1)
        self.assertTrue(allowed2)
        self.assertTrue(allowed3)
        self.assertFalse(allowed4)
        self.assertGreaterEqual(retry_after, 1)

    def test_csrf_token_lifecycle(self):
        sec = SecurityManager()
        session_id = "user_12345"
        token = sec.generate_csrf_token(session_id)

        self.assertTrue(sec.validate_csrf_token(session_id, token))
        self.assertFalse(sec.validate_csrf_token("different_user", token))
        self.assertFalse(sec.validate_csrf_token(session_id, "invalid:token:format"))

    def test_developer_authorization(self):
        sec = SecurityManager()
        sec._dev_ids = {999888777}
        self.assertTrue(sec.is_developer(999888777))
        self.assertTrue(sec.is_developer("999888777"))
        self.assertFalse(sec.is_developer(111222333))

class TestI18nAndCooldown(unittest.TestCase):
    def test_i18n_translation_and_fallback(self):
        mgr = I18nManager(default_locale="en")
        en_str = mgr.get("blacklisted_user", locale="en")
        self.assertIn("blacklisted", en_str)

        es_str = mgr.get("blacklisted_user", locale="es")
        self.assertIn("bloqueado", es_str)

        # Fallback to key or English if key not found in target
        fallback_str = mgr.get("unknown_key_xyz", locale="es")
        self.assertEqual(fallback_str, "unknown_key_xyz")

    def test_cooldown_manager(self):
        cd = CooldownManager(default_cooldown_seconds=1.0)
        guild_id = 100
        user_id = 200
        cmd = "quarantine"

        is_cd1, rem1 = cd.check_cooldown(guild_id, user_id, cmd)
        self.assertFalse(is_cd1)
        self.assertEqual(rem1, 0.0)

        # Immediate next invocation should be on cooldown
        is_cd2, rem2 = cd.check_cooldown(guild_id, user_id, cmd)
        self.assertTrue(is_cd2)
        self.assertGreater(rem2, 0.0)

        # Reset
        cd.reset_cooldown(guild_id, user_id, cmd)
        is_cd3, _ = cd.check_cooldown(guild_id, user_id, cmd)
        self.assertFalse(is_cd3)

if __name__ == "__main__":
    unittest.main()
