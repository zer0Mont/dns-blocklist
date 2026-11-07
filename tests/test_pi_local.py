"""Review-only Pi-local collector, guardian preflight, and scheduler tests."""

import json
import os
import stat
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from pi_local.aggregate import collect_record, extract_database_summary, synthetic_record
from pi_local.api import PiHoleClient, TransportError
from pi_local.cli import activation_allowed, load_config, main, read_secret_file, restore_cron
from pi_local.delivery import DOCUMENTED_CONTRACT, attempt_silence, classify_http, plan_attempts
from pi_local.disk import disk_preflight
from pi_local.secrets import write_secret_atomic
from pi_local.guardian import check_guardian
from pi_local.redact import redact
from pi_local.schedule import comment_gravity_line, gravity_command, inspect_cron
from pi_local.urls import validate_base_url
from pi_local.window import previous_london_day

LONDON = ZoneInfo("Europe/London")
ROOT = Path(__file__).resolve().parents[1]
GUARDIAN = "https://raw.githubusercontent.com/zer0Mont/dns-blocklist/main/blocklist.txt"
STOCK_CRON = """# Pi-hole stock lines
59 1 * * 7 pihole PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole updateGravity >/var/log/pihole/pihole_updateGravity.log || cat /var/log/pihole/pihole_updateGravity.log
00 00 * * * root PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole flush once quiet
@reboot root /usr/sbin/logrotate /etc/logrotate.d/pihole
59 17 * * * pihole PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole updatechecker
@reboot pihole PATH="$PATH:/usr/sbin:/usr/local/bin/" pihole updatechecker reboot
"""


class WindowTests(unittest.TestCase):
    def test_dst_day_lengths(self):
        spring = previous_london_day(datetime(2026, 3, 30, 0, 20, tzinfo=LONDON))
        normal = previous_london_day(datetime(2026, 6, 15, 0, 20, tzinfo=LONDON))
        autumn = previous_london_day(datetime(2026, 10, 26, 0, 20, tzinfo=LONDON))
        self.assertEqual((spring.hours, normal.hours, autumn.hours), (23, 24, 25))
        for window in (spring, normal, autumn):
            self.assertEqual(window.api_until_if_inclusive - window.api_from, window.hours * 3600 - 1)
            self.assertEqual(window.api_until_if_exclusive - window.api_from, window.hours * 3600)
            self.assertIsNone(window.api_until(None))
            described = window.as_dict()
            self.assertEqual(described["until_semantics"], "unverified")
            self.assertEqual(described["label"], "previous-europe-london-calendar-day")
            self.assertNotIn("rolling", described["label"])
        late = previous_london_day(datetime(2026, 6, 15, 23, 59, tzinfo=LONDON))
        early = previous_london_day(datetime(2026, 6, 15, 0, 0, tzinfo=LONDON))
        self.assertEqual(late.start.date().isoformat(), "2026-06-14")
        self.assertEqual(early.start.date().isoformat(), "2026-06-14")


class SummaryTests(unittest.TestCase):
    def test_missing_counts_are_unavailable_not_zero(self):
        parsed = extract_database_summary({"percent_blocked": 0})
        self.assertEqual(parsed["status"], "unavailable")
        self.assertNotIn("total", parsed)

    def test_zero_denominator_keeps_counts_and_hides_percentage(self):
        parsed = extract_database_summary(
            {"sum_queries": 0, "sum_blocked": 0, "percent_blocked": 0, "total_clients": 4}
        )
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["total"], 0)
        self.assertEqual(parsed["blocked"], 0)
        self.assertIsNone(parsed["percent_blocked"])
        self.assertNotIn("total_clients", parsed)

    def test_percentage_from_counts(self):
        parsed = extract_database_summary(
            {"sum_queries": 8, "sum_blocked": 2, "percent_blocked": 25, "total_clients": 1}
        )
        self.assertEqual(parsed["percent_blocked"], 25.0)

    def test_live_summary_queries_are_not_the_day_total(self):
        client = PiHoleClient(
            "https://pi.hole.example.invalid",
            transport=FakeTransport(scripted_api()),
            sleeper=lambda _attempt: None,
        )
        client.login("app-secret")
        try:
            record = collect_record(
                client,
                datetime(2026, 6, 15, 0, 20, tzinfo=LONDON),
                until_semantics="exclusive",
            )
        finally:
            client.logout()
        self.assertEqual(record["queries"]["total"], 100)
        self.assertEqual(record["completeness"]["day_coverage"], "not-evidenced")
        self.assertNotIn("uptime", json.dumps(record))
        self.assertNotEqual(record["record_id"], "session-sid")
        self.assertEqual(record["queries"]["blocked"], 25)
        self.assertNotEqual(record["queries"]["total"], 999)
        encoded = json.dumps(record)
        for forbidden in ("clients", "top_domains", "app-secret", "session-sid", "example.com"):
            self.assertNotIn(forbidden, encoded)
        paths = [path for _method, path in client.calls]
        self.assertNotIn("/api/stats/top_domains", paths)
        self.assertNotIn("/api/stats/database/top_clients", paths)
        self.assertNotIn("/api/queries", paths)
        self.assertTrue(any(method == "DELETE" and path == "/api/auth" for method, path in client.calls))

    def test_unauthorized_summary_is_unavailable_and_not_retried(self):
        client = PiHoleClient(
            "https://pi.hole.example.invalid",
            transport=FakeTransport(unauthorized_summary),
            sleeper=lambda _attempt: None,
        )
        client.login("app-secret")
        try:
            record = collect_record(
                client, datetime(2026, 6, 15, 0, 20, tzinfo=LONDON), "exclusive"
            )
        finally:
            client.logout()
        self.assertEqual(record["queries"]["status"], "unavailable")
        self.assertIsNone(record["queries"].get("total"))
        summary_calls = [
            call for call in client.calls if call[1].startswith("/api/stats/database/summary")
        ]
        self.assertEqual(len(summary_calls), 1)

    def test_transport_retries_are_bounded(self):
        transport = FlakyTransport()
        client = PiHoleClient(
            "https://pi.hole.example.invalid",
            transport=transport,
            sleeper=lambda _attempt: None,
            max_attempts=3,
        )
        result = client.get_json("/api/info/version")
        self.assertEqual(result.payload["version"]["ftl"]["local"]["version"], "v6.0")
        self.assertEqual(transport.attempts, 3)


class GuardianTests(unittest.TestCase):
    def test_single_block_subscription_passes_whatever_the_id_is(self):
        check = check_guardian(
            [{"id": 99, "address": GUARDIAN + "/", "type": "block", "enabled": True}],
            GUARDIAN,
        )
        self.assertTrue(check.ok)
        self.assertEqual(check.action, "report-only")
        self.assertEqual(check.matches[0].public_dict()["db_type"], 0)

    def test_allow_duplicate_is_reported_and_not_ok(self):
        check = check_guardian(
            [
                {"id": 2, "address": GUARDIAN, "type": "block", "enabled": True},
                {"id": 8, "address": GUARDIAN, "type": "allow", "enabled": True},
            ],
            GUARDIAN,
        )
        self.assertFalse(check.ok)
        self.assertIn("not deleting", " ".join(check.messages).lower())
        self.assertEqual(check.action, "report-only")

    def test_database_type_integers_are_classified(self):
        blocked = check_guardian(
            [{"id": 4, "address": GUARDIAN, "type": 0, "enabled": True}],
            GUARDIAN,
        )
        allowed = check_guardian(
            [{"id": 2, "address": GUARDIAN, "type": 1, "enabled": True}],
            GUARDIAN,
        )
        self.assertTrue(blocked.ok)
        self.assertFalse(allowed.ok)

    def test_missing_url_does_not_ask_for_creation(self):
        check = check_guardian([], GUARDIAN)
        self.assertFalse(check.ok)
        self.assertIn("will not create", check.messages[0])

    def test_updater_cannot_add_an_allow_entry(self):
        self.assertEqual(gravity_command(), ("pihole", "updateGravity"))
        source = (ROOT / "pi_local" / "guardian.py").read_text(encoding="utf-8")
        unit = (ROOT / "pi_local" / "units" / "pihole-daily-gravity.service").read_text(encoding="utf-8")
        self.assertNotIn("sqlite", source.lower())
        self.assertNotIn("POST", source)
        self.assertNotIn("DELETE", source)
        self.assertIn("\nExecStart=/usr/bin/pihole updateGravity\n", unit)
        self.assertNotIn("allow", unit.lower())
        self.assertNotIn("sqlite", unit.lower())


class SafetyTests(unittest.TestCase):
    def test_remote_http_is_rejected_and_loopback_http_is_limited(self):
        with self.assertRaises(ValueError):
            validate_base_url("http://192.168.1.10")
        with self.assertRaises(ValueError):
            validate_base_url("https://user:secret@pi.example/api")
        self.assertTrue(validate_base_url("http://127.0.0.1:8080").startswith("http://127.0.0.1"))
        self.assertTrue(validate_base_url("https://pi.example").startswith("https://"))

    def test_secrets_are_redacted_and_rejected_in_config(self):
        self.assertNotIn("app-secret", redact('{"password":"app-secret","sid":"session-sid"}'))
        self.assertNotIn("session-sid", redact("sid=session-sid", ["session-sid"]))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text('{"password":"nope"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_world_readable_secret_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-password"
            path.write_text("secret\n", encoding="utf-8")
            os.chmod(path, 0o644)
            with self.assertRaises(PermissionError):
                read_secret_file(path)
            os.chmod(path, 0o600)
            self.assertEqual(read_secret_file(path), "secret")

    def test_delivery_is_disabled_by_default(self):
        example = json.loads(
            (ROOT / "pi_local" / "examples" / "pi-local.example.json").read_text(encoding="utf-8")
        )
        payload = synthetic_record(datetime(2026, 6, 15, tzinfo=LONDON))

        class Boom:
            def request(self, *args):
                raise AssertionError("network")

        decision = attempt_silence(example, payload, None, transport=Boom())
        self.assertFalse(decision["delivered"])
        self.assertFalse(decision["network"])
        self.assertFalse(decision["queued"])
        approved = {
            "delivery": {
                "enabled": True,
                "prepare_only": False,
                "contract_approved": True,
                "contract": DOCUMENTED_CONTRACT,
            }
        }
        still = attempt_silence(approved, payload, "key", transport=Boom())
        self.assertFalse(still["network"])
        self.assertEqual(classify_http(409), "not-acknowledged")
        self.assertEqual(classify_http(302), "redirect-refused")
        self.assertEqual(plan_attempts([503, 503, 200, 200]), ["retry", "retry", "accepted"])
        self.assertEqual(plan_attempts([409, 200]), ["not-acknowledged"])

    def test_dry_run_help_and_install_do_not_enable_or_send(self):
        self.assertEqual(main([]), 0)
        self.assertEqual(main(["activate"]), 2)
        self.assertEqual(main(["install", "--dest", "/tmp"]), 2)
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "sample.json"
            self.assertEqual(main(["dry-run", "--output", str(output)]), 0)
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(payload["synthetic"])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(main(["install", "--dest", tmp, "--confirm-install-disabled-units"]), 0)
            installed = Path(tmp) / "etc" / "systemd" / "system" / "pihole-daily-stats.timer"
            text = installed.read_text(encoding="utf-8")
            commands = [line for line in text.splitlines() if not line.startswith("#")]
            self.assertFalse(any("systemctl" in line for line in commands))
            self.assertFalse((Path(tmp) / "etc" / "pihole-daily-stats" / "app-password").exists())

    def test_stock_cron_can_be_disabled_and_restored_without_touching_unknown_jobs(self):
        plan = inspect_cron(STOCK_CRON)
        self.assertTrue(plan.can_edit_cron)
        self.assertFalse(activation_allowed(False, plan, True))
        self.assertFalse(activation_allowed(True, plan, False))
        self.assertTrue(activation_allowed(True, plan, True))
        edited = comment_gravity_line(STOCK_CRON)
        self.assertIn("# pi-local-disabled:", edited)
        self.assertEqual(edited.count("pihole updateGravity"), 1)
        self.assertIn("pihole flush", edited)
        unknown = inspect_cron(STOCK_CRON + "\n0 1 * * * root /usr/local/bin/custom-job\n")
        self.assertFalse(unknown.can_edit_cron)
        with self.assertRaises(ValueError):
            comment_gravity_line(STOCK_CRON + "\n0 1 * * * root /usr/local/bin/custom-job\n")
        with tempfile.TemporaryDirectory() as tmp:
            cron_path = Path(tmp) / "pihole"
            backup = Path(tmp) / "pihole.pi-local-backup"
            cron_path.write_text(edited, encoding="utf-8")
            from pi_local.schedule import sha256_text

            backup.write_text(
                json.dumps(
                    {
                        "original_sha256": sha256_text(STOCK_CRON),
                        "edited_sha256": sha256_text(edited),
                        "original": STOCK_CRON,
                    }
                ),
                encoding="utf-8",
            )
            restore_cron(cron_path, backup)
            self.assertEqual(cron_path.read_text(encoding="utf-8"), STOCK_CRON)


class CoverageTests(unittest.TestCase):
    def test_valid_zero_is_not_unavailable_and_partial_is_not_complete(self):
        parsed = extract_database_summary(
            {"sum_queries": 0, "sum_blocked": 0, "percent_blocked": 0, "total_clients": 0}
        )
        self.assertEqual(parsed["status"], "ok")
        self.assertEqual(parsed["total"], 0)
        self.assertIsNone(parsed["percent_blocked"])
        client = PiHoleClient(
            "https://pi.hole.example.invalid",
            transport=FakeTransport(partial_api),
            sleeper=lambda _attempt: None,
        )
        client.login("app-secret")
        try:
            record = collect_record(client, datetime(2026, 6, 15, 0, 20, tzinfo=LONDON), "inclusive")
        finally:
            client.logout()
        self.assertEqual(record["queries"]["status"], "ok")
        self.assertEqual(record["queries"]["total"], 0)
        self.assertEqual(record["version"]["status"], "unavailable")
        self.assertEqual(record["completeness"]["queries"], "validated")
        self.assertEqual(record["completeness"]["day_coverage"], "not-evidenced")
        self.assertNotIn("uptime", json.dumps(record))
        summary = [call for call in client.calls if "/api/stats/database/summary" in call[1]]
        self.assertEqual(len(summary), 1)

    def test_unverified_until_does_not_query_the_database(self):
        client = PiHoleClient(
            "https://pi.hole.example.invalid",
            transport=FakeTransport(scripted_api()),
            sleeper=lambda _attempt: None,
        )
        client.login("app-secret")
        try:
            record = collect_record(client, datetime(2026, 6, 15, 0, 20, tzinfo=LONDON))
        finally:
            client.logout()
        self.assertEqual(record["queries"]["reason"], "until-semantics-unverified")
        self.assertFalse(any("/api/stats/database/summary" in call[1] for call in client.calls))
        self.assertTrue(any(call[0] == "DELETE" for call in client.calls))

    def test_disk_preflight_uses_a_fresh_measurement(self):
        report = disk_preflight(Path("/"), 1)
        self.assertIn("free_bytes", report)
        self.assertEqual(report["measured"], "now")
        self.assertNotIn("993", json.dumps(report))

    def test_secret_writer_rejects_replacement_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-password"
            write_secret_atomic(path, "already-created")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                write_secret_atomic(path, "replacement")
            link = Path(tmp) / "linked"
            link.symlink_to(path)
            with self.assertRaises(PermissionError):
                read_secret_file(link)
        source = (ROOT / "pi_local").read_text() if False else "\n".join(
            path.read_text(encoding="utf-8") for path in (ROOT / "pi_local").glob("*.py")
        )
        self.assertNotIn("/api/auth/app", source)


class FakeTransport:
    def __init__(self, handler):
        self.handler = handler

    def request(self, method, path, body, headers):
        return self.handler(method, path, body, headers)


class FlakyTransport:
    def __init__(self):
        self.attempts = 0

    def request(self, method, path, body, headers):
        self.attempts += 1
        if self.attempts < 3:
            raise TransportError("down")
        payload = {"version": {"ftl": {"local": {"version": "v6.0"}}}}
        return 200, json.dumps(payload).encode("utf-8")


def scripted_api():
    def handler(method, path, body, headers):
        if method == "POST" and path == "/api/auth":
            return 200, json.dumps({"session": {"valid": True, "sid": "session-sid"}}).encode()
        if method == "DELETE" and path == "/api/auth":
            return 200, b"{}"
        if path.startswith("/api/stats/database/summary"):
            self_check_sid(headers)
            return 200, json.dumps(
                {"sum_queries": 100, "sum_blocked": 25, "percent_blocked": 25, "total_clients": 3}
            ).encode()
        if path == "/api/stats/summary":
            return 200, json.dumps(
                {
                    "queries": {"total": 999, "blocked": 999},
                    "clients": {"active": 2, "total": 2},
                    "uptime": 99999,
                    "gravity": {"domains_being_blocked": 10},
                }
            ).encode()
        if path == "/api/info/version":
            return 200, json.dumps({"version": {"ftl": {"local": {"version": "v6.1"}}}}).encode()
        if path == "/api/dns/blocking":
            return 200, json.dumps({"blocking": "enabled", "timer": None}).encode()
        return 404, json.dumps({"error": {"key": "not_found", "message": "secret body"}}).encode()

    return handler


def partial_api(method, path, body, headers):
    if method == "POST" and path == "/api/auth":
        return 200, json.dumps({"session": {"valid": True, "sid": "session-sid"}}).encode()
    if method == "DELETE":
        return 200, b"{}"
    if path.startswith("/api/stats/database/summary"):
        body = {"sum_queries": 0, "sum_blocked": 0, "percent_blocked": 0, "total_clients": 0}
        return 200, json.dumps(body).encode()
    if path == "/api/stats/summary":
        return 200, json.dumps(
            {"uptime": 5, "clients": {"active": 1}, "gravity": {"domains_being_blocked": 3}}
        ).encode()
    if path == "/api/info/version":
        return 404, json.dumps({"error": {"key": "not_found"}}).encode()
    if path == "/api/dns/blocking":
        return 200, json.dumps({"blocking": "enabled", "timer": None}).encode()
    return 404, b"{}"


def unauthorized_summary(method, path, body, headers):
    if method == "POST" and path == "/api/auth":
        return 200, json.dumps({"session": {"valid": True, "sid": "session-sid"}}).encode()
    if method == "DELETE":
        return 200, b"{}"
    if path.startswith("/api/stats/database/summary"):
        return 401, json.dumps({"error": {"key": "unauthorized", "message": "password app-secret"}}).encode()
    return 200, json.dumps({"gravity": {"domains_being_blocked": 1}, "version": {"ftl": {"local": {"version": "v6"}}}}).encode()


def self_check_sid(headers):
    if headers.get("sid") != "session-sid":
        raise AssertionError("session header missing")


if __name__ == "__main__":
    unittest.main()
