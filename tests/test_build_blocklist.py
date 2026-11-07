#!/usr/bin/env python3
"""Exact-domain list rules. No network and no third-party packages."""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import build_blocklist as bl


class NormalizeTests(unittest.TestCase):
    def test_hosts_line_is_exact_name(self):
        self.assertEqual(bl.domains_from_line("0.0.0.0 ads.example.com"), ["ads.example.com"])

    def test_inline_comment_is_ignored(self):
        self.assertEqual(
            bl.domains_from_line("0.0.0.0 ads.example.com # tracker"),
            ["ads.example.com"],
        )

    def test_wildcard_and_abp_markers_become_the_named_domain_only(self):
        self.assertEqual(bl.normalize_token("*.ads.example.com"), "ads.example.com")
        self.assertEqual(bl.normalize_token("||ads.example.com^"), "ads.example.com")

    def test_comments_localhost_and_addresses_are_dropped(self):
        self.assertEqual(bl.domains_from_line("# example.com"), [])
        self.assertEqual(bl.domains_from_line("127.0.0.1 localhost"), [])
        self.assertEqual(bl.domains_from_line("0.0.0.0 0.0.0.0"), [])

    def test_file_dedupes_exact_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "list.txt"
            path.write_text("ads.example.com\nADS.example.com\n0.0.0.0 ads.example.com\n", encoding="utf-8")
            self.assertEqual(bl.parse_domain_file(path), {"ads.example.com"})


class SelectionTests(unittest.TestCase):
    def test_parent_does_not_drop_child(self):
        kept, held, skipped = bl.select_domains({"example.com", "ads.example.com", "track.ads.example.com"})
        self.assertEqual(skipped, [])
        self.assertEqual(held, [])
        self.assertEqual(set(kept), {"example.com", "ads.example.com", "track.ads.example.com"})

    def test_exact_duplicates_collapse_to_one(self):
        kept, _held, _skipped = bl.select_domains({"example.com", "example.com"})
        self.assertEqual(kept, ["example.com"])

    def test_held_names_stay_out_when_children_are_restored(self):
        candidates = {
            "doubleclick.net",
            "ad.doubleclick.net",
            "ads.google.com",
            "id.google.com",
            "id.google.co.uk",
            "discovertech.us.auth0.com",
            "eloqua.onelogin.com",
            "gvt2.com",
            "metrics.cursor.sh",
            "collector.github.com",
            "bzr.openai.com",
        }
        kept, held, _skipped = bl.select_domains(candidates)
        kept_set = set(kept)
        self.assertIn("doubleclick.net", kept_set)
        self.assertIn("ad.doubleclick.net", kept_set)
        self.assertIn("ads.google.com", kept_set)
        self.assertIn("metrics.cursor.sh", kept_set)
        self.assertIn("collector.github.com", kept_set)
        self.assertIn("bzr.openai.com", kept_set)
        self.assertNotIn("id.google.com", kept_set)
        self.assertNotIn("id.google.co.uk", kept_set)
        self.assertNotIn("discovertech.us.auth0.com", kept_set)
        self.assertNotIn("eloqua.onelogin.com", kept_set)
        self.assertNotIn("gvt2.com", kept_set)
        held_names = {domain for domain, _reason in held}
        self.assertTrue({"id.google.com", "discovertech.us.auth0.com", "gvt2.com"} <= held_names)

    def test_core_service_primaries_are_held(self):
        for domain in (
            "google.com",
            "apple.com",
            "microsoft.com",
            "github.com",
            "api.github.com",
            "cloudflare.com",
            "cursor.com",
            "api2.cursor.sh",
            "openai.com",
            "chatgpt.com",
            "claude.ai",
            "accounts.google.com",
            "login.microsoftonline.com",
            "company.okta.com",
        ):
            self.assertIsNotNone(bl.hold_reason(domain), domain)

    def test_lookalikes_and_tracker_suffixes_are_not_held(self):
        for domain in (
            "gmail.tf",
            "icloud.com.gr",
            "ads.google.com",
            "iadsdk.apple.com",
            "ampcid.google.com",
            "co.cc",
            "co.gp",
            "co.nf",
        ):
            self.assertIsNone(bl.hold_reason(domain), domain)

    def test_owner_unblocked_name_is_not_readded(self):
        kept, _held, skipped = bl.select_domains(
            {"ads.example.com", "track.example.com"},
            unblocked={"ads.example.com"},
        )
        self.assertEqual(kept, ["track.example.com"])
        self.assertEqual(skipped, ["ads.example.com"])

    def test_preserved_owner_block_survives_when_sources_omit_it(self):
        kept, _held, _skipped = bl.select_domains(
            {"other.example"},
            preserve={"owner-added.example"},
        )
        self.assertEqual(set(kept), {"other.example", "owner-added.example"})

    def test_preserved_core_name_is_still_held(self):
        kept, held, _skipped = bl.select_domains(set(), preserve={"google.com"})
        self.assertEqual(kept, [])
        self.assertEqual([domain for domain, _reason in held], ["google.com"])

    def test_collapse_helper_is_not_the_published_behavior(self):
        names = {"example.com", "ads.example.com"}
        self.assertEqual(bl.collapse_parents(names), {"example.com"})
        kept, _held, _skipped = bl.select_domains(names)
        self.assertEqual(set(kept), names)


class RenderTests(unittest.TestCase):
    def test_header_does_not_promise_subdomain_blocking(self):
        text = bl.render_blocklist(["ads.example.com"], "2026-11-07", ["Sources: test"])
        self.assertIn("exact name", text)
        self.assertIn("does not block other names under it", text)
        self.assertIn("does not add the", text)
        self.assertNotIn("all of its subdomains", text)
        self.assertNotIn("blocks that domain and all", text)
        self.assertIn("# example-ads.example", text)
        self.assertNotIn("\nexample-ads.example\n", text)
        self.assertTrue(text.strip().endswith("ads.example.com"))


if __name__ == "__main__":
    unittest.main()
