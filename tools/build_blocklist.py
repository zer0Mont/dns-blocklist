#!/usr/bin/env python3
"""Build an exact-domain Pi-hole gravity list from three public sources.

Pi-hole gravity stores a plain domain as an exact name. Listing example.com
does not block ads.example.com. This tool keeps every valid published name,
including names whose parent is also published. It does not expand a wildcard
source into subdomains that the source never wrote down.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SKIP_HOSTS = {
    "localhost",
    "localhost.localdomain",
    "local",
    "localdomain",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
}

# Exact names, and any parent of these names, would block the service itself.
# A different hostname under the same site is not held unless it is listed here
# or falls under an auth-provider tree.
PROTECTED_HOSTS = {
    "google.com",
    "www.google.com",
    "gmail.com",
    "www.gmail.com",
    "googlemail.com",
    "mail.google.com",
    "accounts.google.com",
    "myaccount.google.com",
    "id.google.com",
    "id.l.google.com",
    "admin.google.com",
    "drive.google.com",
    "docs.google.com",
    "sheets.google.com",
    "slides.google.com",
    "calendar.google.com",
    "meet.google.com",
    "chat.google.com",
    "maps.google.com",
    "photos.google.com",
    "play.google.com",
    "pay.google.com",
    "wallet.google.com",
    "gemini.google.com",
    "news.google.com",
    "translate.google.com",
    "one.google.com",
    "messages.google.com",
    "voice.google.com",
    "chrome.google.com",
    "chromewebstore.google.com",
    "console.cloud.google.com",
    "cloud.google.com",
    "dns.google",
    "g.co",
    "goo.gl",
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "tv.youtube.com",
    "studio.youtube.com",
    "youtu.be",
    "googleapis.com",
    "www.googleapis.com",
    "oauth2.googleapis.com",
    "gstatic.com",
    "www.gstatic.com",
    "fonts.gstatic.com",
    "googleusercontent.com",
    "googlevideo.com",
    "ytimg.com",
    "ggpht.com",
    "gvt1.com",
    "gvt2.com",
    "gvt3.com",
    "clients.google.com",
    "dl.google.com",
    "android.com",
    "www.android.com",
    "apple.com",
    "www.apple.com",
    "icloud.com",
    "www.icloud.com",
    "me.com",
    "www.me.com",
    "appleid.apple.com",
    "idmsa.apple.com",
    "gsa.apple.com",
    "id.apple.com",
    "developer.apple.com",
    "apps.apple.com",
    "music.apple.com",
    "tv.apple.com",
    "support.apple.com",
    "maps.apple.com",
    "setup.icloud.com",
    "gateway.icloud.com",
    "mzstatic.com",
    "cdn-apple.com",
    "apple-cloudkit.com",
    "icloud-content.com",
    "aaplimg.com",
    "microsoft.com",
    "www.microsoft.com",
    "login.microsoft.com",
    "account.microsoft.com",
    "accounts.microsoft.com",
    "office.com",
    "www.office.com",
    "office365.com",
    "www.office365.com",
    "microsoftonline.com",
    "login.microsoftonline.com",
    "login.windows.net",
    "live.com",
    "www.live.com",
    "login.live.com",
    "outlook.live.com",
    "onedrive.live.com",
    "outlook.com",
    "www.outlook.com",
    "hotmail.com",
    "www.hotmail.com",
    "outlook.office.com",
    "outlook.office365.com",
    "portal.office.com",
    "officeapps.live.com",
    "sharepoint.com",
    "onedrive.com",
    "windows.com",
    "www.windows.com",
    "azure.com",
    "portal.azure.com",
    "skype.com",
    "www.skype.com",
    "teams.microsoft.com",
    "copilot.microsoft.com",
    "bing.com",
    "www.bing.com",
    "aka.ms",
    "visualstudio.com",
    "www.visualstudio.com",
    "msn.com",
    "www.msn.com",
    "msftauth.net",
    "msidentity.com",
    "office.net",
    "github.com",
    "www.github.com",
    "api.github.com",
    "gist.github.com",
    "codeload.github.com",
    "uploads.github.com",
    "github.io",
    "githubusercontent.com",
    "raw.githubusercontent.com",
    "objects.githubusercontent.com",
    "camo.githubusercontent.com",
    "githubassets.com",
    "github.dev",
    "ghcr.io",
    "cloudflare.com",
    "www.cloudflare.com",
    "dash.cloudflare.com",
    "api.cloudflare.com",
    "cloudflare-dns.com",
    "one.one.one.one",
    "cdnjs.cloudflare.com",
    "workers.dev",
    "pages.dev",
    "cursor.com",
    "www.cursor.com",
    "cursor.sh",
    "api.cursor.sh",
    "api2.cursor.sh",
    "authenticator.cursor.sh",
    "repo42.cursor.sh",
    "cursorapi.com",
    "marketplace.cursorapi.com",
    "openai.com",
    "www.openai.com",
    "api.openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "www.chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    "anthropic.com",
    "www.anthropic.com",
    "api.anthropic.com",
    "console.anthropic.com",
    "claude.ai",
    "www.claude.ai",
    "x.ai",
    "grok.com",
    "www.grok.com",
    "grok.x.ai",
    "perplexity.ai",
    "www.perplexity.ai",
    "deepseek.com",
    "www.deepseek.com",
    "chat.deepseek.com",
    "api.deepseek.com",
    "mistral.ai",
    "www.mistral.ai",
    "cohere.ai",
    "www.cohere.ai",
    "cohere.com",
    "okta.com",
    "oktapreview.com",
    "okta-emea.com",
    "auth0.com",
    "onelogin.com",
    "duosecurity.com",
    "duo.com",
    "pingidentity.com",
    "pingone.com",
    "amazonaws.com",
    "cloudfront.net",
    "azureedge.net",
    "akadns.net",
    "akamaihd.net",
    "fastly.net",
    "windows.net",
    "1e100.net",
    "blogspot.com",
    "ngrok.io",
    "trycloudflare.com",
}

# Tenant hostnames on these auth providers are the login service.
AUTH_TREES = {
    "okta.com",
    "oktapreview.com",
    "okta-emea.com",
    "auth0.com",
    "onelogin.com",
    "duosecurity.com",
    "duo.com",
    "pingidentity.com",
    "pingone.com",
    "microsoftonline.com",
    "msftauth.net",
    "msidentity.com",
}

VENDOR_CCTLD = re.compile(
    r"^(?:www\.)?(?:google|youtube|apple|microsoft)\."
    r"(?:[a-z]{2}|com\.[a-z]{2}|co\.[a-z]{2}|org\.[a-z]{2}|net\.[a-z]{2}|ac\.[a-z]{2}|gov\.[a-z]{2})$"
)
GOOGLE_CORE_HOST = re.compile(
    r"^(?:id|accounts|myaccount|mail|admin|drive|docs|calendar|meet|maps|play|pay|wallet|gemini|login|signin|account)"
    r"\.google\.(?:com|[a-z]{2}|com\.[a-z]{2}|co\.[a-z]{2})$"
)
LABEL_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
GOOGLE_SIGN_IN = {
    "id.google.com",
    "id.l.google.com",
    "accounts.google.com",
    "myaccount.google.com",
    "mail.google.com",
}

HOLD_EXACT = set()
for _host in PROTECTED_HOSTS:
    HOLD_EXACT.add(_host)
    _parts = _host.split(".")
    for _index in range(1, len(_parts)):
        HOLD_EXACT.add(".".join(_parts[_index:]))


def hold_reason(domain: str) -> str | None:
    """Return why a domain must stay out of the exact list, or None to keep it."""
    if domain in PROTECTED_HOSTS or VENDOR_CCTLD.fullmatch(domain) or GOOGLE_CORE_HOST.fullmatch(domain):
        if GOOGLE_CORE_HOST.fullmatch(domain) or domain in GOOGLE_SIGN_IN:
            return "google-sign-in-or-product"
        return "primary-domain"
    for apex in AUTH_TREES:
        if domain == apex or domain.endswith("." + apex):
            return "auth-provider"
    if domain in HOLD_EXACT:
        # A public suffix such as "com" is held only because it is the parent of a
        # protected host we refuse to list. An exact Pi-hole entry would not block
        # that host, but these suffixes are not tracker names we want to publish.
        return "parent-of-core-service"
    return None


def normalize_token(token: str) -> str | None:
    """Reduce one list token to a bare exact domain, or None if it is not a domain."""
    token = token.strip().lower()
    if not token or token.startswith("#") or token.startswith("!") or token.startswith("@@"):
        return None
    if " #" in token:
        token = token.split(" #", 1)[0].strip()
    if "://" in token:
        token = token.split("://", 1)[1]
    if token.startswith("||"):
        token = token[2:]
    token = token.split("/", 1)[0]
    token = token.split("?", 1)[0]
    token = token.split("^", 1)[0]
    token = token.split("$", 1)[0]
    if token.count(":") == 1 and token.rsplit(":", 1)[-1].isdigit():
        token = token.rsplit(":", 1)[0]
    while token.startswith("*."):
        token = token[2:]
    token = token.strip(".*|")
    token = token.rstrip(".")
    if not token or token in SKIP_HOSTS:
        return None
    if any(ord(char) > 127 for char in token):
        try:
            token = ".".join(label.encode("idna").decode("ascii") for label in token.split("."))
        except Exception:
            return None
    if IP_RE.fullmatch(token) or ":" in token or " " in token:
        return None
    if len(token) > 253 or ".." in token:
        return None
    labels = token.split(".")
    if len(labels) < 2:
        return None
    if not re.search(r"[a-z]", labels[-1]):
        return None
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            return None
    return token


def domains_from_line(line: str) -> list[str]:
    text = line.strip()
    if not text or text.startswith("#") or text.startswith("!") or text.startswith("@@"):
        return []
    if " #" in text:
        text = text.split(" #", 1)[0].strip()
    parts = text.split()
    if not parts:
        return []
    if len(parts) >= 2 and (
        IP_RE.fullmatch(parts[0])
        or parts[0] in {"0.0.0.0", "127.0.0.1", "::", "::1", "255.255.255.255"}
        or ":" in parts[0]
    ):
        tokens = parts[1:]
    else:
        tokens = [parts[0]]
    found = []
    for token in tokens:
        domain = normalize_token(token)
        if domain:
            found.append(domain)
    return found


def parse_domain_file(path: Path) -> set[str]:
    found: set[str] = set()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            found.update(domains_from_line(line))
    return found


def source_notes(path: Path, limit: int = 16) -> list[str]:
    notes = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            if not stripped.startswith("#"):
                break
            notes.append(stripped.lstrip("# ").strip())
            if len(notes) >= limit:
                break
    return notes


def comment_value(notes: list[str], prefix: str) -> str | None:
    lowered = prefix.lower()
    for note in notes:
        if note.lower().startswith(lowered):
            return note.split(":", 1)[-1].strip()
    return None


def select_domains(
    candidates: set[str],
    unblocked: set[str] | None = None,
    preserve: set[str] | None = None,
) -> tuple[list[str], list[tuple[str, str]], list[str]]:
    """Keep every exact domain. Parents do not drop children.

    Held-back core and auth names are still omitted, including a child whose
    own name is held even when a sibling or parent is being restored.
    """
    blocked = set(unblocked or ())
    extras = set(preserve or ())
    kept: list[str] = []
    held: list[tuple[str, str]] = []
    skipped_unblocked: list[str] = []
    seen: set[str] = set()

    for domain in sorted(extras | candidates):
        if domain in seen:
            continue
        if domain in blocked:
            skipped_unblocked.append(domain)
            seen.add(domain)
            continue
        reason = hold_reason(domain)
        if reason:
            held.append((domain, reason))
            seen.add(domain)
            continue
        if domain not in candidates and domain not in extras:
            continue
        kept.append(domain)
        seen.add(domain)
    return kept, held, skipped_unblocked


def collapse_parents(domains: set[str]) -> set[str]:
    """Old behavior: drop a name when a shorter parent is also present.

    Used only to measure the previous prune. The published list does not call this.
    """
    kept: set[str] = set()
    for domain in sorted(domains, key=lambda item: (item.count("."), item)):
        parts = domain.split(".")
        if any(".".join(parts[index:]) in kept for index in range(1, len(parts))):
            continue
        kept.add(domain)
    return kept


def render_blocklist(domains: list[str], date: str, source_lines: list[str]) -> str:
    header = [
        "# Owner's custom blocklist for a home DNS ad blocker.",
        "# The blocker should regularly pull this file from the default branch (main).",
        "#",
        "# Format:",
        "# - One domain per line.",
        "# - A line starting with # is a comment and is not blocked.",
        "# - Each uncommented domain is an exact name for Pi-hole gravity.",
        "#   It blocks that name only. It does not block other names under it.",
        "#",
        "# oisd small (domainswild2) and HaGeZi Multi PRO publish wildcard-style",
        "# names: one listed name is meant to cover that name and its subdomains.",
        "# This file keeps the names they actually published. It does not add the",
        "# unpublished subdomains a wildcard would have covered. StevenBlack hosts",
        "# entries are exact hostnames and are kept the same way.",
        "#",
        "# Examples only (commented, not blocked):",
        "# example-ads.example",
        "# tracking.example.com",
        "#",
        f"# Rebuilt {date} (UTC) as an exact-domain list.",
    ]
    header.extend(f"# {line}" for line in source_lines)
    body = "\n".join(header)
    if domains:
        body += "\n" + "\n".join(domains) + "\n"
    else:
        body += "\n"
    return body


def load_name_file(path: Path | None) -> set[str]:
    if path is None:
        return set()
    found = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        domain = normalize_token(line.strip())
        if domain:
            found.add(domain)
    return found


def build_from_files(
    stevenblack: Path,
    oisd: Path,
    hagezi: Path,
    date: str,
    unblocked: set[str] | None = None,
    preserve: set[str] | None = None,
) -> tuple[str, dict]:
    sources = {
        "stevenblack": parse_domain_file(stevenblack),
        "oisd-small": parse_domain_file(oisd),
        "hagezi-pro": parse_domain_file(hagezi),
    }
    candidates: set[str] = set()
    for names in sources.values():
        candidates.update(names)
    kept, held, skipped_unblocked = select_domains(candidates, unblocked, preserve)
    allowed = {domain for domain in candidates if hold_reason(domain) is None and domain not in (unblocked or set())}
    pruned = collapse_parents(allowed)
    restored = allowed - pruned

    notes = {
        "stevenblack": source_notes(stevenblack),
        "oisd-small": source_notes(oisd),
        "hagezi-pro": source_notes(hagezi),
    }
    source_lines = [
        "Sources:",
        "StevenBlack hosts: " + (comment_value(notes["stevenblack"], "Date") or "see file"),
        "oisd small domainswild2 "
        + (comment_value(notes["oisd-small"], "Version") or "")
        + ", "
        + (comment_value(notes["oisd-small"], "Entries") or "?")
        + " wildcard entries",
        "HaGeZi Multi PRO wildcard domains "
        + (comment_value(notes["hagezi-pro"], "Version") or "")
        + ", "
        + (comment_value(notes["hagezi-pro"], "Number of entries") or "?")
        + " entries",
    ]
    text = render_blocklist(kept, date, source_lines)
    held_by_reason: dict[str, int] = {}
    for _domain, reason in held:
        held_by_reason[reason] = held_by_reason.get(reason, 0) + 1
    stats = {
        "per_source_unique": {key: len(value) for key, value in sources.items()},
        "unique_normalized": len(candidates),
        "kept": len(kept),
        "held_back": len(held),
        "held_by_reason": held_by_reason,
        "held_domains": [domain for domain, _reason in held],
        "skipped_previously_unblocked": len(skipped_unblocked),
        "would_have_pruned": len(restored),
        "pruned_kept": len(pruned),
        "source_notes": notes,
    }
    return text, stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Build an exact-domain blocklist.txt")
    parser.add_argument("--stevenblack", type=Path, required=True)
    parser.add_argument("--oisd", type=Path, required=True)
    parser.add_argument("--hagezi", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--date", default="2026-11-07")
    parser.add_argument("--stats", type=Path)
    parser.add_argument("--unblocked", type=Path, help="Exact domains the owner removed. Never re-add them.")
    parser.add_argument("--preserve", type=Path, help="Exact domains to keep even if missing from the sources.")
    args = parser.parse_args()
    text, stats = build_from_files(
        args.stevenblack,
        args.oisd,
        args.hagezi,
        args.date,
        load_name_file(args.unblocked),
        load_name_file(args.preserve),
    )
    args.output.write_text(text, encoding="utf-8")
    printable = {key: value for key, value in stats.items() if key != "held_domains"}
    rendered = json.dumps(printable, indent=2)
    if args.stats:
        args.stats.write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
