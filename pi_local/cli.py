"""Command line. The default action prints help and changes nothing."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from pi_local.aggregate import collect_record, synthetic_record, unavailable_record, write_private_json
from pi_local.api import ApiUnavailable, PiHoleClient
from pi_local.delivery import attempt_silence
from pi_local.disk import disk_preflight
from pi_local.guardian import check_guardian, parse_lists
from pi_local.schedule import comment_gravity_line, gravity_command, inspect_cron, sha256_text
from pi_local.secrets import read_secret_file, write_secret_atomic

HELP = """\
Pi-local Pi-hole prep (review only).

Nothing here enables a timer or refreshes Gravity unless you later pass
--go-live. Reading this help does not contact Pi-hole.

  python3 -m pi_local dry-run --output PATH
  python3 -m pi_local preflight --config PATH
  python3 -m pi_local install --dest DIR --confirm-install-disabled-units
  python3 -m pi_local activate --go-live --config PATH

Do not run activate until you have explicitly approved going live.
"""

FORBIDDEN_CONFIG_KEYS = frozenset({"password", "sid", "webhook_key", "authorization", "api_key"})
UNIT_DIR = Path(__file__).resolve().parent / "units"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pi_local", add_help=True)
    parser.add_argument(
        "command",
        nargs="?",
        choices=(
            "dry-run",
            "preflight",
            "disk-check",
            "provision-password",
            "install",
            "activate",
            "collect",
            "restore",
        ),
    )
    parser.add_argument("--config")
    parser.add_argument("--output")
    parser.add_argument("--dest")
    parser.add_argument("--confirm-install-disabled-units", action="store_true")
    parser.add_argument("--go-live", action="store_true")
    parser.add_argument("--accept-disable-stock-weekly-gravity", action="store_true")
    parser.add_argument("--cron-file")
    parser.add_argument("--backup")
    parser.add_argument("--path")
    parser.add_argument("--store-existing-password", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        print(HELP)
        return 0
    if args.command == "dry-run":
        return _dry_run(args.output)
    if args.command == "preflight":
        return _preflight(args.config)
    if args.command == "disk-check":
        return _disk_check(args.path, args.config)
    if args.command == "provision-password":
        return _provision_password(args.path, args.store_existing_password)
    if args.command == "install":
        return _install(args.dest, args.confirm_install_disabled_units)
    if args.command == "collect":
        return _collect(args.config)
    if args.command == "activate":
        return _activate(args)
    if args.command == "restore":
        return _restore(args)
    print(HELP)
    return 0


def load_config(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    _reject_secret_keys(data)
    return data


def _reject_secret_keys(data: dict) -> None:
    for key, value in data.items():
        if key.lower() in FORBIDDEN_CONFIG_KEYS:
            raise ValueError("config must not contain a secret; use a mode 0600 file")
        if isinstance(value, dict):
            _reject_secret_keys(value)


def _disk_check(path: str | None, config_path: str | None) -> int:
    minimum = 268435456
    target = path
    if config_path:
        config = load_config(Path(config_path))
        minimum = int(config.get("minimum_free_bytes", minimum))
        target = target or config.get("output_dir")
    if not target:
        print("disk-check needs --path or --config", file=sys.stderr)
        return 2
    report = disk_preflight(Path(target), minimum)
    print(json.dumps(report, sort_keys=True))
    return 0 if report["ok"] else 1


def _provision_password(path: str | None, approved: bool) -> int:
    if not path or not approved:
        print(
            "provision-password only stores a password you already created. "
            "It does not generate or replace one. Pass --path and "
            "--store-existing-password after checking other consumers.",
            file=sys.stderr,
        )
        return 2
    if not sys.stdin.isatty():
        print("refusing to read a password from a pipe", file=sys.stderr)
        return 2
    secret = _read_no_echo()
    write_secret_atomic(Path(path), secret)
    print("stored existing password; no Pi-hole password was created or replaced")
    return 0


def _read_no_echo() -> str:
    import termios
    import tty

    descriptor = sys.stdin.fileno()
    original = termios.tcgetattr(descriptor)
    try:
        tty.setraw(descriptor)
        chars = []
        while True:
            char = sys.stdin.read(1)
            if char in {"\n", "\r"}:
                break
            chars.append(char)
    finally:
        termios.tcsetattr(descriptor, termios.TCSADRAIN, original)
        sys.stdout.write("\n")
    return "".join(chars)


def _dry_run(output: str | None) -> int:
    now = datetime.now(ZoneInfo("Europe/London"))
    payload = synthetic_record(now)
    if output:
        write_private_json(Path(output), payload)
    else:
        json.dump(payload, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    return 0


def _preflight(config_path: str | None) -> int:
    if not config_path:
        print("preflight needs --config", file=sys.stderr)
        return 2
    config = load_config(Path(config_path))
    disk = disk_preflight(Path(config.get("output_dir", "/")), int(config.get("minimum_free_bytes", 268435456)))
    print(json.dumps({"disk": disk}, sort_keys=True))
    if not disk["ok"]:
        print("free space is below the configured floor; not contacting Pi-hole", file=sys.stderr)
        return 1
    password = _password(config)
    client = PiHoleClient(config["base_url"], config.get("ca_file"))
    try:
        client.login(password)
        result = client.get_json("/api/lists")
        if result.unavailable:
            print("lists unavailable", file=sys.stderr)
            return 1
        check = check_guardian(parse_lists(result.payload), config["guardian_list_url"])
    finally:
        password = ""
        client.logout()
    for message in check.messages:
        print(message)
    for match in check.matches:
        print(json.dumps(match.public_dict(), sort_keys=True))
    return 0 if check.ok else 1


def _password(config: dict) -> str:
    source = config.get("password_source", "file")
    if source == "systemd-credential":
        directory = os.environ.get("CREDENTIALS_DIRECTORY")
        if not directory:
            raise ValueError("systemd credential directory is not set")
        return read_secret_file(Path(directory) / "pihole_app_password")
    path = config.get("password_file")
    if not isinstance(path, str):
        raise ValueError("password_file is required")
    return read_secret_file(Path(path))


def _install(dest: str | None, confirmed: bool) -> int:
    if not dest or not confirmed:
        print(
            "install copies disabled units only and requires --dest and "
            "--confirm-install-disabled-units. It does not enable them.",
            file=sys.stderr,
        )
        return 2
    root = Path(dest)
    unit_dest = root / "etc" / "systemd" / "system"
    unit_dest.mkdir(parents=True, exist_ok=True)
    for unit in sorted(UNIT_DIR.glob("pihole-daily-*")):
        target = unit_dest / unit.name
        target.write_text(unit.read_text(encoding="utf-8"), encoding="utf-8")
        os.chmod(target, 0o644)
    config_dir = root / "etc" / "pihole-daily-stats"
    config_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(config_dir, 0o750)
    note = config_dir / "README"
    note.write_text(
        "Create app-password here with mode 0600.\n"
        "Do not put the password in config.json or on a command line.\n"
        "Units in this install are not enabled.\n",
        encoding="utf-8",
    )
    os.chmod(note, 0o640)
    print("installed disabled units; not enabled and not started")
    return 0


def activation_allowed(guardian_ok: bool, plan, accept_disable: bool) -> bool:
    """True only when Gravity may be scheduled without duplicating or editing unknown cron."""
    if not guardian_ok or not plan.can_enable_gravity:
        return False
    if plan.gravity_lines == 1 and not accept_disable:
        return False
    return True


def _activate(args) -> int:
    if not args.go_live:
        print("activate does nothing without --go-live", file=sys.stderr)
        return 2
    if not args.config or not args.cron_file:
        print("activate --go-live needs --config and --cron-file", file=sys.stderr)
        return 2
    config = load_config(Path(args.config))
    cron_path = Path(args.cron_file)
    original = cron_path.read_text(encoding="utf-8")
    plan = inspect_cron(original)
    password = _password(config)
    client = PiHoleClient(config["base_url"], config.get("ca_file"))
    guardian_ok = False
    try:
        client.login(password)
        listed = client.get_json("/api/lists")
        if not listed.unavailable:
            check = check_guardian(parse_lists(listed.payload), config["guardian_list_url"])
            guardian_ok = check.ok
            for message in check.messages:
                print(message)
        else:
            print("lists unavailable; not changing Gravity's schedule", file=sys.stderr)
    finally:
        password = ""
        client.logout()
    if not activation_allowed(guardian_ok, plan, args.accept_disable_stock_weekly_gravity):
        print(" ".join(plan.messages), file=sys.stderr)
        print("activation refused; cron was not edited and timers were not enabled", file=sys.stderr)
        return 1
    if plan.gravity_lines == 1:
        edited = comment_gravity_line(original)
        backup = cron_path.with_suffix(cron_path.suffix + ".pi-local-backup")
        backup.write_text(
            json.dumps(
                {
                    "original_sha256": sha256_text(original),
                    "edited_sha256": sha256_text(edited),
                    "original": original,
                    "command": list(gravity_command()),
                }
            ),
            encoding="utf-8",
        )
        os.chmod(backup, 0o600)
        cron_path.write_text(edited, encoding="utf-8")
    print("cron updated only for the recognised weekly updateGravity line")
    print("next, review and enable the disabled systemd timers")
    return 0


def _collect(config_path: str | None) -> int:
    if not config_path:
        print("collect needs --config", file=sys.stderr)
        return 2
    config = load_config(Path(config_path))
    password = _password(config)
    now = datetime.now(ZoneInfo(config.get("timezone", "Europe/London")))
    semantics = config.get("database_summary_until")
    client = PiHoleClient(config["base_url"], config.get("ca_file"))
    try:
        try:
            client.login(password)
            record = collect_record(client, now, semantics if isinstance(semantics, str) else None)
        except ApiUnavailable as exc:
            record = unavailable_record(now, exc.error_key or "authentication-failed")
    finally:
        password = ""
        client.logout()
    day = record["interval"]["from"][:10]
    destination = Path(config["output_dir"]) / f"{day}.json"
    write_private_json(destination, record)
    key = None
    delivery = config.get("delivery") or {}
    if delivery.get("enabled") is True:
        key = read_secret_file(Path(delivery["key_file"]))
    decision = attempt_silence(config, record, key)
    key = None
    print(decision["reason"])
    return 0 if record["queries"]["status"] == "ok" else 1


def _restore(args) -> int:
    if not args.cron_file or not args.backup:
        print("restore needs --cron-file and --backup", file=sys.stderr)
        return 2
    restore_cron(Path(args.cron_file), Path(args.backup))
    print("restored the cron file from backup; timers were not changed")
    return 0


def restore_cron(cron_path: Path, backup_path: Path) -> None:
    payload = json.loads(backup_path.read_text(encoding="utf-8"))
    current = cron_path.read_text(encoding="utf-8")
    if sha256_text(current) != payload["edited_sha256"]:
        raise ValueError("cron file changed after the edit; not restoring over it")
    cron_path.write_text(payload["original"], encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
