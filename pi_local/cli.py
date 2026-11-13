"""Command line. The default action prints help and changes nothing."""

from __future__ import annotations

import argparse
import hashlib
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
from pi_local.schedule import stock_gravity_lines
from pi_local.secrets import read_secret_file, read_systemd_credential, write_secret_atomic

HELP = """\
Pi-local Pi-hole prep (review only).

Nothing here enables a timer or edits Pi-hole's cron, including activate
--go-live. Reading this help does not contact Pi-hole.

  python3 -m pi_local dry-run --output PATH
  python3 -m pi_local preflight --config PATH
  python3 -m pi_local install --dest DIR --confirm-install-disabled-units
  python3 -m pi_local uninstall --dest DIR

install copies a disabled stats timer only. It does not enable it, and it
does not edit /etc/cron.d/pihole. Daily Gravity is deferred, not implemented.
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
            "uninstall",
            "activate",
            "collect",
        ),
    )
    parser.add_argument("--config")
    parser.add_argument("--output")
    parser.add_argument("--dest")
    parser.add_argument("--confirm-install-disabled-units", action="store_true")
    parser.add_argument("--go-live", action="store_true")
    parser.add_argument("--path")
    parser.add_argument("--remove-secrets", action="store_true")
    parser.add_argument("--remove-data", action="store_true")
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
    if args.command == "uninstall":
        return _uninstall(args.dest, args.remove_secrets, args.remove_data)
    if args.command == "collect":
        return _collect(args.config)
    if args.command == "activate":
        return _activate(args)
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


def resolve_config_path(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not directory:
        raise ValueError("pass --config or set CREDENTIALS_DIRECTORY")
    return Path(directory) / "config.json"


def load_credential_config() -> dict:
    data = json.loads(read_systemd_credential("config.json"))
    if not isinstance(data, dict):
        raise ValueError("config must be a JSON object")
    _reject_secret_keys(data)
    return data


def _password(config: dict) -> str:
    source = config.get("password_source", "systemd-credential")
    if source == "systemd-credential":
        return read_systemd_credential("pihole_app_password")
    if source == "file":
        path = config.get("password_file")
        if not isinstance(path, str):
            raise ValueError("password_file is required")
        return read_secret_file(Path(path))
    raise ValueError("unsupported password_source")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _place_file(root: Path, relative: str, content: str, mode: int, manifest: dict) -> None:
    if Path(relative).is_absolute() or ".." in Path(relative).parts:
        raise ValueError("refusing to install outside the destination")
    target = root / relative
    if target.is_symlink():
        raise ValueError(f"refusing to replace symlink {relative}")
    if target.exists() and target.read_text(encoding="utf-8") != content:
        raise ValueError(f"refusing to replace existing {relative}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    os.chmod(target, mode)
    manifest[relative] = _sha256(content)


def _install(dest: str | None, confirmed: bool) -> int:
    if not dest or not confirmed:
        print(
            "install copies the package and a disabled stats timer. "
            "It requires --dest and --confirm-install-disabled-units. "
            "It does not enable the timer and does not edit cron.",
            file=sys.stderr,
        )
        return 2
    root = Path(dest)
    package = Path(__file__).resolve().parent
    manifest: dict[str, str] = {}
    for source in sorted(package.rglob("*")):
        if not source.is_file() or source.suffix == ".pyc" or "__pycache__" in source.parts:
            continue
        if source.name.startswith("pihole-daily-gravity"):
            continue
        relative = Path("opt") / "pi-local" / source.relative_to(package.parent)
        _place_file(root, str(relative), source.read_text(encoding="utf-8"), 0o644, manifest)
    for unit in sorted(UNIT_DIR.glob("pihole-daily-stats.*")):
        relative = Path("etc") / "systemd" / "system" / unit.name
        _place_file(root, str(relative), unit.read_text(encoding="utf-8"), 0o644, manifest)
    note = (
        "The stats service reads config.json and app-password only through\n"
        "systemd LoadCredential. Source files stay mode 0600. The copies\n"
        "systemd shows the service are mode 0440 and are accepted only\n"
        "inside /run/credentials/<unit>.\n"
        "Do not put the password in the unit or on a command line.\n"
        "Copy examples/pi-local.example.json to config.json if you have not.\n"
        "This install does not enable the timer and does not edit cron.\n"
        "Daily Gravity is deferred and is not implemented.\n"
    )
    _place_file(root, "etc/pihole-daily-stats/README", note, 0o640, manifest)
    manifest_path = root / "var" / "lib" / "pihole-daily-stats" / "install-manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    if manifest_path.is_symlink():
        raise ValueError("refusing to replace symlink install-manifest.json")
    manifest_path.write_text(
        json.dumps({"files": manifest}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o600)
    cron = root / "etc" / "cron.d" / "pihole"
    if cron.is_file() and not cron.is_symlink():
        found = stock_gravity_lines(cron.read_text(encoding="utf-8"))
        print(f"left stock gravity cron untouched ({len(found)} updateGravity line(s))")
    print("installed package and disabled stats units; not enabled and not started")
    return 0


def _uninstall(dest: str | None, remove_secrets: bool, remove_data: bool) -> int:
    if not dest:
        print("uninstall needs --dest", file=sys.stderr)
        return 2
    root = Path(dest)
    manifest_path = root / "var" / "lib" / "pihole-daily-stats" / "install-manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        if not remove_secrets and not remove_data:
            print("no install manifest; nothing removed", file=sys.stderr)
            return 2
        recorded = {}
    else:
        recorded = json.loads(manifest_path.read_text(encoding="utf-8"))["files"]
    for relative, digest in sorted(recorded.items(), reverse=True):
        if relative == "var/lib/pihole-daily-stats/install-manifest.json":
            continue
        path = root / relative
        if path.is_symlink():
            print(f"skipped symlink {relative}")
            continue
        if not path.is_file():
            continue
        if _sha256(path.read_text(encoding="utf-8")) != digest:
            print(f"left modified file {relative}")
            continue
        path.unlink()
    for directory in (
        root / "opt" / "pi-local" / "pi_local" / "units",
        root / "opt" / "pi-local" / "pi_local" / "examples",
        root / "opt" / "pi-local" / "pi_local",
        root / "opt" / "pi-local",
    ):
        if directory.is_dir() and not directory.is_symlink() and not any(directory.iterdir()):
            directory.rmdir()
    if remove_secrets:
        secret = root / "etc" / "pihole-daily-stats" / "app-password"
        if secret.is_file() and not secret.is_symlink():
            secret.unlink()
            print("removed app-password because --remove-secrets was set")
    if remove_data:
        state = root / "var" / "lib" / "pihole-daily-stats"
        for child in state.glob("*.json"):
            if child.name == "install-manifest.json" or child.is_symlink():
                continue
            child.unlink()
        print("removed aggregate json because --remove-data was set")
    if manifest_path.is_file() and not manifest_path.is_symlink():
        manifest_path.unlink()
    print("uninstalled this install's unchanged files; preexisting config was kept")
    return 0


def _activate(args) -> int:
    print(
        "activate does not enable units and does not edit /etc/cron.d/pihole. "
        "Daily Gravity is deferred and is not implemented. "
        "After a later approval the only stats command is: "
        "systemctl enable --now pihole-daily-stats.timer",
        file=sys.stderr,
    )
    return 2


def _collect(config_path: str | None) -> int:
    try:
        config = load_config(Path(config_path)) if config_path else load_credential_config()
    except (ValueError, PermissionError, json.JSONDecodeError) as exc:
        print(exc.__class__.__name__, file=sys.stderr)
        return 2
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


if __name__ == "__main__":
    sys.exit(main())
