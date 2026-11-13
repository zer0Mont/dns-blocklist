"""Read and create secret files. This module never generates or replaces a Pi-hole password.

systemd LoadCredential exposes files in ``$CREDENTIALS_DIRECTORY``, which it
sets to ``/run/credentials/<unit>``. Those files are owned by the service user
or root and are mode 0440: owner and group may read, nobody may write, and
other users have no access. That group-read bit is part of the credential
mount. It is not accepted for an ordinary secret path.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

CREDENTIAL_ROOT = Path("/run/credentials")
_CREDENTIAL_MODES = frozenset({0o400, 0o440})
_WRITE_OR_OTHER = stat.S_IWUSR | stat.S_IWGRP | stat.S_IXUSR | stat.S_IXGRP | stat.S_IRWXO


@dataclass(frozen=True)
class CredentialFacts:
    requested_name: str
    directory_resolved: Path
    file_resolved: Path
    mode: int
    uid: int
    is_symlink: bool
    is_reg: bool
    directory_is_symlink: bool
    text: str = ""


def read_secret_file(path: Path) -> str:
    if path.is_symlink():
        raise PermissionError("secret path is a symlink")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError("secret path is not a regular file")
    if stat.S_IMODE(info.st_mode) & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("secret file is readable by group or others")
    if info.st_uid not in {0, os.geteuid()}:
        raise PermissionError("secret file owner is not root or the collector")
    secret = _read_nofollow(path).strip()
    if not secret:
        raise ValueError("secret file is empty")
    return secret


def validate_credential_facts(facts: CredentialFacts, *, euid: int, credential_root: Path = CREDENTIAL_ROOT) -> None:
    """Accept only a direct child of ``/run/credentials/<unit>`` with a safe mode."""
    name = _safe_credential_name(facts.requested_name)
    if facts.is_symlink or facts.directory_is_symlink or not facts.is_reg:
        raise PermissionError("credential path is a symlink or not a regular file")
    mode = stat.S_IMODE(facts.mode)
    if mode & _WRITE_OR_OTHER or mode not in _CREDENTIAL_MODES:
        raise PermissionError("credential mode is not read-only 0400 or 0440")
    if facts.uid not in {0, euid}:
        raise PermissionError("credential owner is not root or the service user")
    root = Path(credential_root)
    try:
        unit = facts.directory_resolved.relative_to(root)
        leaf = facts.file_resolved.relative_to(facts.directory_resolved)
    except ValueError as exc:
        raise PermissionError("credential path is outside /run/credentials/<unit>") from exc
    if len(unit.parts) != 1 or unit.parts[0] in {".", ".."}:
        raise PermissionError("credential directory is not a single unit directory")
    if len(leaf.parts) != 1 or leaf.parts[0] != name:
        raise PermissionError("credential file escapes its directory")


def read_systemd_credential(name: str) -> str:
    facts = inspect_systemd_credential(name)
    validate_credential_facts(facts, euid=os.geteuid())
    secret = _read_nofollow(facts.file_resolved).strip()
    if not secret:
        raise ValueError("credential is empty")
    return secret


def inspect_systemd_credential(name: str) -> CredentialFacts:
    filename = _safe_credential_name(name)
    raw_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    if not raw_directory:
        raise PermissionError("CREDENTIALS_DIRECTORY is not set")
    directory = Path(raw_directory)
    if not directory.is_absolute():
        raise PermissionError("CREDENTIALS_DIRECTORY is not absolute")
    directory_is_symlink = directory.is_symlink()
    try:
        directory_resolved = directory.resolve(strict=True)
    except OSError as exc:
        raise PermissionError("credential directory cannot be resolved") from exc
    candidate = directory_resolved / filename
    file_is_symlink = candidate.is_symlink()
    try:
        info = candidate.lstat()
    except OSError as exc:
        raise PermissionError("credential file cannot be stated") from exc
    return CredentialFacts(
        requested_name=filename,
        directory_resolved=directory_resolved,
        file_resolved=candidate if file_is_symlink else candidate.resolve(strict=True),
        mode=info.st_mode,
        uid=info.st_uid,
        is_symlink=file_is_symlink,
        is_reg=stat.S_ISREG(info.st_mode),
        directory_is_symlink=directory_is_symlink,
    )


def _safe_credential_name(name: str) -> str:
    if not name or name != Path(name).name or name in {".", ".."}:
        raise PermissionError("credential name escapes the directory")
    return name


def _read_nofollow(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, 4096)
        extra = os.read(descriptor, 1)
    finally:
        os.close(descriptor)
    if extra:
        raise ValueError("secret file is too large")
    return raw.decode("utf-8")


def write_secret_atomic(path: Path, secret: str) -> None:
    """Create a new mode 0600 file. Refuses to replace an existing path."""
    if "\n" in secret or not secret.strip():
        raise ValueError("refusing to store an empty or multi-line secret")
    if path.exists() or path.is_symlink():
        raise FileExistsError("refusing to replace an existing secret file")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError("refusing to use an existing temporary secret file")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, secret.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path)
    except FileExistsError:
        os.unlink(temporary)
        raise FileExistsError("refusing to replace an existing secret file") from None
    os.unlink(temporary)
    os.chmod(path, 0o600)
