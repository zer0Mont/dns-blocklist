"""Read and create secret files. This module never generates or replaces a Pi-hole password."""

from __future__ import annotations

import os
import stat
from pathlib import Path


def read_secret_file(path: Path) -> str:
    if path.is_symlink():
        raise PermissionError("secret path is a symlink")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise PermissionError("secret path is not a regular file")
    if info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise PermissionError("secret file is readable by group or others")
    if info.st_uid not in {0, os.geteuid()}:
        raise PermissionError("secret file owner is not root or the collector")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        raw = os.read(descriptor, 4096)
    finally:
        os.close(descriptor)
    secret = raw.decode("utf-8").strip()
    if not secret or len(raw) > 4096:
        raise ValueError("secret file is empty or too large")
    return secret


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
