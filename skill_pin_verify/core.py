"""Core helpers: hashing, downloading, and safe tarball extraction.

Everything here is standard library only. Extraction is hardened
against path traversal (absolute member names, ``..`` segments, and
symlinks pointing outside the destination are skipped and reported).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path

MAX_DOWNLOAD_BYTES = 100 * 1024 * 1024  # 100 MiB, guards against zip bombs

USER_AGENT = "skill-pin-verify/0.1.0 (+https://github.com/hahahahahahahahah6/skill-pin-verify)"


class PinVerifyError(Exception):
    """Fatal error during download, hash, or extraction."""


def sha256_bytes(data: bytes) -> str:
    """Hex SHA-256 of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike | str) -> str:
    """Hex SHA-256 of a file, streamed so large files stay cheap."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: os.PathLike | str) -> Path:
    """Fetch *url* into *dest*.

    Accepts http(s) URLs, ``file://`` URLs, and plain local paths.
    Returns the destination path. Raises :class:`PinVerifyError`.
    """
    dest = Path(dest)
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme in ("", "file"):
        if parsed.scheme == "file":
            src = Path(urllib.request.url2pathname(parsed.path))
        else:
            src = Path(url).expanduser()
        if not src.is_file():
            raise PinVerifyError(f"local file not found: {src}")
        shutil.copyfile(src, dest)
        return dest

    if parsed.scheme not in ("http", "https"):
        raise PinVerifyError(f"unsupported URL scheme: {parsed.scheme!r}")

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response, open(dest, "wb") as handle:
            total = 0
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise PinVerifyError(
                        f"download exceeds {MAX_DOWNLOAD_BYTES // (1024 * 1024)} MiB limit, refusing"
                    )
                handle.write(chunk)
    except PinVerifyError:
        raise
    except Exception as exc:  # network errors, timeouts, HTTP errors
        raise PinVerifyError(f"download failed: {exc}") from exc
    return dest


def is_tarball(path: os.PathLike | str) -> bool:
    """True when *path* looks like a tar archive (any compression)."""
    try:
        return tarfile.is_tarfile(path)
    except OSError:
        return False


def _inside(base: Path, target: Path) -> bool:
    base = base.resolve()
    try:
        target_resolved = target.resolve()
    except OSError:
        target_resolved = target.absolute()
    return target_resolved == base or str(target_resolved).startswith(str(base) + os.sep)


def safe_extract(tar_path: os.PathLike | str, dest: os.PathLike | str) -> list[dict]:
    """Extract *tar_path* into *dest*, skipping dangerous members.

    Absolute member names, ``..`` segments, and symlinks that escape
    *dest* are skipped and returned as traversal findings so the audit
    layer can flag them instead of the extractor following them.
    """
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    findings: list[dict] = []

    with tarfile.open(tar_path, "r:*") as tar:
        for member in tar.getmembers():
            name = member.name
            target = dest / name

            risky = name.startswith(("/", "\\")) or ".." in Path(name).parts
            if not risky and (member.issym() or member.islnk()):
                link_target = dest / member.linkname if not os.path.isabs(member.linkname) else Path(member.linkname)
                risky = not _inside(dest, link_target)
            if not risky:
                risky = not _inside(dest, target)

            if risky:
                findings.append(
                    {
                        "path": name,
                        "rule": "tar_traversal",
                        "severity": "high",
                        "detail": "tarball member escapes the extraction directory (absolute path, '..' segment, or symlink); skipped, not extracted",
                    }
                )
                continue
            tar.extract(member, path=dest)
    return findings


def extract_to_temp(tar_path: os.PathLike | str) -> tuple[Path, tempfile.TemporaryDirectory, list[dict]]:
    """Extract a tarball into a fresh temp dir; caller cleans up the TemporaryDirectory."""
    tmp = tempfile.TemporaryDirectory(prefix="spv-")
    findings = safe_extract(tar_path, tmp.name)
    return Path(tmp.name), tmp, findings


def utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
