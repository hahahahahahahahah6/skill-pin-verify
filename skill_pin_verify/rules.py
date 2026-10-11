"""Detection rules: scan skill package contents for tampering signals.

Each rule returns findings shaped like::

    {"path": "SKILL.md", "rule": "install_script", "severity": "high",
     "detail": "..."}

Severities: ``high`` (likely malicious or a takeover vector),
``medium`` (suspicious, warrants review), ``low`` (informational).
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# File names that should never ship inside a skill package silently.
INSTALL_FILENAMES = {
    "install.sh", "install.py", "install.js", "install.bat", "install.ps1",
    "setup.sh", "setup.py", "setup.js", "postinstall.sh", "preinstall.sh",
    "postinstall.js", "preinstall.js",
}

HOOK_KEYS = {"postinstall", "preinstall", "prepublish", "prepublishOnly"}

NETWORK_PATTERNS = [
    r"\bcurl\b",
    r"\bwget\b",
    r"urllib\.request",
    r"urllib\.urlopen",
    r"http\.client",
    r"\bsocket\b",
    r"\brequests\.",
    r"\bhttpx\b",
    r"\bfetch\s*\(",
    r"XMLHttpRequest",
]

SHELL_PATTERNS = [
    r"subprocess\.(run|call|Popen|check_output|check_call)",
    r"os\.system\b",
    r"os\.popen\b",
    r"child_process",
    r"\bpowershell\b",
    r"\bcmd\.exe\b",
]

OBFUSCATION_PATTERNS = [
    r"base64\.b64decode",
    r"Buffer\.from\([^)]*,\s*['\"]base64['\"]\)",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"__import__\s*\(",
    r"marshal\.loads",
    r"codecs\.decode\([^)]*rot",
    r"(\\x[0-9a-fA-F]{2}){8,}",  # long hex-escape runs
]

ENV_PATTERNS = [
    r"os\.environ",
    r"os\.getenv",
    r"process\.env",
    r"getenv\s*\(",
]

SENSITIVE_PATH_PATTERNS = [
    r"~\/\.ssh",
    r"~\/\.aws",
    r"\.pem\b",
    r"id_rsa",
    r"known_hosts",
    r"\.env\b",
    r"AWS_SECRET",
    r"OPENAI_API_KEY",
    r"api[_-]?key",
    r"client[_-]?secret",
]

# curl ... | sh is the classic prompt-level install vector.
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^\n]*\|\s*(ba)?sh\b", re.IGNORECASE)
URL_PATTERN = re.compile(r"https?://[^\s)\"'<>`]+")
DOWNLOAD_RUN_WORDS = re.compile(
    r"(download|fetch|pull|install).{0,40}(and|then).{0,40}(run|execute|eval)",
    re.IGNORECASE,
)

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".js", ".ts", ".sh", ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".html", ".css", ".xml", ".rst", ".ps1",
    ".bat", ".c", ".cpp", ".h", ".java", ".go", ".rs", ".rb", ".php",
}
MAX_SCAN_BYTES = 2 * 1024 * 1024  # skip giant/minified blobs, note them instead


def _compile(patterns: list[str]) -> list[re.Pattern]:
    return [re.compile(p) for p in patterns]


_NETWORK = _compile(NETWORK_PATTERNS)
_SHELL = _compile(SHELL_PATTERNS)
_OBFUSC = _compile(OBFUSCATION_PATTERNS)
_ENV = _compile(ENV_PATTERNS)
_SENSITIVE = _compile(SENSITIVE_PATH_PATTERNS)


def _iter_text_files(root: Path):
    """Yield (relative_path, absolute_path) for scannable text files."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in {".git", "__pycache__", "node_modules", ".venv"}]
        for filename in filenames:
            abs_path = Path(dirpath) / filename
            rel = abs_path.relative_to(root).as_posix()
            suffix = abs_path.suffix.lower()
            if suffix in TEXT_SUFFIXES or suffix == "" or filename.upper() in {"SKILL.MD", "README", "LICENSE", "MAKEFILE"}:
                yield rel, abs_path


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_SCAN_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("utf-8", errors="replace")


def _matches(compiled: list[re.Pattern], text: str) -> list[str]:
    hits = []
    for pattern in compiled:
        match = pattern.search(text)
        if match:
            hits.append(match.group(0)[:80])
    return hits


def audit_directory(root: os.PathLike | str) -> list[dict]:
    """Run every rule over an extracted skill directory."""
    root = Path(root)
    findings: list[dict] = []

    for rel, abs_path in _iter_text_files(root):
        name = abs_path.name.lower()

        # Rule 1: install scripts / lifecycle hooks.
        if name in INSTALL_FILENAMES:
            findings.append({
                "path": rel, "rule": "install_script", "severity": "high",
                "detail": f"install-style script {abs_path.name!r} ships inside the skill package",
            })

        text = _read_text(abs_path)
        if text is None:
            findings.append({
                "path": rel, "rule": "unscannable_blob", "severity": "low",
                "detail": "file exceeds the 2 MiB scan cap or is unreadable; review manually",
            })
            continue

        network_hits = _matches(_NETWORK, text)
        shell_hits = _matches(_SHELL, text)
        env_hits = _matches(_ENV, text)

        # Rule 2: network calls.
        for hit in network_hits:
            findings.append({
                "path": rel, "rule": "network_call", "severity": "medium",
                "detail": f"network capability referenced: {hit!r}",
            })

        # Rule 3: shell execution.
        for hit in shell_hits:
            findings.append({
                "path": rel, "rule": "shell_exec", "severity": "medium",
                "detail": f"shell execution referenced: {hit!r}",
            })

        # Rule 4: obfuscation.
        for hit in _matches(_OBFUSC, text):
            findings.append({
                "path": rel, "rule": "obfuscation", "severity": "medium",
                "detail": f"obfuscation/decode primitive referenced: {hit!r}",
            })

        # Rule 5: credential access plus network in the same file = exfil shape.
        if env_hits and network_hits:
            findings.append({
                "path": rel, "rule": "possible_exfil", "severity": "high",
                "detail": f"reads environment/credentials ({env_hits[0]!r}) and can reach the network ({network_hits[0]!r}) in the same file",
            })

        # Rule 6: sensitive path or secret-name references.
        for hit in _matches(_SENSITIVE, text):
            findings.append({
                "path": rel, "rule": "sensitive_reference", "severity": "medium",
                "detail": f"references sensitive material: {hit!r}",
            })

        # Rule 7: lifecycle hooks in manifests.
        if name in {"package.json"}:
            for hook in HOOK_KEYS:
                if re.search(rf'"{hook}"\s*:', text):
                    findings.append({
                        "path": rel, "rule": "lifecycle_hook", "severity": "high",
                        "detail": f"npm lifecycle hook {hook!r} declared in package.json",
                    })

        # Rules 8-9: SKILL.md is the trust surface agents read first.
        if name == "skill.md":
            pipe = PIPE_TO_SHELL.search(text)
            if pipe:
                findings.append({
                    "path": rel, "rule": "remote_install_instruction", "severity": "high",
                    "detail": f"SKILL.md pipes a download into a shell: {pipe.group(0)[:80]!r}",
                })
            if DOWNLOAD_RUN_WORDS.search(text):
                findings.append({
                    "path": rel, "rule": "remote_install_instruction", "severity": "medium",
                    "detail": "SKILL.md tells the agent to download and then run something",
                })
            urls = URL_PATTERN.findall(text)
            for url in sorted(set(urls))[:10]:
                findings.append({
                    "path": rel, "rule": "remote_reference", "severity": "low",
                    "detail": f"SKILL.md references remote URL: {url[:100]}",
                })

    return findings


def summarize(findings: list[dict]) -> dict:
    counts = {"high": 0, "medium": 0, "low": 0}
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {"total": len(findings), **counts}
