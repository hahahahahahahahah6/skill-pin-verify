"""Command-line interface for skill-pin-verify.

Subcommands:
  verify <tarball-url> --pin <sha256>   download, compare pin, then audit
  audit <path>                          scan a directory or tarball for tampering signals
  record <tarball-url> [--name]         download and print a JSON pin record
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from . import __version__
from .core import PinVerifyError, download, extract_to_temp, is_tarball, sha256_file, utc_now_iso
from .rules import audit_directory, summarize

EXIT_OK = 0          # pin matches, audit clean
EXIT_SUSPICIOUS = 1  # pin matches, but high-severity findings
EXIT_MISMATCH = 2    # pin mismatch or fatal error


def _print_findings(findings: list[dict], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"findings": findings, "summary": summarize(findings)}, indent=2))
        return
    summary = summarize(findings)
    print(f"findings: {summary['total']} (high={summary['high']}, medium={summary['medium']}, low={summary['low']})")
    for finding in findings:
        print(f"[{finding['severity'].upper():6}] {finding['path']} :: {finding['rule']}: {finding['detail']}")


def _audit_target(path: Path) -> tuple[list[dict], tempfile.TemporaryDirectory | None]:
    """Audit a directory or tarball. Returns (findings, tmpdir-to-keep-alive-or-None)."""
    if is_tarball(path):
        extracted, tmpdir, findings = extract_to_temp(path)
        findings = findings + audit_directory(extracted)
        return findings, tmpdir
    if path.is_dir():
        return audit_directory(path), None
    raise PinVerifyError(f"not a directory or tarball: {path}")


def cmd_verify(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="spv-verify-") as tmpdir:
        tarball = Path(tmpdir) / "skill.tar"
        try:
            download(args.tarball_url, tarball)
        except PinVerifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_MISMATCH

        actual = sha256_file(tarball)
        expected = args.pin.lower().strip()
        if actual != expected:
            print("PIN MISMATCH")
            print(f"  expected: {expected}")
            print(f"  actual:   {actual}")
            return EXIT_MISMATCH

        print(f"pin OK: sha256={actual}")
        findings, keepalive = _audit_target(tarball)
        _print_findings(findings, args.json)
        if keepalive is not None:
            keepalive.cleanup()
        high = summarize(findings)["high"]
        if high:
            print(f"warning: {high} high-severity finding(s); do not install this skill", file=sys.stderr)
            return EXIT_SUSPICIOUS
        print("audit clean: no high-severity findings")
        return EXIT_OK


def cmd_audit(args: argparse.Namespace) -> int:
    path = Path(args.path)
    try:
        findings, keepalive = _audit_target(path)
    except PinVerifyError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_MISMATCH
    _print_findings(findings, args.json)
    if keepalive is not None:
        keepalive.cleanup()
    if args.strict and summarize(findings)["high"]:
        return EXIT_SUSPICIOUS
    return EXIT_OK


def cmd_record(args: argparse.Namespace) -> int:
    with tempfile.TemporaryDirectory(prefix="spv-record-") as tmpdir:
        tarball = Path(tmpdir) / "skill.tar"
        try:
            download(args.tarball_url, tarball)
        except PinVerifyError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return EXIT_MISMATCH
        digest = sha256_file(tarball)
    record = {
        "name": args.name or Path(args.tarball_url.split("?")[0]).name,
        "url": args.tarball_url,
        "sha256": digest,
        "recorded_at": utc_now_iso(),
    }
    print(json.dumps(record, indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skill-pin-verify",
        description="Verify AI agent skill packages: pin tarballs by SHA-256 and scan for tampering signals.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_verify = sub.add_parser("verify", help="download a skill tarball, check its pin, then audit it")
    p_verify.add_argument("tarball_url", help="http(s)://, file://, or local path to the skill tarball")
    p_verify.add_argument("--pin", required=True, help="expected SHA-256 hex digest")
    p_verify.add_argument("--json", action="store_true", help="emit findings as JSON")
    p_verify.set_defaults(func=cmd_verify)

    p_audit = sub.add_parser("audit", help="scan a skill directory or tarball for tampering signals")
    p_audit.add_argument("path", help="path to a skill directory or tarball")
    p_audit.add_argument("--json", action="store_true", help="emit findings as JSON")
    p_audit.add_argument("--strict", action="store_true", help="exit 1 when high-severity findings exist")
    p_audit.set_defaults(func=cmd_audit)

    p_record = sub.add_parser("record", help="download a skill tarball and print a JSON pin record")
    p_record.add_argument("tarball_url", help="http(s)://, file://, or local path to the skill tarball")
    p_record.add_argument("--name", help="skill name for the pin record (default: tarball file name)")
    p_record.set_defaults(func=cmd_record)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
