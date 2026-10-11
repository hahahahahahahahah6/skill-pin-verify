"""skill-pin-verify: integrity verifier for AI agent skill packages.

Pin a skill tarball by SHA-256 and scan it for install hooks,
exfiltration code, obfuscation, and other signs of tampering.
Standard library only.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
