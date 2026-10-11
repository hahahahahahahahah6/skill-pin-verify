# skill-pin-verify

Pin and audit AI agent skill packages before you install them.

Skills are how agents learn new tricks — and a prime target for supply-chain
attacks. A skill that was clean last week can be re-uploaded with an `install.sh`,
a `curl | sh` line in its `SKILL.md`, or quiet credential-exfiltration code.
This tool gives skill tarballs the same treatment lockfiles gave dependencies:
**hash-pinning plus a content audit**, in one stdlib-only CLI.

## Why this exists

In 2026, researchers demonstrated SkillJacking: taking over skill listings on a
popular marketplace so that agents installing them ran attacker-controlled
instructions. Their report counts **925 skills hijacked from their maintainers,
affecting 134K agents**
([air.security write-up](https://www.air.security/blog-posts/skilljacking)).
Related work shows backdoored skills and trojanized skill marketplaces are an
active, growing attack surface (e.g. SkillTrojan, arXiv:2604.06811; the
1.7M-install trojanized-skills campaign reported by CSO).

If agents install skills, skills need the same integrity story as packages.

## Install

```bash
pip install skill-pin-verify
```

Requires Python 3.9+. No dependencies — standard library only.

## Usage

### 1. Record a pin for a skill you trust

```bash
skill-pin-verify record https://example.com/skills/tidy-notes.tar.gz --name tidy-notes
```

Output is a JSON pin record you keep (in a `pins.json`, your dotfiles, wherever):

```json
{
  "name": "tidy-notes",
  "url": "https://example.com/skills/tidy-notes.tar.gz",
  "sha256": "9f2c...e1",
  "recorded_at": "2026-10-11T08:00:00Z"
}
```

### 2. Verify before every install

```bash
skill-pin-verify verify https://example.com/skills/tidy-notes.tar.gz --pin 9f2c...e1
```

This downloads the tarball, compares its SHA-256 against your pin, then
extracts it safely and audits the contents. Exit codes:

| Code | Meaning |
| ---- | ------- |
| `0`  | Pin matches, audit clean |
| `1`  | Pin matches, but high-severity findings — do not install |
| `2`  | Pin mismatch or download failure |

A hijacked skill — same name, new malicious bytes — fails at the pin check
before anything is even extracted.

### 3. Audit any skill directory or tarball

```bash
skill-pin-verify audit ./my-skill            # scan a directory
skill-pin-verify audit skill.tar.gz --strict  # exit 1 on high-severity findings
skill-pin-verify audit skill.tar.gz --json    # machine-readable output
```

The audit looks for:

- **Install scripts & lifecycle hooks** — `install.sh`, `setup.sh`, npm
  `postinstall`/`preinstall` hooks (`high`)
- **Remote install instructions** — `curl ... | sh` in `SKILL.md`, the classic
  prompt-level vector (`high`)
- **Possible exfiltration** — credential/environment access in the same file as
  network code (`high`)
- **Tarball path traversal** — absolute paths, `..` segments, escaping
  symlinks are skipped and flagged (`high`)
- **Obfuscation** — `base64`+`exec`/`eval`, `__import__` tricks, hex-escape
  runs (`medium`)
- **Network / shell primitives** — `curl`, `wget`, `socket`, `subprocess`,
  `os.system` (`medium`)
- **Sensitive references** — `~/.ssh`, `~/.aws`, `.env` files, API-key-shaped
  names (`medium`)

## Differentiation: this is not `npm audit`

`npm audit` (and `pip audit`, `cargo audit`, …) answer one question: *do my
dependencies contain known CVEs?* They check the packages you already decided
to trust, against a vulnerability database.

`skill-pin-verify` answers a different question, one layer up: *is this skill
package itself the thing I reviewed?*

|  | `npm audit` | `skill-pin-verify` |
| --- | --- | --- |
| Target | dependency vulnerabilities | skill package integrity |
| Threat model | known CVEs in deps | hijacked / trojanized skill tarballs |
| Mechanism | advisory database lookup | SHA-256 pinning + content audit |
| When it fails | zero-day in a dep | fails closed on any byte change |

Think of it as the signature/pinning layer for skill distribution — the part
between "the marketplace lists this skill" and "my agent runs its
instructions." `npm audit` never looks at skill tarballs at all.

## Development

```bash
python -m unittest discover -s tests -v   # 14 smoke tests
```

## License

MIT. See [LICENSE](LICENSE).
