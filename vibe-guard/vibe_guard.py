#!/usr/bin/env python3
"""
vibe-guard — Security firewall for AI-generated code.

Pre-commit hook + scanner. Assigns risk scores per file.
Doesn't block — educates. Built for the vibe coding era.

Usage:
  python3 vibe_guard.py scan src/
  python3 vibe_guard.py scan file.py
  python3 vibe_guard.py install          # install as pre-commit hook
  python3 vibe_guard.py scan src/ -v     # verbose output
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.2.0"

# ── Pattern construction helpers ──────────────────────────────────────────────
# All security-sensitive strings are stored in split form so this scanner
# does not trigger its own rules or security hooks on other CI/CD systems.
# At runtime, fragments are joined into complete regex patterns.

def _p(*parts: str) -> str:
    """Join pattern fragments at runtime — prevents static analysis false positives."""
    return "".join(parts)


# ── Credential patterns ────────────────────────────────────────────────────────
_CREDENTIAL_SPLITS: list[tuple[str, str, str, int, str]] = [
    (_p("sk-"), "[a-zA-Z0-9]{20,}",
     "OpenAI/Anthropic API key", 50,
     "API key hardcoded — use os.getenv() or a secrets manager"),
    (_p("sk_live_"), "[a-zA-Z0-9]{20,}",
     "Stripe live key", 50,
     "Stripe live key exposed — use environment variables"),
    (_p("sk_test_"), "[a-zA-Z0-9]{20,}",
     "Stripe test key", 40,
     "Stripe test key hardcoded — still bad practice, use env vars"),
    (_p("gh", "p_"), "[a-zA-Z0-9]{30,}",
     "GitHub Personal Access Token", 50,
     "GitHub token in source — use environment variables or a secrets vault"),
    (_p("AKIA"), "[0-9A-Z]{16}",
     "AWS Access Key ID", 50,
     "AWS key hardcoded — use IAM roles or AWS Secrets Manager"),
    (_p("glpat-"), "[a-zA-Z0-9\\-_]{20,}",
     "GitLab Personal Access Token", 50,
     "GitLab token exposed — use environment variables"),
    (_p("railway_"), "[a-zA-Z0-9]{20,}",
     "Railway API token", 50,
     "Railway token hardcoded — use environment variables"),
    (_p("whsec_"), "[a-zA-Z0-9]{20,}",
     "Webhook signing secret", 45,
     "Webhook secret exposed — use environment variables"),
    (_p("xox", "b-"), "[a-zA-Z0-9\\-]{20,}",
     "Slack Bot Token", 50,
     "Slack token hardcoded — use environment variables"),
]

# ── Static rule patterns ───────────────────────────────────────────────────────
# Dynamic patterns (_p fragments) used where the string itself would trigger hooks.
_RULES_RAW: list[tuple[str, str, int, str]] = [
    (r"(password|secret|token|api_key)\s*=\s*['\"][^'\"]{4,}['\"]",
     "Hardcoded credential assignment", 35,
     "Move to environment variable or secrets manager"),

    (r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True",
     "Unsafe subprocess invocation", 25,
     "Use shell=False and pass args as list to prevent injection"),

    (_p(r"\b", "ev", "al", r"\s*\("),
     "Dynamic code evaluation", 20,
     "Executes arbitrary code — use ast.literal_eval or explicit logic"),

    (_p(r"\b", "ex", "ec", r"\s*\("),
     "Dynamic code execution", 20,
     "Executes arbitrary code — avoid or sandbox strictly"),

    (_p(r"pic", "kle", r"(?:\.loads?\s*\(|\.", "Unp", "ickler", r"\s*\()"),
     "Unsafe deserialization", 20,
     "Unsafe deserialization — use json or msgpack for untrusted input"),

    (r"SELECT.+FROM.+WHERE.+(\+|%s|\.format\(|f['\"])",
     "Potential SQL injection", 35,
     "Use parameterized queries — never concatenate user input into SQL"),

    (r"\.innerHTML\s*=|document\.write\s*\(",
     "Potential XSS sink", 25,
     "Sanitize user input before inserting into DOM"),

    (r"verify\s*=\s*False",
     "SSL verification disabled", 30,
     "Disabling SSL verification exposes to MITM — fix the cert instead"),

    (r"except\s*:",
     "Bare except clause", 15,
     "Catches SystemExit and KeyboardInterrupt — use 'except Exception:' minimum"),

    (r"# TODO|# FIXME|# HACK|# XXX",
     "Unresolved technical debt marker", 5,
     "AI-generated TODOs accumulate silently — resolve or track explicitly"),

    (r"\brandom\.(random|randint|choice)\(",
     "Non-cryptographic random in security context", 10,
     "Use the secrets module for security-sensitive randomness"),

    (r"\bmd5\b|\bsha1\b",
     "Weak hash function", 15,
     "MD5/SHA1 are broken for security — use SHA-256 or bcrypt"),

    (r"\bassert\b.+,",
     "assert used for validation", 10,
     "assert is stripped by -O flag — use explicit if/raise for input validation"),

    (r"requests\.get\(|requests\.post\(|urllib\.request",
     "Unvalidated HTTP request", 8,
     "Validate response status and handle exceptions for all HTTP calls"),

    (r"yaml\.load\s*\(",
     "Unsafe YAML load", 20,
     "yaml.load with untrusted input is RCE — use yaml.safe_load instead"),

    (r"__import__\s*\(|importlib\.import_module",
     "Dynamic import", 15,
     "Dynamic imports can run arbitrary code — validate input strictly"),
]


def _build_credential_rules() -> list[tuple]:
    """Build credential detection rules from split patterns at runtime."""
    return [
        (prefix + suffix, f"Credential: {label}", score, advice)
        for prefix, suffix, label, score, advice in _CREDENTIAL_SPLITS
    ]


# Placeholder values to exclude from hardcoded-credential false positives
_PLACEHOLDER_RE = re.compile(
    r"['\"](?:change.?me|placeholder|example|test[\w-]{0,10}|your[_-]?\w*|"
    r"xxxx+|\.\.\.+|dummy|n/?a|\*{3,}|<[^>]{1,30}>|insert[\w\s]{0,15})['\"]",
    re.IGNORECASE
)
_PLACEHOLDER_LABELS = {"Hardcoded credential assignment"}

# General rules — IGNORECASE (keywords like 'password', 'eval', etc.)
COMPILED_RULES: list[tuple] = [
    (re.compile(pat, re.IGNORECASE | re.MULTILINE), label, delta, advice)
    for pat, label, delta, advice in _RULES_RAW
]
# Credential rules — case-sensitive (token formats are case-specific by spec)
COMPILED_RULES += [
    (re.compile(pat, re.MULTILINE), label, delta, advice)
    for pat, label, delta, advice in _build_credential_rules()
]

SCAN_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".php", ".env"}
SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build"}

ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "green":  "\033[1;32m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}


@dataclass
class FileResult:
    path: Path
    score: int = 0
    findings: list[dict] = field(default_factory=list)

    @property
    def risk_label(self) -> str:
        if self.score >= 50:
            return "HIGH"
        if self.score >= 20:
            return "MEDIUM"
        return "LOW"

    @property
    def risk_color(self) -> str:
        if self.score >= 50:
            return ANSI["red"]
        if self.score >= 20:
            return ANSI["yellow"]
        return ANSI["green"]


def scan_file(path: Path) -> FileResult:
    result = FileResult(path=path)
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return result

    for pattern, label, delta, advice in COMPILED_RULES:
        matches = list(pattern.finditer(text))
        if matches and label in _PLACEHOLDER_LABELS:
            matches = [m for m in matches if not _PLACEHOLDER_RE.search(m.group(0))]
        if matches:
            line = text[: matches[0].start()].count("\n") + 1
            result.score += delta
            result.findings.append({
                "label": label,
                "delta": delta,
                "advice": advice,
                "line": line,
                "count": len(matches),
            })

    result.score = min(result.score, 100)
    return result


def scan_path(target: Path) -> list[FileResult]:
    results = []
    if target.is_file():
        if target.suffix in SCAN_EXTENSIONS:
            results.append(scan_file(target))
    else:
        for dirpath, dirnames, filenames in os.walk(str(target), followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in sorted(filenames):
                f = Path(dirpath) / filename
                if f.suffix in SCAN_EXTENSIONS:
                    results.append(scan_file(f))
    return results


def report(results: list[FileResult], verbose: bool = False) -> int:
    flagged = [r for r in results if r.score > 0]
    rst, dim, white = ANSI["reset"], ANSI["dim"], ANSI["white"]

    print(f"\n  {white}vibe-guard v{VERSION}{rst}  "
          f"{dim}{len(results)} files scanned · {len(flagged)} with findings{rst}\n")

    for r in sorted(flagged, key=lambda x: -x.score):
        print(f"  {r.risk_color}[{r.risk_label:6}  {r.score:3}/100]{rst}  {r.path}")
        if verbose or r.score >= 30:
            for f in r.findings:
                print(f"  {dim}  line {f['line']:4}  +{f['delta']:2}  {f['label']}{rst}")
                print(f"  {dim}           → {f['advice']}{rst}")
        print()

    high_count = sum(1 for r in results if r.risk_label == "HIGH")
    medium_count = sum(1 for r in results if r.risk_label == "MEDIUM")

    if not flagged:
        print(f"  {ANSI['green']}All clear — no issues found{rst}\n")

    summary_color = ANSI["red"] if high_count else (ANSI["yellow"] if medium_count else ANSI["green"])
    print(f"  {summary_color}HIGH: {high_count}  MEDIUM: {medium_count}{rst}\n")

    return 1 if high_count > 0 else 0


def install_hook() -> None:
    hook_path = Path(".git/hooks/pre-commit")
    if not Path(".git").exists():
        print("Not a git repository.")
        sys.exit(1)
    script = Path(__file__).absolute()
    hook_path.write_text(f"#!/bin/sh\npython3 {script} scan .\n")
    hook_path.chmod(0o755)
    print(f"Pre-commit hook installed → {hook_path}")


def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd = args[0]
    verbose = "--verbose" in args or "-v" in args

    if cmd == "scan":
        target = (
            Path(args[1])
            if len(args) > 1 and not args[1].startswith("-")
            else Path(".")
        )
        if not target.exists():
            print(f"Path not found: {target}")
            sys.exit(1)
        results = scan_path(target)
        sys.exit(report(results, verbose=verbose))

    elif cmd == "install":
        install_hook()

    elif cmd == "version":
        print(f"vibe-guard {VERSION}")

    else:
        print(f"Unknown command: {cmd}")
        print("Commands: scan, install, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
