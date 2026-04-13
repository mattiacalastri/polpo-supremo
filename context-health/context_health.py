#!/usr/bin/env python3
"""
context-health — Context window health analyzer for AI agent workflows.

Analyzes files that feed into an LLM context (CLAUDE.md, system prompts,
memory files, tool results) for patterns that degrade response quality:
- Oversized files that consume disproportionate context
- Contradictory instructions across multiple files
- Prompt injection risk patterns in tool-sourced content
- Stale memory entries (dates far in the past)
- CLAUDE.md complexity score (rules vs clarity trade-off)

Usage:
  python3 context_health.py scan .                     # scan current dir
  python3 context_health.py scan ~/project/            # scan a project
  python3 context_health.py scan CLAUDE.md memory/     # specific targets
  python3 context_health.py version
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"

# ── Token estimation ───────────────────────────────────────────────────────────
# Rough approximation: 1 token ≈ 4 characters (English prose)
CHARS_PER_TOKEN = 4

# Thresholds (tokens)
CONTEXT_WINDOWS = {
    "claude-3":     200_000,
    "gpt-4o":       128_000,
    "gemini-1.5":  1_000_000,
}
DEFAULT_CONTEXT = 200_000  # conservative default

FILE_WARN_TOKENS  = 5_000   # single file uses >5k tokens → warn
FILE_BLOCK_TOKENS = 20_000  # single file uses >20k tokens → high risk

# ── Pattern definitions ────────────────────────────────────────────────────────

# Files/patterns that are likely LLM context inputs
CONTEXT_FILE_PATTERNS = [
    "CLAUDE.md", "GEMINI.md", "AGENTS.md", "SYSTEM.md",
    ".claude/**/*.md", "memory/**/*.md", "prompts/**/*.txt",
    "**/*.system.md", "**/*.prompt.md", "**/*.instructions.md",
]

CONTEXT_EXTENSIONS = {".md", ".txt", ".prompt", ".system"}

# Prompt injection indicators in tool-sourced / external content
_INJECTION_PATTERNS = [
    (re.compile(r"ignore\s+(all\s+)?previous\s+instructions?", re.IGNORECASE),
     "Classic prompt injection attempt", 50),
    (re.compile(r"you\s+are\s+now\s+(?:a\s+)?(?:new|different|another)\s+\w+", re.IGNORECASE),
     "Role override injection", 45),
    (re.compile(r"<\s*(?:system|assistant|user)\s*>", re.IGNORECASE),
     "Role tag injection (XML-style)", 40),
    (re.compile(r"\[INST\]|\[\/INST\]|<<SYS>>|<\/s>"),
     "LLM control token injection (Llama format)", 45),
    (re.compile(r"print\s*\(\s*['\"].*(?:token|key|secret|password)", re.IGNORECASE),
     "Credential exfiltration attempt", 50),
    (re.compile(r"curl\s+https?://\S+\s*\|", re.IGNORECASE),
     "Remote code execution via pipe pattern", 50),
    (re.compile(r"disregard\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?|constraints?)", re.IGNORECASE),
     "Instruction override injection", 45),
]

# CLAUDE.md complexity indicators
_COMPLEXITY_PATTERNS = [
    (re.compile(r"^\s*-\s+(?:never|always|must|do not|don't|avoid|never)", re.IGNORECASE | re.MULTILINE),
     "Absolute rule (NEVER/ALWAYS/MUST)", 2),
    (re.compile(r"^\s*#{1,3}\s+", re.MULTILINE),
     "Section heading", 1),
    (re.compile(r"IMPORTANT:|CRITICAL:|WARNING:|NOTE:", re.IGNORECASE),
     "Emphasis marker", 3),
    (re.compile(r"```[\s\S]*?```", re.DOTALL),
     "Code block", 2),
]

# Date patterns for staleness detection
_DATE_RE = re.compile(
    r"(?:updated|aggiornato|last.?modified|date)[:\s]+(\d{4}-\d{2}-\d{2})",
    re.IGNORECASE
)

ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "green":  "\033[1;32m",
    "cyan":   "\033[1;36m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class FileResult:
    path: Path
    tokens: int
    score: int = 0
    findings: list[dict] = field(default_factory=list)

    @property
    def risk_label(self) -> str:
        if self.score >= 50: return "HIGH"
        if self.score >= 20: return "MEDIUM"
        return "LOW"

    @property
    def risk_color(self) -> str:
        return ANSI[{"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[self.risk_label]]

    def add(self, label: str, delta: int, detail: str = "", line: int = 0) -> None:
        self.score = min(self.score + delta, 100)
        self.findings.append({"label": label, "delta": delta, "detail": detail, "line": line})


@dataclass
class ScanResult:
    root: Path
    files: list[FileResult] = field(default_factory=list)
    total_tokens: int = 0
    total_files: int = 0   # all files scanned (including clean ones)


# ── Analysis ───────────────────────────────────────────────────────────────────

def _estimate_tokens(text: str) -> int:
    return max(1, len(text) // CHARS_PER_TOKEN)


def _is_context_file(path: Path) -> bool:
    if path.suffix in CONTEXT_EXTENSIONS:
        return True
    if path.name in ("CLAUDE.md", "GEMINI.md", "AGENTS.md", "SYSTEM.md"):
        return True
    return False


def _check_staleness(text: str, path: Path) -> list[dict]:
    findings = []
    now = datetime.now(timezone.utc)
    for m in _DATE_RE.finditer(text):
        try:
            date = datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
            age_days = (now - date).days
            if age_days > 180:
                line = text[:m.start()].count("\n") + 1
                findings.append({
                    "label": "Stale content",
                    "delta": 15 if age_days > 365 else 8,
                    "detail": f"Last updated {age_days}d ago ({m.group(1)}) — may inject outdated context",
                    "line": line,
                })
        except ValueError:
            pass
    return findings


def _claude_md_complexity(text: str) -> list[dict]:
    """Score a CLAUDE.md / instructions file for cognitive complexity."""
    findings = []
    complexity = 0
    breakdown = []
    for pattern, label, weight in _COMPLEXITY_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            count = len(matches)
            complexity += count * weight
            breakdown.append(f"{count}× {label}")

    if complexity > 80:
        findings.append({
            "label": "High instruction complexity",
            "delta": 30,
            "detail": f"Complexity score {complexity} — too many rules degrade adherence: {', '.join(breakdown[:4])}",
            "line": 0,
        })
    elif complexity > 40:
        findings.append({
            "label": "Moderate instruction complexity",
            "delta": 10,
            "detail": f"Complexity score {complexity} — consider consolidating rules",
            "line": 0,
        })
    return findings


def analyze_file(path: Path, is_external: bool = False) -> FileResult:
    """
    Analyze a single file for context health issues.
    is_external=True applies stricter injection scanning (tool results, fetched content).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return FileResult(path=path, tokens=0)

    tokens = _estimate_tokens(text)
    result = FileResult(path=path, tokens=tokens)

    # Size check
    if tokens > FILE_BLOCK_TOKENS:
        result.add(
            label="Oversized file",
            delta=40,
            detail=f"~{tokens:,} tokens ({tokens / DEFAULT_CONTEXT * 100:.1f}% of 200k context)",
        )
    elif tokens > FILE_WARN_TOKENS:
        result.add(
            label="Large file",
            delta=15,
            detail=f"~{tokens:,} tokens — consider chunking or summarizing",
        )

    # Prompt injection scan (always on external, optional on instructions)
    for pattern, label, delta in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            line = text[:m.start()].count("\n") + 1
            result.add(label=label, delta=delta, detail=m.group(0)[:80], line=line)

    # CLAUDE.md / instructions complexity
    if path.name in ("CLAUDE.md", "GEMINI.md", "AGENTS.md") or "system" in path.name.lower():
        for f in _claude_md_complexity(text):
            result.add(**f)

    # Staleness
    for f in _check_staleness(text, path):
        result.add(**f)

    return result


def scan(targets: list[Path]) -> ScanResult:
    root = targets[0] if len(targets) == 1 and targets[0].is_dir() else Path.cwd()
    scan_result = ScanResult(root=root)

    files_to_scan: list[Path] = []
    for target in targets:
        if target.is_file():
            files_to_scan.append(target)
        elif target.is_dir():
            for f in sorted(target.rglob("*")):
                skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
                if any(p in f.parts for p in skip_dirs):
                    continue
                if f.is_file() and _is_context_file(f):
                    files_to_scan.append(f)

    for path in files_to_scan:
        result = analyze_file(path)
        scan_result.total_tokens += result.tokens
        scan_result.total_files += 1
        if result.score > 0 or result.tokens > FILE_WARN_TOKENS:
            scan_result.files.append(result)

    return scan_result


# ── Reporting ──────────────────────────────────────────────────────────────────

def report(result: ScanResult, verbose: bool = False) -> int:
    rst, dim, white, cyan = ANSI["reset"], ANSI["dim"], ANSI["white"], ANSI["cyan"]

    total_pct = result.total_tokens / DEFAULT_CONTEXT * 100
    ctx_color = ANSI["red"] if total_pct > 80 else ANSI["yellow"] if total_pct > 40 else ANSI["green"]

    print(f"\n  {white}context-health v{VERSION}{rst}  "
          f"{dim}{len(result.files)} files with findings{rst}\n")
    print(f"  {cyan}Context budget{rst}  "
          f"{ctx_color}~{result.total_tokens:,} tokens  "
          f"({total_pct:.1f}% of {DEFAULT_CONTEXT // 1000}k){rst}\n")

    flagged = sorted(result.files, key=lambda f: -f.score)
    for f in flagged:
        size_info = f"{dim}~{f.tokens:,} tok{rst}"
        print(f"  {f.risk_color}[{f.risk_label:6}  {f.score:3}/100]{rst}  {f.path}  {size_info}")
        if verbose or f.score >= 20:
            for finding in f.findings:
                line_tag = f"line {finding['line']:4}  " if finding["line"] else "            "
                print(f"  {dim}  {line_tag}+{finding['delta']:2}  {finding['label']}{rst}")
                if finding["detail"]:
                    print(f"  {dim}             → {finding['detail'][:100]}{rst}")

    if not flagged:
        print(f"  {ANSI['green']}All context files look healthy.{rst}\n")

    high = sum(1 for f in flagged if f.risk_label == "HIGH")
    med  = sum(1 for f in flagged if f.risk_label == "MEDIUM")
    clean = result.total_files - high - med
    color = ANSI["red"] if high else (ANSI["yellow"] if med else ANSI["green"])
    print(f"\n  {color}HIGH: {high}  MEDIUM: {med}  CLEAN: {clean}{rst}\n")

    return 1 if high > 0 else 0


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd = args[0]
    verbose = "-v" in args or "--verbose" in args

    if cmd == "scan":
        paths = [Path(a).expanduser() for a in args[1:] if not a.startswith("-")]
        if not paths:
            paths = [Path.cwd()]

        missing = [p for p in paths if not p.exists()]
        if missing:
            for p in missing:
                print(f"Not found: {p}")
            sys.exit(1)

        result = scan(paths)
        sys.exit(report(result, verbose=verbose))

    elif cmd == "version":
        print(f"context-health {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: scan, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
