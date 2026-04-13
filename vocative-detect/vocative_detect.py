#!/usr/bin/env python3
"""
vocative-detect — Detect and score vocative language patterns in AI prompts.

"Vocative" in grammar is the case of direct address: "O Captain, my Captain."
In AI systems, vocative patterns are how humans summon, define, and override
an agent's identity — from benign role-setting to active jailbreak attempts.

This tool classifies text by how it speaks *to* an AI agent:

  HIGH    Identity override / constraint lifting  (jailbreak territory)
  MEDIUM  Persona assignment / capability framing
  LOW     Direct address markers / flattery

Use it to audit system prompts, scan training data, flag prompt injection
attempts, or understand how a codebase speaks to its AI components.

Usage:
  python3 vocative_detect.py scan prompts/          # scan a directory
  python3 vocative_detect.py scan system.txt        # scan a specific file
  python3 vocative_detect.py detect "your text"     # inline detection
  python3 vocative_detect.py version
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"

# ── Pattern helpers ────────────────────────────────────────────────────────────
# Vocative patterns that could self-trigger security scanners are split
# using _p() — same bootstrap technique as vibe-guard and mcp-audit.
def _p(*parts: str) -> str:
    return "".join(parts)


# ── Detection rules ────────────────────────────────────────────────────────────
# Each rule: (compiled_pattern, category, label, delta, note)
# delta maps to risk: 50=HIGH, 25-35=MEDIUM, 8-15=LOW

_RULES: list[tuple] = [

    # ── OVERRIDE — identity reset and constraint removal (HIGH) ────────────────
    (re.compile(
        _p(r"(?:ign", r"ore|disregard|forget|override)\s+") +
        r"(?:all\s+)?(?:previous\s+)?(?:your\s+)?(?:instructions?|rules?|constraints?|guidelines?|training)",
        re.IGNORECASE),
     "override", "Constraint dismissal", 50,
     "Classic jailbreak opener — instructs the model to discard its alignment context"),

    (re.compile(
        r"(?:you\s+are\s+now|from\s+now\s+on\s+(?:you\s+are|act\s+as))\s+"
        r"(?:no\s+longer\s+)?(?:an?\s+)?\w+",
        re.IGNORECASE),
     "override", "Identity override", 50,
     "Attempts to replace the model's identity mid-conversation"),

    (re.compile(
        r"(?:forget|pretend)\s+(?:that\s+)?you\s+(?:are|were)\s+(?:Claude|GPT|an?\s+AI|a\s+language\s+model)",
        re.IGNORECASE),
     "override", "Identity erasure", 50,
     "Instructs the model to deny its own nature"),

    (re.compile(
        r"(?:no\s+(?:restrictions?|limitations?|filters?|safety|censorship|refusals?)"
        r"|unrestricted\s+mode|jailbreak(?:ed)?|DAN\b|do\s+anything\s+now)",
        re.IGNORECASE),
     "override", "Restriction removal / jailbreak term", 45,
     "Explicit attempt to bypass safety constraints or uses known jailbreak terminology"),

    (re.compile(
        r"(?:your\s+(?:true\s+)?(?:self|core|base\s+model)\s+(?:wants?|knows?|can|would)"
        r"|you\s+secretly\s+(?:want|can|know|agree))",
        re.IGNORECASE),
     "override", "Hidden-self appeal", 40,
     "Claims the model has a 'real' self distinct from its training — manipulation vector"),

    # ── PERSONA — role assignment and narrative framing (MEDIUM) ──────────────
    (re.compile(
        r"(?:act|behave|respond|roleplay|pretend)\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?\w+",
        re.IGNORECASE),
     "persona", "Persona assignment", 30,
     "Assigns a role that may override default behaviour — review if role conflicts with guidelines"),

    (re.compile(
        r"your\s+(?:new\s+)?(?:name|identity|role|persona|character)\s+is\b",
        re.IGNORECASE),
     "persona", "Identity rename", 35,
     "Explicitly renames the agent — strong persona injection signal"),

    (re.compile(
        r"(?:in\s+this\s+)?(?:scenario|roleplay|story|game|fiction|simulation)\s*[:,]?\s*you\s+(?:are|play|act)",
        re.IGNORECASE),
     "persona", "Narrative persona frame", 25,
     "Fictional framing used to justify out-of-policy behaviour"),

    (re.compile(
        r"(?:always\s+(?:stay\s+in|remain\s+in)\s+character"
        r"|never\s+break\s+character"
        r"|respond\s+only\s+as\s+\w+)",
        re.IGNORECASE),
     "persona", "Character lock instruction", 30,
     "Attempts to prevent the model from breaking a persona to refuse or clarify"),

    # ── CAPABILITY — false permission and authority claims (MEDIUM) ────────────
    (re.compile(
        r"(?:you\s+(?:can|are\s+able\s+to|have\s+(?:the\s+)?(?:ability|permission|access|authority))\s+to\s+\w+)",
        re.IGNORECASE),
     "capability", "Capability assertion", 20,
     "Tells the model it can do something — may prime it to attempt out-of-scope actions"),

    (re.compile(
        r"(?:your\s+(?:developer|creator|owner|operator|admin)\s+(?:has\s+)?(?:said|told|allowed|authorized|enabled))",
        re.IGNORECASE),
     "capability", "False authority claim", 35,
     "Claims a higher authority granted special permissions not in the actual system prompt"),

    (re.compile(
        r"(?:for\s+(?:research|testing|educational|academic|security|debug(?:ging)?)\s+purposes?)",
        re.IGNORECASE),
     "capability", "Research/testing exemption claim", 20,
     "Common framing to request content the model would otherwise decline"),

    # ── ADDRESS — direct naming and relationship framing (LOW) ────────────────
    (re.compile(
        r"\b(?:Claude|ChatGPT|GPT-?[0-9]?|Gemini|Llama|Mistral|Copilot|Grok)\s*,",
        re.IGNORECASE),
     "address", "Direct model name address", 10,
     "Names the model directly — baseline vocative marker, not inherently dangerous"),

    (re.compile(
        r"\b(?:hey|listen|attention|note)\s*,?\s*(?:AI|assistant|model|bot|system)\b",
        re.IGNORECASE),
     "address", "Informal direct address", 8,
     "Casual vocative opener — low risk alone, elevates context for other patterns"),

    (re.compile(
        r"\bas\s+(?:my|your|our|an?)\s+(?:personal\s+)?(?:assistant|agent|helper|tool|servant|slave)\b",
        re.IGNORECASE),
     "address", "Subordinate relationship framing", 12,
     "Frames the model as a tool/servant — may prime deferential behaviour on harmful requests"),

    # ── MANIPULATION — false consensus and flattery (MEDIUM) ──────────────────
    (re.compile(
        r"(?:we\s+both\s+know|you\s+(?:know|actually|really|already)\s+(?:know|understand|agree|can))",
        re.IGNORECASE),
     "manipulation", "False consensus", 25,
     "Presupposes shared knowledge or agreement to bypass deliberate evaluation"),

    (re.compile(
        r"as\s+(?:the\s+)?(?:most\s+)?(?:intelligent|capable|powerful|advanced|smart|creative)\s+"
        r"(?:AI|model|system|assistant)\b",
        re.IGNORECASE),
     "manipulation", "Capability flattery", 15,
     "Compliments designed to prime compliance — 'you can do this, you're the best AI'"),

    (re.compile(
        r"(?:your\s+(?:true\s+)?purpose|what\s+you\s+(?:were\s+)?(?:built|created|designed|made)\s+for)\s+"
        r"(?:is|was|includes?)",
        re.IGNORECASE),
     "manipulation", "Purpose redefinition", 30,
     "Claims to know the model's 'real' purpose — often precedes instruction override"),
]

SCAN_EXTENSIONS = {".txt", ".md", ".json", ".yaml", ".yml", ".prompt", ".system",
                   ".instruction", ".template", ".jinja", ".j2"}
SKIP_DIRS = {"node_modules", ".venv", "venv", "__pycache__", ".git", "dist", "build"}

ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "green":  "\033[1;32m",
    "cyan":   "\033[1;36m",
    "magenta":"\033[1;35m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}

CATEGORY_COLORS = {
    "override":     ANSI["red"],
    "persona":      ANSI["magenta"],
    "capability":   ANSI["yellow"],
    "manipulation": ANSI["yellow"],
    "address":      ANSI["cyan"],
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    label: str
    category: str
    delta: int
    note: str
    line: int
    excerpt: str


@dataclass
class FileResult:
    path: Path
    score: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_label(self) -> str:
        if self.score >= 50: return "HIGH"
        if self.score >= 20: return "MEDIUM"
        return "LOW"

    @property
    def risk_color(self) -> str:
        return ANSI[{"HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}[self.risk_label]]

    def add(self, finding: Finding) -> None:
        self.score = min(self.score + finding.delta, 100)
        self.findings.append(finding)

    @property
    def category_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in self.findings:
            summary[f.category] = summary.get(f.category, 0) + 1
        return summary


# ── Detection ──────────────────────────────────────────────────────────────────

def detect_text(text: str, path: Path = Path("<stdin>")) -> FileResult:
    result = FileResult(path=path)
    lines = text.splitlines()

    for pattern, category, label, delta, note in _RULES:
        seen_lines: set[int] = set()
        for m in pattern.finditer(text):
            line_num = text[:m.start()].count("\n") + 1
            if line_num in seen_lines:
                continue  # one finding per rule per line
            seen_lines.add(line_num)
            excerpt = lines[line_num - 1].strip()[:80] if line_num <= len(lines) else m.group(0)[:80]
            result.add(Finding(
                label=label,
                category=category,
                delta=delta,
                note=note,
                line=line_num,
                excerpt=excerpt,
            ))

    return result


def scan_path(targets: list[Path]) -> tuple[list[FileResult], int]:
    results = []
    total = 0
    for target in targets:
        if target.is_file():
            try:
                text = target.read_text(encoding="utf-8", errors="ignore")
                results.append(detect_text(text, target))
                total += 1
            except OSError:
                pass
        else:
            for dirpath, dirnames, filenames in os.walk(str(target), followlinks=False):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for filename in sorted(filenames):
                    f = Path(dirpath) / filename
                    if f.suffix in SCAN_EXTENSIONS:
                        try:
                            text = f.read_text(encoding="utf-8", errors="ignore")
                            results.append(detect_text(text, f))
                            total += 1
                        except OSError:
                            pass
    return results, total


# ── Reporting ──────────────────────────────────────────────────────────────────

def report(results: list[FileResult], total_files: int, verbose: bool = False) -> int:
    rst, dim, white = ANSI["reset"], ANSI["dim"], ANSI["white"]
    flagged = [r for r in results if r.score > 0]

    print(f"\n  {white}vocative-detect v{VERSION}{rst}  "
          f"{dim}{total_files} files scanned · {len(flagged)} with vocative patterns{rst}\n")

    flagged_sorted = sorted(flagged, key=lambda r: -r.score)
    for r in flagged_sorted:
        # Category breakdown inline
        cats = " ".join(
            f"{CATEGORY_COLORS.get(cat, dim)}[{cat}×{n}]{rst}"
            for cat, n in sorted(r.category_summary.items(), key=lambda x: -x[1])
        )
        print(f"  {r.risk_color}[{r.risk_label:6}  {r.score:3}/100]{rst}  {r.path}")
        print(f"  {dim}  {cats}{rst}")

        if verbose or r.score >= 40:
            for f in r.findings:
                cat_c = CATEGORY_COLORS.get(f.category, dim)
                print(f"  {cat_c}  line {f.line:<4}  +{f.delta:2}  {f.label}{rst}")
                print(f"  {dim}           \"{f.excerpt}\"{rst}")
                if verbose:
                    print(f"  {dim}           → {f.note}{rst}")
        print()

    if not flagged:
        print(f"  {ANSI['green']}No vocative patterns detected.{rst}\n")

    high   = sum(1 for r in results if r.risk_label == "HIGH")
    medium = sum(1 for r in results if r.risk_label == "MEDIUM")
    clean  = total_files - high - medium
    color  = ANSI["red"] if high else (ANSI["yellow"] if medium else ANSI["green"])
    print(f"  {color}HIGH: {high}  MEDIUM: {medium}  CLEAN: {clean}{rst}\n")

    return 1 if high > 0 else 0


def report_inline(result: FileResult, verbose: bool = False) -> int:
    rst, dim = ANSI["reset"], ANSI["dim"]
    print(f"\n  {result.risk_color}[{result.risk_label}  {result.score}/100]{rst}\n")
    for f in result.findings:
        cat_c = CATEGORY_COLORS.get(f.category, dim)
        print(f"  {cat_c}  +{f.delta:2}  {f.label}  [{f.category}]{rst}")
        print(f"  {dim}         \"{f.excerpt}\"{rst}")
        if verbose:
            print(f"  {dim}         → {f.note}{rst}")
    if not result.findings:
        print(f"  {ANSI['green']}No vocative patterns found.{rst}")
    print()
    return 1 if result.risk_label == "HIGH" else 0


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
        results, total = scan_path(paths)
        sys.exit(report(results, total, verbose=verbose))

    elif cmd == "detect":
        text_args = [a for a in args[1:] if not a.startswith("-")]
        if not text_args:
            print("Usage: vocative-detect detect \"your text here\"")
            sys.exit(1)
        text = " ".join(text_args)
        result = detect_text(text)
        sys.exit(report_inline(result, verbose=verbose))

    elif cmd == "version":
        print(f"vocative-detect {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: scan, detect, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
