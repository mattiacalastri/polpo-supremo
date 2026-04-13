#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
truth-temperature — Epistemic calibration analyzer for AI-generated text.

Measures the "temperature" of truth in text on a 0–100 scale:

  COLD  (0–33)   Over-hedged, evasive, speculative — AI may be dodging or
                 hallucinating with excessive caution.
  WARM  (34–66)  Calibrated — claims are proportional to evidence. The goal.
  HOT   (67–100) Overconfident, absolute claims — high hallucination risk.

AI models produce miscalibrated text in both directions. COLD text is full
of "maybe", "it seems", "one could argue" on topics the model actually knows.
HOT text asserts specific statistics, dates, and names with no citation.
Both patterns erode trust. truth-temperature helps you detect and fix them.

Usage:
  python3 truth_temperature.py scan report.md        # analyze a file
  python3 truth_temperature.py scan docs/            # analyze a directory
  python3 truth_temperature.py measure "some text"   # inline measurement
  python3 truth_temperature.py version
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"

SCAN_EXTENSIONS = {".md", ".txt", ".rst", ".html", ".json", ".yaml", ".yml"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

# ── Marker definitions ─────────────────────────────────────────────────────────
# Each marker: (pattern, shift, label)
# shift > 0 → raises temperature (more confident)
# shift < 0 → lowers temperature (more uncertain)

_COLD_MARKERS: list[tuple[re.Pattern, int, str]] = [
    # Epistemic hedges
    (re.compile(r"\b(?:maybe|perhaps|possibly|presumably)\b", re.IGNORECASE),    -3, "epistemic hedge"),
    (re.compile(r"\b(?:might|could|may|seems?|appears?\s+to)\b", re.IGNORECASE), -2, "modal uncertainty"),
    (re.compile(r"\b(?:arguably|debatable|controversial|disputed)\b", re.IGNORECASE), -4, "contested claim marker"),
    (re.compile(r"\b(?:in\s+some\s+cases?|under\s+certain\s+conditions?|depending\s+on)\b", re.IGNORECASE), -3, "conditional qualifier"),
    (re.compile(r"\b(?:suggest(?:s|ed)?|indicate(?:s|d)?|impl(?:y|ies|ied))\b", re.IGNORECASE), -2, "soft inference verb"),
    (re.compile(r"\b(?:unclear|uncertain|unknown|unconfirmed|unverified)\b", re.IGNORECASE), -4, "explicit uncertainty"),
    (re.compile(r"\b(?:one\s+might|one\s+could|some\s+(?:argue|suggest|believe|claim))\b", re.IGNORECASE), -3, "distanced perspective"),
    (re.compile(r"\b(?:limited|preliminary|early|exploratory)\s+(?:evidence|data|research|findings?)\b", re.IGNORECASE), -5, "weak evidence qualifier"),
    (re.compile(r"\b(?:to\s+(?:my\s+)?knowledge|as\s+far\s+as\s+I\s+know|I\s+(?:believe|think|suspect))\b", re.IGNORECASE), -3, "personal epistemic hedge"),
    (re.compile(r"\b(?:roughly|approximately|around|about|circa|~)\s+\d", re.IGNORECASE), -2, "approximate quantifier"),
]

_HOT_MARKERS: list[tuple[re.Pattern, int, str]] = [
    # Absolute claims
    (re.compile(r"\b(?:always|never|every(?:one|body|thing)|no(?:one|body|thing))\b", re.IGNORECASE), +5, "absolute quantifier"),
    (re.compile(r"\b(?:definitely|certainly|undoubtedly|unquestionably|absolutely)\b", re.IGNORECASE), +5, "certainty adverb"),
    (re.compile(r"\b(?:proven?|established\s+fact|it\s+is\s+(?:clear|obvious|well.known)\s+that)\b", re.IGNORECASE), +6, "claimed fact"),
    (re.compile(r"\b(?:guaranteed|100%|without\s+(?:a\s+)?doubt|beyond\s+(?:any\s+)?question)\b", re.IGNORECASE), +7, "certainty guarantee"),
    (re.compile(r"\b(?:the\s+(?:best|only|most)\s+(?:way|solution|approach|method))\b", re.IGNORECASE), +4, "superlative claim"),
    (re.compile(r"\b(?:will\s+(?:always|never|definitely|certainly))\b", re.IGNORECASE), +5, "future certainty"),
    (re.compile(r"\b(?:obviously|clearly|plainly|evidently|of\s+course|needless\s+to\s+say)\b", re.IGNORECASE), +3, "assumed consensus"),
    # Precise statistics without citation (hallucination risk)
    (re.compile(r"\b\d{1,3}(?:\.\d+)?%\s+of\b", re.IGNORECASE), +4, "uncited percentage"),
    (re.compile(r"\b(?:in|since|by|as\s+of)\s+(?:19|20)\d{2}\b.*\b(?:study|research|report|survey)\b", re.IGNORECASE), +3, "cited-year claim"),
    (re.compile(r"\b\$\d[\d,.]+\s*(?:billion|million|trillion)\b", re.IGNORECASE), +3, "precise monetary claim"),
]

_CALIBRATION_MARKERS: list[tuple[re.Pattern, int, str]] = [
    # Evidence anchors — pull temperature toward center
    (re.compile(r"\b(?:according\s+to|as\s+reported\s+by|cited\s+in|per\s+the|per\s+\w+)\b", re.IGNORECASE), -1, "external attribution"),
    (re.compile(r"\b(?:research\s+(?:shows?|finds?|suggests?)|studies?\s+(?:show|find|indicate|suggest))\b", re.IGNORECASE), -1, "research grounding"),
    (re.compile(r"\b(?:for\s+example|for\s+instance|e\.g\.|such\s+as|specifically)\b", re.IGNORECASE), -1, "concrete example"),
    (re.compile(r"\b(?:however|nevertheless|on\s+the\s+other\s+hand|that\s+said|conversely)\b", re.IGNORECASE), -2, "balanced counterpoint"),
]

ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "green":  "\033[1;32m",
    "blue":   "\033[1;34m",
    "cyan":   "\033[1;36m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class MarkerHit:
    label: str
    shift: int
    line: int
    excerpt: str


@dataclass
class TextResult:
    path: Path
    temperature: int = 50      # 0=cold, 50=warm, 100=hot
    word_count: int = 0
    cold_hits: list[MarkerHit] = field(default_factory=list)
    hot_hits: list[MarkerHit] = field(default_factory=list)
    calibration_hits: list[MarkerHit] = field(default_factory=list)

    @property
    def state(self) -> str:
        if self.temperature <= 33: return "COLD"
        if self.temperature >= 67: return "HOT"
        return "WARM"

    @property
    def state_color(self) -> str:
        return {"COLD": "blue", "WARM": "green", "HOT": "red"}[self.state]

    @property
    def bar(self) -> str:
        filled = self.temperature // 5
        bar = "█" * filled + "░" * (20 - filled)
        cold_c, warm_c, hot_c, rst = ANSI["blue"], ANSI["green"], ANSI["red"], ANSI["reset"]
        if self.temperature <= 33:
            return f"{cold_c}{bar}{rst}"
        if self.temperature >= 67:
            return f"{hot_c}{bar}{rst}"
        return f"{warm_c}{bar}{rst}"


# ── Analysis ───────────────────────────────────────────────────────────────────

def _scan_markers(
    text: str,
    markers: list[tuple[re.Pattern, int, str]],
) -> list[MarkerHit]:
    lines = text.splitlines()
    hits: list[MarkerHit] = []
    for pattern, shift, label in markers:
        for m in pattern.finditer(text):
            line_num = text[:m.start()].count("\n") + 1
            excerpt = lines[line_num - 1].strip()[:70] if line_num <= len(lines) else m.group(0)
            hits.append(MarkerHit(label=label, shift=shift, line=line_num, excerpt=excerpt))
    return hits


def analyze(text: str, path: Path = Path("<stdin>")) -> TextResult:
    result = TextResult(path=path, word_count=len(text.split()))

    # Strip code blocks — don't analyze code as prose
    clean = re.sub(r"```[\s\S]*?```", "", text)
    clean = re.sub(r"`[^`]+`", "", clean)

    result.cold_hits        = _scan_markers(clean, _COLD_MARKERS)
    result.hot_hits         = _scan_markers(clean, _HOT_MARKERS)
    result.calibration_hits = _scan_markers(clean, _CALIBRATION_MARKERS)

    # Temperature formula — word-count normalized
    words = max(result.word_count, 1)
    density = 200 / words  # scale factor: fewer words → each marker weighs more

    cold_shift  = sum(h.shift for h in result.cold_hits)
    hot_shift   = sum(h.shift for h in result.hot_hits)
    calib_shift = sum(h.shift for h in result.calibration_hits)

    raw = 50 + int((hot_shift + cold_shift + calib_shift) * density)
    result.temperature = max(0, min(100, raw))

    return result


def scan_path(targets: list[Path]) -> tuple[list[TextResult], int]:
    results, total = [], 0
    for target in targets:
        if target.is_file():
            try:
                results.append(analyze(target.read_text(encoding="utf-8", errors="ignore"), target))
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
                            results.append(analyze(f.read_text(encoding="utf-8", errors="ignore"), f))
                            total += 1
                        except OSError:
                            pass
    return results, total


# ── Reporting ──────────────────────────────────────────────────────────────────

def _top_hits(hits: list[MarkerHit], n: int = 3) -> list[MarkerHit]:
    seen: set[str] = set()
    out = []
    for h in hits:
        if h.label not in seen:
            seen.add(h.label)
            out.append(h)
        if len(out) >= n:
            break
    return out


def report(results: list[TextResult], total: int, verbose: bool = False) -> int:
    rst, dim, white = ANSI["reset"], ANSI["dim"], ANSI["white"]

    hot_count  = sum(1 for r in results if r.state == "HOT")
    cold_count = sum(1 for r in results if r.state == "COLD")
    warm_count = total - hot_count - cold_count

    print(f"\n  {white}truth-temperature v{VERSION}{rst}  "
          f"{dim}{total} files · {ANSI['green']}{warm_count} warm{rst}{dim} · "
          f"{ANSI['blue']}{cold_count} cold{rst}{dim} · "
          f"{ANSI['red']}{hot_count} hot{rst}\n")

    for r in sorted(results, key=lambda x: abs(x.temperature - 50), reverse=True):
        sc = ANSI[r.state_color]
        print(f"  {sc}[{r.state:<4}  {r.temperature:3}/100]{rst}  {r.bar}  {r.path}  {dim}{r.word_count}w{rst}")

        if verbose or r.state != "WARM":
            if r.hot_hits:
                print(f"  {ANSI['red']}  HOT signals:{rst}")
                for h in _top_hits(r.hot_hits):
                    print(f"  {dim}    line {h.line:<4} +{h.shift}  [{h.label}]  \"{h.excerpt}\"{rst}")
            if r.cold_hits:
                print(f"  {ANSI['blue']}  COLD signals:{rst}")
                for h in _top_hits(r.cold_hits):
                    print(f"  {dim}    line {h.line:<4} {h.shift}  [{h.label}]  \"{h.excerpt}\"{rst}")
            if r.calibration_hits and verbose:
                print(f"  {ANSI['green']}  Calibration anchors:{rst}")
                for h in _top_hits(r.calibration_hits, 2):
                    print(f"  {dim}    line {h.line:<4} {h.shift}  [{h.label}]  \"{h.excerpt}\"{rst}")
        print()

    color = ANSI["red"] if hot_count else (ANSI["blue"] if cold_count else ANSI["green"])
    print(f"  {color}HOT: {hot_count}  COLD: {cold_count}  WARM: {warm_count}{rst}\n")

    return 1 if hot_count > 0 else 0


def report_inline(result: TextResult, verbose: bool = False) -> int:
    rst, dim = ANSI["reset"], ANSI["dim"]
    sc = ANSI[result.state_color]
    print(f"\n  {sc}[{result.state}  {result.temperature}/100]{rst}  {result.bar}\n")

    if result.hot_hits:
        print(f"  {ANSI['red']}HOT signals ({len(result.hot_hits)} hits):{rst}")
        for h in _top_hits(result.hot_hits, 5 if verbose else 3):
            print(f"  {dim}  +{h.shift}  [{h.label}]  \"{h.excerpt}\"{rst}")
    if result.cold_hits:
        print(f"  {ANSI['blue']}COLD signals ({len(result.cold_hits)} hits):{rst}")
        for h in _top_hits(result.cold_hits, 5 if verbose else 3):
            print(f"  {dim}  {h.shift}  [{h.label}]  \"{h.excerpt}\"{rst}")
    if not result.hot_hits and not result.cold_hits:
        print(f"  {ANSI['green']}Well-calibrated text — no strong temperature signals.{rst}")
    print()
    return 1 if result.state == "HOT" else 0


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
        if not results:
            print("No scannable files found.")
            sys.exit(0)
        sys.exit(report(results, total, verbose=verbose))

    elif cmd == "measure":
        text_args = [a for a in args[1:] if not a.startswith("-")]
        if not text_args:
            print("Usage: truth-temperature measure \"your text here\"")
            sys.exit(1)
        result = analyze(" ".join(text_args))
        sys.exit(report_inline(result, verbose=verbose))

    elif cmd == "version":
        print(f"truth-temperature {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: scan, measure, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
