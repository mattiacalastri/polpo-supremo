#!/usr/bin/env python3
"""
dream-engine — AI session capture and vault automation engine.

Transforms raw text — conversations, notes, ideas, transcripts — into
structured Markdown notes ready to drop into any vault (Obsidian, Logseq,
Notion export, or plain files).

dream-engine extracts:
  - Named entities (people, projects, dates, amounts, tools)
  - Action items and decisions
  - Cross-links to related concepts
  - A one-line summary

Output is a vault-ready .md file with YAML frontmatter.

Usage:
  python3 dream_engine.py capture "text or idea"           # from stdin
  python3 dream_engine.py capture session.txt              # from file
  python3 dream_engine.py capture session.txt --out vault/ # to directory
  python3 dream_engine.py extract note.md                  # re-extract entities
  python3 dream_engine.py batch transcripts/               # process directory
  python3 dream_engine.py version
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"

SCAN_EXTENSIONS = {".txt", ".md", ".log", ".transcript", ".session"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

ANSI = {
    "cyan":   "\033[1;36m",
    "green":  "\033[1;32m",
    "yellow": "\033[1;33m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}

# ── Entity extraction patterns ─────────────────────────────────────────────────

_PATTERNS = {
    # People: Capitalized First Last, or @mention
    "people": re.compile(
        r"(?:(?<!\w)@[\w]+|(?<!\w)[A-Z][a-z]{2,}\s+[A-Z][a-z]{2,}(?:\s+[A-Z][a-z]+)?)",
    ),
    # Dates: ISO, European, natural language
    "dates": re.compile(
        r"\b(?:\d{4}-\d{2}-\d{2}"
        r"|\d{1,2}[/-]\d{1,2}[/-]\d{2,4}"
        r"|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)"
        r"\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}"
        r"|(?:yesterday|today|tomorrow|next\s+\w+|last\s+\w+))\b",
        re.IGNORECASE
    ),
    # Amounts: currency + number
    "amounts": re.compile(
        r"(?:€|£|\$|USD|EUR|GBP)\s*\d[\d,.]+(?:\s*(?:k|K|M|B|billion|million|thousand))?"
        r"|\b\d[\d,.]+\s*(?:€|£|\$|USD|EUR|GBP)"
        r"|\b\d+(?:\.\d+)?\s*(?:percent|%)\b",
        re.IGNORECASE
    ),
    # Tools / tech: known keywords and patterns
    "tools": re.compile(
        r"\b(?:Claude|GPT|Gemini|Llama|Mistral|OpenAI|Anthropic"
        r"|Python|TypeScript|JavaScript|Go|Rust|Java"
        r"|Docker|Kubernetes|Railway|Supabase|n8n|Postgres|MySQL|Redis|MongoDB"
        r"|GitHub|GitLab|Vercel|AWS|GCP|Azure"
        r"|Obsidian|Notion|Logseq|Slack|Discord|Telegram"
        r"|FastAPI|Next\.?js|React|Vue|Svelte|Django|Flask)\b",
        re.IGNORECASE
    ),
    # Action items: task markers
    "actions": re.compile(
        r"(?:^|\n)\s*[-*•]\s*(?:\[\s*\]\s*)?(?:TODO|FIXME|ACTION|TASK|NEXT|DO|CHECK|REVIEW|SEND|CALL|EMAIL|BUILD|FIX|UPDATE|CREATE)[:,:]?\s*(.+?)(?:\n|$)",
        re.IGNORECASE
    ),
    # Decisions: decision markers
    "decisions": re.compile(
        r"(?:decided|decision|agreed|resolved|confirmed|chosen|will use|going with|we chose)\s*:?\s*(.{10,80}?)(?:[.!?\n]|$)",
        re.IGNORECASE
    ),
}

# Concepts that become wiki-links [[concept]]
_LINKABLE_CONCEPTS = re.compile(
    r"\b(?:strategy|roadmap|milestone|sprint|release|version|architecture"
    r"|meeting|call|demo|review|audit|deploy|launch|MVP|POC|prototype"
    r"|contract|invoice|proposal|client|customer|user|team|partner"
    r"|bug|issue|ticket|PR|commit|branch|merge|refactor"
    r"|API|webhook|pipeline|workflow|automation|integration"
    r"|revenue|MRR|ARR|churn|conversion|funnel|lead|deal"
    r"|onboarding|training|documentation|spec|RFC)\b",
    re.IGNORECASE
)

# Stop-words for entity deduplication
_STOP_PEOPLE = {
    "The", "This", "That", "These", "Those", "Some", "Many", "Each",
    "New", "Old", "Big", "High", "Low", "True", "False", "Good", "Bad",
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class Entities:
    people:    list[str] = field(default_factory=list)
    dates:     list[str] = field(default_factory=list)
    amounts:   list[str] = field(default_factory=list)
    tools:     list[str] = field(default_factory=list)
    actions:   list[str] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    links:     list[str] = field(default_factory=list)


@dataclass
class DreamNote:
    title: str
    summary: str
    body: str
    entities: Entities
    source: Path
    created_at: str


# ── Extraction ─────────────────────────────────────────────────────────────────

def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in items:
        key = item.strip().lower()
        if key not in seen and len(key) > 1:
            seen.add(key)
            out.append(item.strip())
    return out


def extract_entities(text: str) -> Entities:
    ents = Entities()

    # People
    raw_people = _PATTERNS["people"].findall(text)
    ents.people = _dedupe([
        p for p in raw_people
        if p not in _STOP_PEOPLE and not p.startswith("@")
    ] + [p for p in raw_people if p.startswith("@")])[:10]

    # Dates
    ents.dates = _dedupe(_PATTERNS["dates"].findall(text))[:5]

    # Amounts
    ents.amounts = _dedupe(_PATTERNS["amounts"].findall(text))[:8]

    # Tools
    ents.tools = _dedupe(_PATTERNS["tools"].findall(text))[:10]

    # Actions
    ents.actions = [
        m.group(1).strip()
        for m in _PATTERNS["actions"].finditer(text)
    ][:8]

    # Decisions
    ents.decisions = [
        m.group(1).strip()
        for m in _PATTERNS["decisions"].finditer(text)
    ][:5]

    # Wiki-links: unique concepts found in text
    ents.links = _dedupe(_LINKABLE_CONCEPTS.findall(text))[:12]

    return ents


def _generate_title(text: str, source: Path) -> str:
    """Derive a concise title from the first meaningful line."""
    for line in text.splitlines():
        line = line.strip().lstrip("#").strip()
        if len(line) > 10 and not line.startswith("---"):
            # Truncate at first sentence boundary
            for sep in (".", "!", "?", "—", " - "):
                if sep in line:
                    line = line[:line.index(sep)].strip()
                    break
            return line[:70]
    return source.stem.replace("_", " ").replace("-", " ").title()


def _generate_summary(text: str, ents: Entities) -> str:
    """One-line summary: first sentence + key entities."""
    first = ""
    for line in text.splitlines():
        line = line.strip().lstrip("#").strip()
        if len(line) > 20:
            for sep in (".", "!", "?"):
                if sep in line:
                    first = line[:line.index(sep) + 1].strip()
                    break
            if not first:
                first = line[:80]
            break

    parts = []
    if ents.people:
        parts.append("People: " + ", ".join(ents.people[:3]))
    if ents.amounts:
        parts.append("Amounts: " + ", ".join(ents.amounts[:3]))
    if ents.tools:
        parts.append("Tools: " + ", ".join(ents.tools[:4]))

    suffix = " | ".join(parts)
    return (f"{first} [{suffix}]" if suffix else first)[:200]


def _add_links(text: str) -> str:
    """Wrap linkable concepts in [[wiki-link]] format."""
    def replacer(m: re.Match) -> str:
        word = m.group(0)
        return f"[[{word}]]"
    return _LINKABLE_CONCEPTS.sub(replacer, text)


def capture(text: str, source: Path = Path("<stdin>"), add_links: bool = True) -> DreamNote:
    ents = extract_entities(text)
    title = _generate_title(text, source)
    summary = _generate_summary(text, ents)
    body = _add_links(text) if add_links else text
    now = datetime.now(timezone.utc).isoformat()

    return DreamNote(
        title=title,
        summary=summary,
        body=body,
        entities=ents,
        source=source,
        created_at=now,
    )


# ── Rendering ──────────────────────────────────────────────────────────────────

def render_note(note: DreamNote) -> str:
    e = note.entities
    lines = [
        "---",
        f"title: {note.title}",
        f"summary: {note.summary[:100]}",
        f"created: {note.created_at}",
        f"source: {note.source}",
    ]
    if e.people:    lines.append(f"people: [{', '.join(e.people[:5])}]")
    if e.dates:     lines.append(f"dates: [{', '.join(e.dates[:3])}]")
    if e.amounts:   lines.append(f"amounts: [{', '.join(e.amounts[:4])}]")
    if e.tools:     lines.append(f"tools: [{', '.join(e.tools[:6])}]")
    lines.append("tags: [dream-engine]")
    lines.append("---\n")

    if e.actions:
        lines.append("## Action Items\n")
        for a in e.actions:
            lines.append(f"- [ ] {a}")
        lines.append("")

    if e.decisions:
        lines.append("## Decisions\n")
        for d in e.decisions:
            lines.append(f"- {d}")
        lines.append("")

    lines.append("## Content\n")
    lines.append(note.body)

    if e.links:
        lines.append("\n## Links\n")
        links_str = " · ".join(f"[[{lk}]]" for lk in e.links)
        lines.append(links_str)

    return "\n".join(lines) + "\n"


def _output_path(source: Path, out_dir: Path | None) -> Path:
    stem = re.sub(r"[^\w\s-]", "", source.stem.lower())
    stem = re.sub(r"[\s-]+", "_", stem).strip("_")[:50]
    now = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{now}_{stem}.md"
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
        return out_dir / filename
    return source.parent / filename


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    rst, green, dim = ANSI["reset"], ANSI["green"], ANSI["dim"]
    cmd = args[0]
    verbose = "-v" in args or "--verbose" in args
    no_links = "--no-links" in args

    if cmd == "capture":
        out_dir = None
        out_val = None
        if "--out" in args:
            idx = args.index("--out")
            if idx + 1 < len(args):
                out_val = args[idx + 1]
                out_dir = Path(out_val).expanduser()
        positional = [
            a for a in args[1:]
            if not a.startswith("-") and a != "--out" and a != out_val
        ]

        if not positional:
            print("Usage: dream-engine capture <file or text> [--out dir]")
            sys.exit(1)

        target = positional[0]
        path = Path(target).expanduser()
        if path.exists() and path.is_file():
            text = path.read_text(encoding="utf-8", errors="ignore")
            source = path
        else:
            text = " ".join(positional)
            source = Path("<stdin>")

        note = capture(text, source, add_links=not no_links)
        rendered = render_note(note)
        out = _output_path(source, out_dir)
        out.write_text(rendered, encoding="utf-8")

        print(f"\n  {green}Captured:{rst} {out}")
        print(f"  {dim}Title:{rst} {note.title}")
        print(f"  {dim}Entities:{rst} "
              f"{len(note.entities.people)} people · "
              f"{len(note.entities.tools)} tools · "
              f"{len(note.entities.amounts)} amounts · "
              f"{len(note.entities.actions)} actions\n")
        if verbose:
            print(rendered)

    elif cmd == "extract":
        positional = [a for a in args[1:] if not a.startswith("-")]
        if not positional:
            print("Usage: dream-engine extract <file>")
            sys.exit(1)
        path = Path(positional[0]).expanduser()
        if not path.exists():
            print(f"Not found: {path}")
            sys.exit(1)
        text = path.read_text(encoding="utf-8", errors="ignore")
        ents = extract_entities(text)
        print(f"\n  {ANSI['cyan']}Entities in {path.name}{rst}\n")
        if ents.people:    print(f"  {dim}People:{rst}    {', '.join(ents.people)}")
        if ents.dates:     print(f"  {dim}Dates:{rst}     {', '.join(ents.dates)}")
        if ents.amounts:   print(f"  {dim}Amounts:{rst}   {', '.join(ents.amounts)}")
        if ents.tools:     print(f"  {dim}Tools:{rst}     {', '.join(ents.tools)}")
        if ents.actions:   print(f"  {dim}Actions:{rst}   {len(ents.actions)} found")
        if ents.decisions: print(f"  {dim}Decisions:{rst} {len(ents.decisions)} found")
        if ents.links:     print(f"  {dim}Links:{rst}     {', '.join(f'[[{lk}]]' for lk in ents.links[:8])}")
        print()

    elif cmd == "batch":
        out_dir = None
        out_val = None
        if "--out" in args:
            idx = args.index("--out")
            if idx + 1 < len(args):
                out_val = args[idx + 1]
                out_dir = Path(out_val).expanduser()
        positional = [
            a for a in args[1:]
            if not a.startswith("-") and a != "--out" and a != out_val
        ]

        if not positional:
            print("Usage: dream-engine batch <directory> [--out dir]")
            sys.exit(1)

        src = Path(positional[0]).expanduser()
        if not src.is_dir():
            print(f"Not a directory: {src}")
            sys.exit(1)

        processed = 0
        for dirpath, dirnames, filenames in os.walk(str(src), followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for filename in sorted(filenames):
                f = Path(dirpath) / filename
                if f.suffix in SCAN_EXTENSIONS and not f.name.endswith(".dream.md"):
                    try:
                        text = f.read_text(encoding="utf-8", errors="ignore")
                        note = capture(text, f, add_links=not no_links)
                        rendered = render_note(note)
                        out = _output_path(f, out_dir or src / "dream-output")
                        out.write_text(rendered, encoding="utf-8")
                        print(f"  {green}✓{rst}  {f.name}  →  {out.name}")
                        processed += 1
                    except OSError as exc:
                        print(f"  !  {f.name}  ({exc})")
        print(f"\n  {dim}{processed} files processed{rst}\n")

    elif cmd == "version":
        print(f"dream-engine {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: capture, extract, batch, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
