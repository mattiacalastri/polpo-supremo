#!/usr/bin/env python3
# SPDX-License-Identifier: MIT AND LicenseRef-soul-transfer-commercial
"""
soul-transfer — Cross-vendor AI agent identity portability.

Exports a complete AI agent configuration (CLAUDE.md, memory, MCP tools,
system prompts) into a portable .soul bundle. Import the bundle on any
system — same vendor or different — to reconstruct a working agent identity.

A .soul file is human-readable JSON containing:
  - identity      Agent name, role, mission, laws extracted from instructions
  - instructions  CLAUDE.md / system prompt content (all instruction files)
  - memory        Structured memory files (user, feedback, project, reference)
  - tools         MCP server configurations (credentials redacted by default)

This is the IP layer. Your agent's identity, not just its config.

Usage:
  python3 soul_transfer.py export [--from dir] [--out agent.soul] [--include-creds]
  python3 soul_transfer.py import agent.soul [--to dir] [--vendor claude-code]
  python3 soul_transfer.py inspect agent.soul
  python3 soul_transfer.py diff soul1.soul soul2.soul
  python3 soul_transfer.py version

Vendors supported for import:
  claude-code  (default) CLAUDE.md + memory/ + .mcp.json
  gemini       GEMINI.md + memory/ + .mcp.json
  openai       single system_prompt.md (instructions concatenated)
  generic      flat export, all files as-is

License:
  MIT for personal and open-source use.
  Commercial use (SaaS, products, resale) requires a separate license.
  See: https://github.com/polpo-supremo/soul-transfer/LICENSE-commercial
"""
from __future__ import annotations

import gzip
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

VERSION = "0.1.0"
SCHEMA  = "soul-transfer/1.0"

# ── File discovery constants ───────────────────────────────────────────────────

INSTRUCTION_NAMES = {"CLAUDE.md", "GEMINI.md", "AGENTS.md", "SYSTEM.md", "system.md"}
MEMORY_SUBDIR_NAMES = {"memory", ".memory", "memories", "context"}
MCP_CONFIG_NAMES  = {".mcp.json", ".claude.json", "mcp.json", "claude.json"}
MEMORY_EXTENSIONS = {".md", ".txt"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}

# Memory file type heuristics: filename prefix → type
_MEMORY_TYPE_MAP = {
    "user_":       "user",
    "feedback_":   "feedback",
    "project_":    "project",
    "reference_":  "reference",
    "procedure":   "procedure",
}

# ── Credential redaction ───────────────────────────────────────────────────────

_CRED_KEY_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|password|passwd|bearer|private[_-]?key|auth)",
)
# Values that look like secrets: long alphanum, vendor-prefixed keys
_CRED_VAL_RE = re.compile(
    r"(?:sk-[A-Za-z0-9]{20,}"
    r"|ghp_[A-Za-z0-9]{36}"
    r"|xoxb-\d+-[A-Za-z0-9\-]+"
    r"|[A-Za-z0-9+/]{40,}={0,2}"
    r"|[A-Fa-f0-9]{40,}"
    r")"
)


def _redact_value(key: str, val: object) -> object:
    if not isinstance(val, str):
        return val
    if _CRED_KEY_RE.search(str(key)) and _CRED_VAL_RE.search(val):
        return "[REDACTED — supply via env var]"
    return val


def _redact_dict(d: object, include_creds: bool) -> object:
    if include_creds:
        return d
    if isinstance(d, dict):
        return {k: _redact_dict(v if not isinstance(v, str) else _redact_value(k, v), False)
                for k, v in d.items()}
    if isinstance(d, list):
        return [_redact_dict(item, False) for item in d]
    return d


# ── Identity extraction ────────────────────────────────────────────────────────

def _extract_identity(text: str) -> dict:
    identity: dict = {"name": "", "role": "", "mission": "", "laws": []}

    # Name: first H1 heading
    m = re.search(r"(?m)^#\s+(.+)$", text)
    if m:
        identity["name"] = m.group(1).strip()[:80]

    # Role / Mission: first line matching keyword
    for line in text.splitlines():
        stripped = line.strip()
        low = stripped.lower()
        if not identity["role"] and re.match(r"(?:role|identity|sono|i am)\s*[:\-]", low):
            identity["role"] = re.sub(r"^[^:\-]+[:\-]\s*", "", stripped)[:120]
        if not identity["mission"] and re.match(
            r"(?:mission|missione|purpose|goal|obiettivo|scopo)\s*[:\-]", low
        ):
            identity["mission"] = re.sub(r"^[^:\-]+[:\-]\s*", "", stripped)[:200]

    # Laws: bullet-point rules (first 15)
    laws = []
    for bm in re.finditer(r"(?m)^\s*[-*•]\s+(.{10,150})$", text):
        laws.append(bm.group(1).strip())
    identity["laws"] = laws[:15]

    return identity


# ── Memory file type detection ─────────────────────────────────────────────────

def _memory_type(path: Path) -> str:
    name = path.name.lower()
    for prefix, mtype in _MEMORY_TYPE_MAP.items():
        if name.startswith(prefix):
            return mtype
    return "unknown"


# ── Bundle data structure ──────────────────────────────────────────────────────

@dataclass
class SoulBundle:
    schema: str
    version: str
    exported: str
    source_dir: str
    vendor: str
    identity: dict
    instructions: list[dict]   # [{filename, content}]
    memory: list[dict]         # [{path, content, type}]
    tools: dict                # {mcp_servers: {name: config}, skills: [...]}
    metadata: dict             # {word_count, file_count, tags}


# ── Export ─────────────────────────────────────────────────────────────────────

def _find_instruction_files(src: Path) -> list[Path]:
    found = []
    # Root level
    for name in INSTRUCTION_NAMES:
        p = src / name
        if p.is_file():
            found.append(p)
    # One level deep (e.g., .claude/CLAUDE.md)
    for child in sorted(src.iterdir()):
        if child.is_dir() and child.name not in SKIP_DIRS:
            for name in INSTRUCTION_NAMES:
                p = child / name
                if p.is_file():
                    found.append(p)
    return found


def _find_memory_files(src: Path) -> list[Path]:
    found = []
    for subdir_name in MEMORY_SUBDIR_NAMES:
        mem_dir = src / subdir_name
        if mem_dir.is_dir():
            for dirpath, dirnames, filenames in os.walk(str(mem_dir), followlinks=False):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
                for fname in sorted(filenames):
                    f = Path(dirpath) / fname
                    if f.suffix in MEMORY_EXTENSIONS:
                        found.append(f)
    return found


def _find_mcp_config(src: Path) -> dict:
    for name in MCP_CONFIG_NAMES:
        p = src / name
        if p.is_file():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data
            except (json.JSONDecodeError, OSError):
                pass
    # Only fall back to home dir when explicitly exporting from home
    if src == Path.home():
        home = Path.home()
        for name in MCP_CONFIG_NAMES:
            p = home / name
            if p.is_file():
                try:
                    data = json.loads(p.read_text(encoding="utf-8"))
                    return data
                except (json.JSONDecodeError, OSError):
                    pass
    return {}


def export_soul(
    src: Path,
    include_creds: bool = False,
    vendor: str = "claude-code",
) -> SoulBundle:
    src = src.resolve()

    # Instructions
    instr_files = _find_instruction_files(src)
    instructions = []
    primary_text = ""
    for f in instr_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            rel = str(f.relative_to(src))
            instructions.append({"filename": rel, "content": content})
            if not primary_text and f.name in ("CLAUDE.md", "GEMINI.md", "AGENTS.md"):
                primary_text = content
        except OSError:
            pass

    # Identity
    identity = _extract_identity(primary_text or (instructions[0]["content"] if instructions else ""))

    # Memory
    mem_files = _find_memory_files(src)
    memory = []
    for f in mem_files:
        try:
            content = f.read_text(encoding="utf-8", errors="ignore")
            rel = str(f.relative_to(src))
            memory.append({
                "path": rel,
                "content": content,
                "type": _memory_type(f),
            })
        except OSError:
            pass

    # MCP / Tools
    raw_mcp = _find_mcp_config(src)
    mcp_servers = raw_mcp.get("mcpServers", raw_mcp)  # handle both formats
    tools = {
        "mcp_servers": _redact_dict(mcp_servers, include_creds),
        "skills": [],  # reserved for future skill extraction
    }

    # Metadata
    total_words = sum(len(i["content"].split()) for i in instructions)
    total_words += sum(len(m["content"].split()) for m in memory)

    return SoulBundle(
        schema=SCHEMA,
        version=VERSION,
        exported=datetime.now(timezone.utc).isoformat(),
        source_dir=str(src),
        vendor=vendor,
        identity=identity,
        instructions=instructions,
        memory=memory,
        tools=tools,
        metadata={
            "word_count": total_words,
            "file_count": len(instructions) + len(memory),
            "tags": ["soul-transfer"],
        },
    )


# ── Serialization ──────────────────────────────────────────────────────────────

def _to_dict(bundle: SoulBundle) -> dict:
    return {
        "schema":      bundle.schema,
        "version":     bundle.version,
        "exported":    bundle.exported,
        "source_dir":  bundle.source_dir,
        "vendor":      bundle.vendor,
        "identity":    bundle.identity,
        "instructions": bundle.instructions,
        "memory":      bundle.memory,
        "tools":       bundle.tools,
        "metadata":    bundle.metadata,
    }


def write_soul(bundle: SoulBundle, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(_to_dict(bundle), indent=2, ensure_ascii=False)
    try:
        if out.suffix == ".gz":
            out.write_bytes(gzip.compress(data.encode("utf-8")))
        else:
            out.write_text(data, encoding="utf-8")
    except OSError as exc:
        print(f"Error writing {out}: {exc}")
        sys.exit(1)


def load_soul(path: Path) -> SoulBundle:
    try:
        if path.suffix == ".gz":
            raw = gzip.decompress(path.read_bytes()).decode("utf-8")
        else:
            raw = path.read_text(encoding="utf-8")
    except (OSError, gzip.BadGzipFile) as exc:
        print(f"Error reading {path}: {exc}")
        sys.exit(1)
    try:
        d = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Invalid .soul file {path}: {exc}")
        sys.exit(1)
    return SoulBundle(
        schema=d.get("schema", ""),
        version=d.get("version", ""),
        exported=d.get("exported", ""),
        source_dir=d.get("source_dir", ""),
        vendor=d.get("vendor", "generic"),
        identity=d.get("identity", {}),
        instructions=d.get("instructions", []),
        memory=d.get("memory", []),
        tools=d.get("tools", {}),
        metadata=d.get("metadata", {}),
    )


# ── Import / Reconstruct ───────────────────────────────────────────────────────

_VENDOR_INSTRUCTION_NAME = {
    "claude-code": "CLAUDE.md",
    "gemini":      "GEMINI.md",
    "openai":      "system_prompt.md",
    "generic":     None,  # use original filenames
}

_CRED_PLACEHOLDER_RE = re.compile(r"\[REDACTED[^\]]*\]")


def _safe_path(dest: Path, rel: str) -> Path | None:
    """Resolve dest/rel and verify it stays within dest. Returns None on traversal."""
    dest_abs = dest.resolve()
    candidate = (dest / rel).resolve()
    try:
        candidate.relative_to(dest_abs)
        return candidate
    except ValueError:
        return None


def import_soul(bundle: SoulBundle, dest: Path, vendor: str = "claude-code") -> tuple[list[str], list[str]]:
    """Reconstruct agent config from bundle. Returns (written_paths, needs_creds)."""
    dest.mkdir(parents=True, exist_ok=True)
    written = []
    needs_creds: list[str] = []

    instr_name = _VENDOR_INSTRUCTION_NAME.get(vendor)

    if vendor == "openai":
        # Concatenate all instructions into one system prompt
        combined = "\n\n---\n\n".join(
            f"# {i['filename']}\n\n{i['content']}" for i in bundle.instructions
        )
        p = dest / "system_prompt.md"
        p.write_text(combined, encoding="utf-8")
        written.append(str(p))
    else:
        for instr in bundle.instructions:
            rel = instr["filename"]
            if instr_name and vendor in ("claude-code", "gemini"):
                orig = Path(rel)
                if orig.name in INSTRUCTION_NAMES:
                    rel = str(orig.parent / instr_name)
            out_path = _safe_path(dest, rel)
            if out_path is None:
                print(f"  ! Skipping unsafe path: {instr['filename']}")
                continue
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(instr["content"], encoding="utf-8")
            written.append(str(out_path))

    # Memory files
    for mem in bundle.memory:
        out_path = _safe_path(dest, mem["path"])
        if out_path is None:
            print(f"  ! Skipping unsafe path: {mem['path']}")
            continue
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(mem["content"], encoding="utf-8")
        written.append(str(out_path))

    # MCP config (only for vendors that use it)
    if vendor in ("claude-code", "gemini") and bundle.tools.get("mcp_servers"):
        mcp_data = {"mcpServers": bundle.tools["mcp_servers"]}
        mcp_json = json.dumps(mcp_data, indent=2)
        if _CRED_PLACEHOLDER_RE.search(mcp_json):
            needs_creds.append(".mcp.json (contains [REDACTED] values — supply via env vars)")
        mcp_path = dest / ".mcp.json"
        mcp_path.write_text(mcp_json, encoding="utf-8")
        written.append(str(mcp_path))

    return written, needs_creds


# ── Inspect ────────────────────────────────────────────────────────────────────

def inspect_soul(bundle: SoulBundle) -> None:
    rst, dim, white, cyan, green, yellow = (
        ANSI["reset"], ANSI["dim"], ANSI["white"],
        ANSI["cyan"], ANSI["green"], ANSI["yellow"],
    )
    ident = bundle.identity
    meta  = bundle.metadata
    tools = bundle.tools

    print(f"\n  {white}soul-transfer v{VERSION}{rst}  "
          f"{dim}schema {bundle.schema}{rst}\n")
    print(f"  {cyan}Exported:{rst}   {bundle.exported}")
    print(f"  {cyan}Source:{rst}     {bundle.source_dir}")
    print(f"  {cyan}Vendor:{rst}     {bundle.vendor}\n")

    if ident.get("name"):
        print(f"  {white}Identity{rst}")
        if ident["name"]:    print(f"  {dim}Name:{rst}     {ident['name']}")
        if ident["role"]:    print(f"  {dim}Role:{rst}     {ident['role'][:80]}")
        if ident["mission"]: print(f"  {dim}Mission:{rst}  {ident['mission'][:100]}")
        if ident["laws"]:
            print(f"  {dim}Laws:{rst}     {len(ident['laws'])} extracted")
        print()

    print(f"  {white}Contents{rst}")
    print(f"  {dim}Instructions:{rst} {len(bundle.instructions)} files  "
          f"({', '.join(i['filename'] for i in bundle.instructions[:4])})")
    print(f"  {dim}Memory:{rst}       {len(bundle.memory)} files  "
          f"({meta.get('word_count', 0):,} total words)")

    mcp = tools.get("mcp_servers", {})
    if mcp:
        redacted = sum(
            1 for v in json.dumps(mcp).split('"')
            if "[REDACTED" in v
        )
        print(f"  {dim}MCP servers:{rst}  {len(mcp)} configured"
              + (f"  {yellow}({redacted} credentials redacted){rst}" if redacted else ""))

    by_type: dict[str, int] = {}
    for m in bundle.memory:
        t = m.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1
    if by_type:
        type_str = "  ".join(f"{t}:{n}" for t, n in sorted(by_type.items()))
        print(f"  {dim}Memory types:{rst} {type_str}")

    print(f"\n  {green}Total:{rst} {meta.get('file_count', 0)} files  "
          f"{meta.get('word_count', 0):,} words\n")


# ── Diff ───────────────────────────────────────────────────────────────────────

def diff_souls(a: SoulBundle, b: SoulBundle) -> int:
    rst, dim, green, red, yellow = (
        ANSI["reset"], ANSI["dim"], ANSI["green"], ANSI["red"], ANSI["yellow"],
    )
    changes = 0

    print(f"\n  {ANSI['white']}soul-transfer diff{rst}\n")
    print(f"  {dim}A:{rst} {a.exported}  ({a.source_dir})")
    print(f"  {dim}B:{rst} {b.exported}  ({b.source_dir})\n")

    # Identity diff
    ident_changes = []
    for key in ("name", "role", "mission"):
        va, vb = a.identity.get(key, ""), b.identity.get(key, "")
        if va != vb:
            ident_changes.append((key, va, vb))
    laws_a = set(a.identity.get("laws", []))
    laws_b = set(b.identity.get("laws", []))
    added_laws   = laws_b - laws_a
    removed_laws = laws_a - laws_b

    if ident_changes or added_laws or removed_laws:
        print(f"  {yellow}Identity changes:{rst}")
        for key, va, vb in ident_changes:
            print(f"  {dim}  {key}:{rst}")
            if va: print(f"  {red}  - {va[:80]}{rst}")
            if vb: print(f"  {green}  + {vb[:80]}{rst}")
        for law in sorted(removed_laws)[:5]:
            print(f"  {red}  - [law] {law[:70]}{rst}")
        for law in sorted(added_laws)[:5]:
            print(f"  {green}  + [law] {law[:70]}{rst}")
        changes += len(ident_changes) + len(added_laws) + len(removed_laws)
        print()

    # Instructions diff
    a_instr = {i["filename"]: i["content"] for i in a.instructions}
    b_instr = {i["filename"]: i["content"] for i in b.instructions}
    added_i   = set(b_instr) - set(a_instr)
    removed_i = set(a_instr) - set(b_instr)
    changed_i = {f for f in a_instr if f in b_instr and a_instr[f] != b_instr[f]}

    if added_i or removed_i or changed_i:
        print(f"  {yellow}Instruction changes:{rst}")
        for f in sorted(removed_i): print(f"  {red}  - {f}{rst}")
        for f in sorted(added_i):   print(f"  {green}  + {f}{rst}")
        for f in sorted(changed_i):
            la, lb = len(a_instr[f].splitlines()), len(b_instr[f].splitlines())
            delta = lb - la
            sign = "+" if delta >= 0 else ""
            print(f"  {dim}  ~ {f}  ({sign}{delta} lines){rst}")
        changes += len(added_i) + len(removed_i) + len(changed_i)
        print()

    # Memory diff
    a_mem = {m["path"]: m["content"] for m in a.memory}
    b_mem = {m["path"]: m["content"] for m in b.memory}
    added_m   = set(b_mem) - set(a_mem)
    removed_m = set(a_mem) - set(b_mem)
    changed_m = {p for p in a_mem if p in b_mem and a_mem[p] != b_mem[p]}

    if added_m or removed_m or changed_m:
        print(f"  {yellow}Memory changes:{rst}")
        for p in sorted(removed_m)[:8]: print(f"  {red}  - {p}{rst}")
        for p in sorted(added_m)[:8]:   print(f"  {green}  + {p}{rst}")
        for p in sorted(changed_m)[:8]:
            wa = len(a_mem[p].split())
            wb = len(b_mem[p].split())
            print(f"  {dim}  ~ {p}  ({wb - wa:+d} words){rst}")
        changes += len(added_m) + len(removed_m) + len(changed_m)
        print()

    # MCP diff
    a_mcp = set(a.tools.get("mcp_servers", {}).keys())
    b_mcp = set(b.tools.get("mcp_servers", {}).keys())
    if a_mcp != b_mcp:
        print(f"  {yellow}MCP server changes:{rst}")
        for s in sorted(a_mcp - b_mcp): print(f"  {red}  - {s}{rst}")
        for s in sorted(b_mcp - a_mcp): print(f"  {green}  + {s}{rst}")
        changes += len(a_mcp - b_mcp) + len(b_mcp - a_mcp)
        print()

    if not changes:
        print(f"  {green}No differences found — souls are identical.{rst}\n")
    else:
        print(f"  {yellow}{changes} change(s) detected{rst}\n")

    return 1 if changes else 0


# ── ANSI ───────────────────────────────────────────────────────────────────────

ANSI = {
    "red":    "\033[1;31m",
    "yellow": "\033[1;33m",
    "green":  "\033[1;32m",
    "cyan":   "\033[1;36m",
    "white":  "\033[1;37m",
    "dim":    "\033[2m",
    "reset":  "\033[0m",
}


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    rst, green, dim = ANSI["reset"], ANSI["green"], ANSI["dim"]
    cmd = args[0]
    verbose = "-v" in args or "--verbose" in args

    if cmd == "export":
        from_val = None
        out_val  = None
        if "--from" in args:
            idx = args.index("--from")
            if idx + 1 < len(args):
                from_val = args[idx + 1]
        if "--out" in args:
            idx = args.index("--out")
            if idx + 1 < len(args):
                out_val = args[idx + 1]

        include_creds = "--include-creds" in args
        src = Path(from_val).expanduser() if from_val else Path.cwd()
        if not src.is_dir():
            print(f"Not a directory: {src}")
            sys.exit(1)

        bundle = export_soul(src, include_creds=include_creds)
        stem = re.sub(r"[^\w-]", "_", bundle.identity.get("name", "agent") or "agent")[:30]
        out_path = Path(out_val).expanduser() if out_val else (src / f"{stem}.soul")

        write_soul(bundle, out_path)

        print(f"\n  {green}Exported:{rst} {out_path}")
        print(f"  {dim}Identity:{rst}     {bundle.identity.get('name', '—')}")
        print(f"  {dim}Instructions:{rst} {len(bundle.instructions)} files")
        print(f"  {dim}Memory:{rst}       {len(bundle.memory)} files")
        mcp = bundle.tools.get("mcp_servers", {})
        print(f"  {dim}MCP servers:{rst}  {len(mcp)}")
        if not include_creds:
            print(f"  {dim}Note:{rst}         credentials redacted — use --include-creds to embed")
        print()

    elif cmd == "import":
        to_val     = None
        vendor_val = "claude-code"
        if "--to" in args:
            idx = args.index("--to")
            if idx + 1 < len(args):
                to_val = args[idx + 1]
        if "--vendor" in args:
            idx = args.index("--vendor")
            if idx + 1 < len(args):
                vendor_val = args[idx + 1]

        # Collect positionals, skipping flag names and their values
        skip_next = False
        clean_positional = []
        for a in args[1:]:
            if skip_next:
                skip_next = False
                continue
            if a in ("--to", "--vendor"):
                skip_next = True
                continue
            if not a.startswith("-"):
                clean_positional.append(a)

        if not clean_positional:
            print("Usage: soul-transfer import <file.soul> [--to dir] [--vendor claude-code]")
            sys.exit(1)

        soul_path = Path(clean_positional[0]).expanduser()
        if not soul_path.exists():
            print(f"Not found: {soul_path}")
            sys.exit(1)

        bundle = load_soul(soul_path)
        dest = Path(to_val).expanduser() if to_val else Path.cwd() / "soul-import"
        written, needs_creds = import_soul(bundle, dest, vendor=vendor_val)

        print(f"\n  {green}Imported:{rst} {len(written)} files → {dest}")
        print(f"  {dim}Vendor:{rst}   {vendor_val}")
        if verbose:
            for f in written:
                print(f"  {dim}  {f}{rst}")
        if needs_creds:
            print(f"\n  {ANSI['yellow']}Action required — redacted credentials:{rst}")
            for note in needs_creds:
                print(f"  {dim}  • {note}{rst}")
        print()

    elif cmd == "inspect":
        positional = [a for a in args[1:] if not a.startswith("-")]
        if not positional:
            print("Usage: soul-transfer inspect <file.soul>")
            sys.exit(1)
        soul_path = Path(positional[0]).expanduser()
        if not soul_path.exists():
            print(f"Not found: {soul_path}")
            sys.exit(1)
        bundle = load_soul(soul_path)
        inspect_soul(bundle)

    elif cmd == "diff":
        positional = [a for a in args[1:] if not a.startswith("-")]
        if len(positional) < 2:
            print("Usage: soul-transfer diff soul1.soul soul2.soul")
            sys.exit(1)
        p1, p2 = Path(positional[0]).expanduser(), Path(positional[1]).expanduser()
        for p in (p1, p2):
            if not p.exists():
                print(f"Not found: {p}")
                sys.exit(1)
        bundle_a = load_soul(p1)
        bundle_b = load_soul(p2)
        sys.exit(diff_souls(bundle_a, bundle_b))

    elif cmd == "version":
        print(f"soul-transfer {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: export, import, inspect, diff, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
