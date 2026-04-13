"""
open-memory — file-based memory system for any AI agent
Zero external dependencies. Compatible with Claude Code memory format.

Usage:
    from memory import Memory
    mem = Memory("~/.my-agent/memory")
    mem.save("user_role", "senior backend engineer", type="user")
    result = mem.load("user_role")
    results = mem.search("engineer")
    all_keys = mem.list_all()
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional


VERSION = "0.1.0"

VALID_TYPES = {"user", "feedback", "project", "reference"}
_FRONTMATTER_RE = re.compile(r'^---\n(.*?)\n---\n?(.*)', re.DOTALL)


class MemoryEntry:
    __slots__ = ('key', 'name', 'description', 'type', 'content', 'updated_at')

    def __init__(self, key, name, description, type_, content, updated_at):
        self.key = key
        self.name = name
        self.description = description
        self.type = type_
        self.content = content
        self.updated_at = updated_at

    def to_dict(self):
        return {s: getattr(self, s) for s in self.__slots__}


class Memory:
    """
    File-based memory store. Each entry is a markdown file with YAML frontmatter.

    Directory layout:
        {base_dir}/
            {key}.md        ← memory file
            INDEX.json      ← fast lookup index (auto-managed)
    """

    def __init__(self, base_dir: str = "~/.open-memory"):
        self.base_dir = Path(base_dir).expanduser()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self.base_dir / "INDEX.json"
        self._index = self._load_index()

    # ── Public API ────────────────────────────────────────────────────────────

    def save(self, key: str, content: str, type: str = "project",
             name: str = "", description: str = "") -> MemoryEntry:
        """Save or update a memory entry."""
        if type not in VALID_TYPES:
            raise ValueError(f"type must be one of {VALID_TYPES}, got '{type}'")

        key = self._sanitize_key(key)
        name = name or key.replace('_', ' ').title()
        description = description or content[:100].replace('\n', ' ')
        now = datetime.now(timezone.utc).isoformat()

        entry = MemoryEntry(key, name, description, type, content, now)
        self._write_file(entry)
        self._index[key] = {
            'name': name, 'description': description,
            'type': type, 'updated_at': now
        }
        self._save_index()
        return entry

    def load(self, key: str) -> Optional[MemoryEntry]:
        """Load a memory entry by key. Returns None if not found."""
        key = self._sanitize_key(key)
        path = self.base_dir / f"{key}.md"
        if not path.exists():
            return None
        return self._read_file(path)

    def search(self, query: str, type_filter: str = None) -> list[MemoryEntry]:
        """
        Search memories by keyword (case-insensitive).
        Searches key, name, description, and content.
        Optionally filter by type.
        """
        query_lower = query.lower()
        results = []

        for key, meta in self._index.items():
            if type_filter and meta.get('type') != type_filter:
                continue
            # Quick check against index first
            if (query_lower in key.lower() or
                    query_lower in meta.get('name', '').lower() or
                    query_lower in meta.get('description', '').lower()):
                entry = self.load(key)
                if entry:
                    results.append(entry)
                continue
            # Full content check
            entry = self.load(key)
            if entry and query_lower in entry.content.lower():
                results.append(entry)

        return results

    def list_all(self, type_filter: str = None) -> list[dict]:
        """List all memory entries (index only, no content load)."""
        entries = []
        for key, meta in self._index.items():
            if type_filter and meta.get('type') != type_filter:
                continue
            entries.append({'key': key, **meta})
        return sorted(entries, key=lambda x: x.get('updated_at', ''), reverse=True)

    def delete(self, key: str) -> bool:
        """Delete a memory entry. Returns True if deleted, False if not found."""
        key = self._sanitize_key(key)
        path = self.base_dir / f"{key}.md"
        if not path.exists():
            return False
        path.unlink()
        self._index.pop(key, None)
        self._save_index()
        return True

    def stats(self) -> dict:
        """Return memory store stats."""
        by_type = {}
        for meta in self._index.values():
            t = meta.get('type', 'unknown')
            by_type[t] = by_type.get(t, 0) + 1
        return {
            'total': len(self._index),
            'by_type': by_type,
            'base_dir': str(self.base_dir),
        }

    # ── Internal ──────────────────────────────────────────────────────────────

    def _sanitize_key(self, key: str) -> str:
        """Convert key to safe filename (lowercase, underscores, no special chars)."""
        key = re.sub(r'[^\w\s-]', '', key.lower())
        return re.sub(r'[\s-]+', '_', key).strip('_')

    def _write_file(self, entry: MemoryEntry):
        path = self.base_dir / f"{entry.key}.md"
        tmp = path.with_suffix('.tmp')
        content = (
            f"---\n"
            f"name: {entry.name}\n"
            f"description: {entry.description}\n"
            f"type: {entry.type}\n"
            f"updated_at: {entry.updated_at}\n"
            f"---\n\n"
            f"{entry.content}\n"
        )
        tmp.write_text(content, encoding='utf-8')
        os.replace(tmp, path)  # atomic on POSIX — crash-safe

    def _read_file(self, path: Path) -> Optional[MemoryEntry]:
        try:
            raw = path.read_text(encoding='utf-8')
        except OSError:
            return None

        m = _FRONTMATTER_RE.match(raw)
        if not m:
            return MemoryEntry(
                key=path.stem, name=path.stem, description='',
                type_='project', content=raw.strip(),
                updated_at=''
            )

        fm_text, body = m.group(1), m.group(2).strip()
        fm = {}
        for line in fm_text.splitlines():
            if ':' in line:
                k, _, v = line.partition(':')
                fm[k.strip()] = v.strip()

        return MemoryEntry(
            key=path.stem,
            name=fm.get('name', path.stem),
            description=fm.get('description', ''),
            type_=fm.get('type', 'project'),
            content=body,
            updated_at=fm.get('updated_at', ''),
        )

    def _load_index(self) -> dict:
        if self._index_path.exists():
            try:
                return json.loads(self._index_path.read_text(encoding='utf-8'))
            except (json.JSONDecodeError, OSError):
                pass
        # Rebuild from files
        index = {}
        for md_file in self.base_dir.glob('*.md'):
            entry = self._read_file(md_file)
            if entry:
                index[entry.key] = {
                    'name': entry.name, 'description': entry.description,
                    'type': entry.type, 'updated_at': entry.updated_at
                }
        return index

    def _save_index(self):
        tmp = self._index_path.with_suffix('.tmp')
        tmp.write_text(
            json.dumps(self._index, indent=2, ensure_ascii=False),
            encoding='utf-8'
        )
        os.replace(tmp, self._index_path)  # atomic on POSIX — crash-safe


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse, sys

    parser = argparse.ArgumentParser(prog='open-memory')
    parser.add_argument('--dir', default='~/.open-memory', help='Memory directory')
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_save = sub.add_parser('save')
    p_save.add_argument('key')
    p_save.add_argument('content')
    p_save.add_argument('--type', default='project', choices=VALID_TYPES)
    p_save.add_argument('--name', default='')
    p_save.add_argument('--desc', default='')

    p_load = sub.add_parser('load')
    p_load.add_argument('key')

    p_search = sub.add_parser('search')
    p_search.add_argument('query')
    p_search.add_argument('--type', default=None)

    p_list = sub.add_parser('list')
    p_list.add_argument('--type', default=None)

    p_stats = sub.add_parser('stats')

    args = parser.parse_args()
    mem = Memory(args.dir)

    if args.cmd == 'save':
        e = mem.save(args.key, args.content, args.type, args.name, args.desc)
        print(f"[OK] Saved: {e.key} ({e.type})")
    elif args.cmd == 'load':
        e = mem.load(args.key)
        if e:
            print(f"# {e.name} [{e.type}]\n{e.content}")
        else:
            print(f"[NOT FOUND] {args.key}", file=sys.stderr); sys.exit(1)
    elif args.cmd == 'search':
        results = mem.search(args.query, args.type)
        if not results:
            print("[NO RESULTS]")
        for r in results:
            print(f"- {r.key} [{r.type}]: {r.description[:80]}")
    elif args.cmd == 'list':
        for e in mem.list_all(args.type):
            print(f"- {e['key']} [{e['type']}] {e['updated_at'][:10]}: {e['description'][:60]}")
    elif args.cmd == 'stats':
        s = mem.stats()
        print(f"Total: {s['total']} | Dir: {s['base_dir']}")
        for t, n in s['by_type'].items():
            print(f"  {t}: {n}")
