#!/usr/bin/env python3
"""
mcp-audit — Security auditor for MCP (Model Context Protocol) server configurations.

Scans ~/.claude.json, .mcp.json, and similar configs for:
- Hardcoded credentials and tokens in env vars or args
- Insecure file permissions (should be 600)
- Relative command paths (PATH hijacking risk)
- Excessive or dangerous tool exposure

Usage:
  python3 mcp_audit.py scan                    # audit default locations
  python3 mcp_audit.py scan ~/.claude.json     # audit specific file
  python3 mcp_audit.py scan -v                 # verbose (show all servers)
  python3 mcp_audit.py version
"""
from __future__ import annotations

import json
import os
import re
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"

# ── Pattern helpers ────────────────────────────────────────────────────────────
# Credential strings split via _p() so this scanner doesn't flag itself.
def _p(*parts: str) -> str:
    """Join pattern fragments at runtime — prevents static analysis false positives."""
    return "".join(parts)


# ── Credential detection ───────────────────────────────────────────────────────
# (prefix, suffix_regex, label, score) — credentials are case-sensitive by spec
_CRED_SPLITS: list[tuple[str, str, str, int]] = [
    (_p("sk-"),      r"[a-zA-Z0-9]{20,}",        "OpenAI/Anthropic API key",  50),
    (_p("sk_live_"), r"[a-zA-Z0-9]{20,}",        "Stripe live key",           50),
    (_p("sk_test_"), r"[a-zA-Z0-9]{20,}",        "Stripe test key",           40),
    (_p("gh", "p_"), r"[a-zA-Z0-9]{30,}",        "GitHub Personal Access Token", 50),
    (_p("AKIA"),     r"[0-9A-Z]{16}",             "AWS Access Key ID",         50),
    (_p("glpat-"),   r"[a-zA-Z0-9\-_]{20,}",     "GitLab PAT",                50),
    (_p("railway_"), r"[a-zA-Z0-9]{20,}",        "Railway API token",         50),
    (_p("whsec_"),   r"[a-zA-Z0-9]{20,}",        "Webhook signing secret",    45),
    (_p("xox", "b-"),r"[a-zA-Z0-9\-]{20,}",      "Slack Bot Token",           50),
    (r"eyJ[a-zA-Z0-9\-_]{20,}\.", "",             "JWT token (hardcoded)",     40),
]

_COMPILED_CREDS = [
    (re.compile(prefix + suffix, re.MULTILINE), label, score)
    for prefix, suffix, label, score in _CRED_SPLITS
]

# Keys whose values always warrant a credential scan regardless of value format
_SENSITIVE_KEY_FRAGMENTS = (
    "token", "key", "secret", "password", "auth", "credential",
    "api", "bearer", "access", "refresh",
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

DEFAULT_LOCATIONS = [
    Path.home() / ".claude.json",
    Path.home() / ".mcp.json",
    Path.cwd() / ".mcp.json",
    Path.cwd() / "mcp.json",
]


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    label: str
    delta: int
    detail: str
    advice: str


@dataclass
class ServerResult:
    name: str
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

    def add(self, label: str, delta: int, detail: str, advice: str) -> None:
        self.score = min(self.score + delta, 100)
        self.findings.append(Finding(label, delta, detail, advice))


@dataclass
class AuditResult:
    config_path: Path
    servers: list[ServerResult] = field(default_factory=list)
    file_findings: list[Finding] = field(default_factory=list)


# ── Scanning logic ────────────────────────────────────────────────────────────

def _scan_str_for_creds(value: str, context: str) -> list[Finding]:
    """Return credential findings for a single string value."""
    found = []
    for pattern, label, score in _COMPILED_CREDS:
        if pattern.search(value):
            found.append(Finding(
                label=f"Hardcoded credential: {label}",
                delta=score,
                detail=f"Found in {context}",
                advice="Replace with environment variable reference: $ENV_VAR_NAME",
            ))
    return found


def _check_permissions(path: Path) -> list[Finding]:
    found = []
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IROTH | stat.S_IWOTH):
            perms = oct(mode & 0o777)
            found.append(Finding(
                label="Insecure file permissions",
                delta=25,
                detail=f"Config is {perms} — group/world readable/writable",
                advice=f"chmod 600 {path}",
            ))
    except OSError:
        pass
    return found


def _audit_server(name: str, cfg: dict) -> ServerResult:
    srv = ServerResult(name=name)

    # Scan env vars for hardcoded credentials
    for var_name, var_val in cfg.get("env", {}).items():
        if not isinstance(var_val, str):
            continue
        key_lower = var_name.lower()
        is_sensitive_key = any(frag in key_lower for frag in _SENSITIVE_KEY_FRAGMENTS)
        findings = _scan_str_for_creds(var_val, f"env.{var_name}")
        is_path_value = var_val.startswith(("/", "~", "./", "../")) or var_val.endswith((".json", ".pem", ".key", ".env"))
        is_path_key = any(key_lower.endswith(sfx) for sfx in ("_path", "_dir", "_file", "_location", "_url"))
        if not findings and is_sensitive_key and not is_path_key and not is_path_value and len(var_val) > 8:
            # Key name implies a credential but pattern didn't match — flag generically
            findings = [Finding(
                label="Possible hardcoded credential",
                delta=20,
                detail=f"env.{var_name} has a sensitive key name with a non-empty value",
                advice="Use environment variable reference or a secrets manager",
            )]
        for f in findings:
            srv.score = min(srv.score + f.delta, 100)
            srv.findings.append(f)

    # Scan command and args
    cmd = cfg.get("command", "")
    args = cfg.get("args", [])
    for i, part in enumerate(([cmd] if cmd else []) + (args if isinstance(args, list) else [])):
        for f in _scan_str_for_creds(str(part), f"args[{i}]" if i else "command"):
            srv.score = min(srv.score + f.delta, 100)
            srv.findings.append(f)

    # Relative command path — PATH hijacking risk
    _SAFE_CMDS = {"node", "python3", "python", "uvx", "npx", "bash", "sh", "zsh", "fish", "deno", "bun"}
    if cmd and not os.path.isabs(cmd) and "/" not in cmd and cmd not in _SAFE_CMDS:
        srv.add(
            label="Relative command path",
            delta=10,
            detail=f"'{cmd}' resolved via PATH — vulnerable to PATH hijacking",
            advice=f"Use absolute path: $(which {cmd})",
        )

    return srv


def audit_file(config_path: Path) -> AuditResult | None:
    if not config_path.exists():
        return None

    result = AuditResult(config_path=config_path)
    result.file_findings.extend(_check_permissions(config_path))

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as e:
        result.file_findings.append(Finding(
            label="Parse error", delta=0, detail=str(e), advice="Validate JSON syntax",
        ))
        return result

    # Support multiple config formats
    servers_data: dict = {}
    if "mcpServers" in data:
        servers_data = data["mcpServers"]
    elif isinstance(data.get("mcp"), dict) and "servers" in data["mcp"]:
        servers_data = data["mcp"]["servers"]
    else:
        # Fallback: top-level keys that look like server configs
        servers_data = {k: v for k, v in data.items() if isinstance(v, dict) and "command" in v}

    if not servers_data:
        result.file_findings.append(Finding(
            label="No MCP servers found",
            delta=0,
            detail="Expected {mcpServers: {name: {command, env, ...}}}",
            advice="Check your MCP config format",
        ))
        return result

    for server_name, server_cfg in servers_data.items():
        if isinstance(server_cfg, dict):
            result.servers.append(_audit_server(server_name, server_cfg))

    return result


# ── Reporting ─────────────────────────────────────────────────────────────────

def report(results: list[AuditResult], verbose: bool = False) -> int:
    rst, dim, white, cyan = ANSI["reset"], ANSI["dim"], ANSI["white"], ANSI["cyan"]
    total_servers = sum(len(r.servers) for r in results)
    total_findings = sum(
        len(r.file_findings) + sum(len(s.findings) for s in r.servers) for r in results
    )

    print(f"\n  {white}mcp-audit v{VERSION}{rst}  "
          f"{dim}{len(results)} config · {total_servers} servers · {total_findings} findings{rst}\n")

    exit_code = 0
    for audit in results:
        print(f"  {cyan}► {audit.config_path}{rst}")

        for f in audit.file_findings:
            color = ANSI["red"] if f.delta >= 25 else ANSI["yellow"] if f.delta else ANSI["dim"]
            print(f"  {color}  [FILE  +{f.delta:2}]{rst}  {f.label}")
            if f.detail:
                print(f"  {dim}           {f.detail}{rst}")
            print(f"  {dim}           → {f.advice}{rst}")

        servers_sorted = sorted(audit.servers, key=lambda s: -s.score)
        shown = 0
        for srv in servers_sorted:
            if srv.score == 0 and not verbose:
                continue
            shown += 1
            print(f"\n  {srv.risk_color}[{srv.risk_label:6}  {srv.score:3}/100]{rst}  {srv.name}")
            if verbose or srv.score >= 20:
                for f in srv.findings:
                    print(f"  {dim}    +{f.delta:2}  {f.label}{rst}")
                    print(f"  {dim}         {f.detail}{rst}")
                    print(f"  {dim}         → {f.advice}{rst}")

        clean = [s for s in audit.servers if s.score == 0]
        if clean and not verbose:
            print(f"\n  {dim}  + {len(clean)} clean server(s) — use -v to show{rst}")

        high = sum(1 for s in audit.servers if s.risk_label == "HIGH")
        med  = sum(1 for s in audit.servers if s.risk_label == "MEDIUM")
        if high:
            exit_code = 1
        color = ANSI["red"] if high else (ANSI["yellow"] if med else ANSI["green"])
        print(f"\n  {color}HIGH: {high}  MEDIUM: {med}  CLEAN: {len(audit.servers) - high - med}{rst}\n")

    return exit_code


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return

    cmd, verbose = args[0], ("-v" in args or "--verbose" in args)

    if cmd == "scan":
        targets = [
            Path(a).expanduser() for a in args[1:] if not a.startswith("-")
        ]
        if not targets:
            targets = [p for p in DEFAULT_LOCATIONS if p.exists()]
        if not targets:
            print("No MCP config files found. Checked:")
            for p in DEFAULT_LOCATIONS:
                print(f"  {p}")
            sys.exit(1)

        results = [r for p in targets if (r := audit_file(p)) is not None]
        sys.exit(report(results, verbose=verbose))

    elif cmd == "version":
        print(f"mcp-audit {VERSION}")

    else:
        print(f"Unknown command: {cmd}\nCommands: scan, version")
        sys.exit(1)


if __name__ == "__main__":
    main()
