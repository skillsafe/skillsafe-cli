#!/usr/bin/env python3
"""
SkillSafe — secured skill registry client for AI coding tools.

A single-file Python client (stdlib only) that can scan, save, share, install,
and verify skills from the SkillSafe registry. Designed to run inside
Claude Code, Cursor, Windsurf, Codex, Gemini CLI, OpenCode, OpenClaw, and similar AI-assisted development tools.

Usage:
    python skillsafe.py auth                              # browser login
    python skillsafe.py scan <path>
    python skillsafe.py bom <path> [-o bom.json]
    python skillsafe.py save <path> --version <ver> [--description <d>] [--category <c>] [--tags <t>]
    python skillsafe.py share <@namespace/skill> --version <ver> [--public] [--expires <1d|7d|30d|never>]
    python skillsafe.py install <@namespace/skill> [--version <ver>] [--tool <name>] [--location project|global] [--skills-dir <override>]
    python skillsafe.py install <share-link> [--tool <name>] [--location project|global] [--skills-dir <override>]
    python skillsafe.py search <query> [--category <c>] [--sort <s>]
    python skillsafe.py info <@namespace/skill>
    python skillsafe.py list
    python skillsafe.py import <github-or-clawhub-url>
    python skillsafe.py claim github.com/owner/repo
    python skillsafe.py eval @ns/name --version <ver> --eval-json results.json
    python skillsafe.py benchmark @ns/name --version <ver> --runs 10
    python skillsafe.py yank @ns/name --version <ver>
    python skillsafe.py demo <path/to/demo.json> @ns/name --version <ver> --title "My demo"
    python skillsafe.py agent save <path>
    python skillsafe.py update
    python skillsafe.py whoami

Also importable as a module:
    from skillsafe import Scanner, SkillSafeClient

References / Thanks:
    https://github.com/kriskimmerle/skillsafe — rule taxonomy and detection patterns
    OWASP Agentic AI Threat Taxonomy
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sys
import tarfile
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

# ---------------------------------------------------------------------------
# Python version guard
# ---------------------------------------------------------------------------

if sys.version_info < (3, 8):
    print("Error: Python 3.8+ is required.", file=sys.stderr)
    sys.exit(1)


def _safe_extractall(tar: tarfile.TarFile, path: Union[str, Path]) -> None:
    """Extract tarfile safely.  Uses the ``filter="data"`` parameter on
    Python 3.12+ (which blocks absolute paths, traversals, and special
    members).  On older Pythons we validate each member then extract
    individually to avoid TOCTOU races."""
    if sys.version_info >= (3, 12):
        tar.extractall(path=path, filter="data")
    else:
        # Manual safety: reject absolute paths, traversals, symlinks,
        # hardlinks, and special file types.  Extract member-by-member
        # so the validated list cannot be swapped between check and use.
        dest = os.path.realpath(path)
        safe_members: list = []
        for member in tar.getmembers():
            member_path = os.path.normpath(member.name)
            if member_path.startswith("/") or member_path.startswith("..") or "/../" in member_path:
                raise tarfile.TarError(f"Path traversal in archive: {member.name}")
            resolved = os.path.realpath(os.path.join(dest, member_path))
            if not resolved.startswith(dest + os.sep) and resolved != dest:
                raise tarfile.TarError(f"Path escapes destination: {member.name}")
            # Block symlinks entirely — skills should never contain them
            if member.issym():
                raise tarfile.TarError(f"Blocked symlink: {member.name} -> {member.linkname}")
            # Block hardlinks — they can reference arbitrary files on the host
            if member.islnk():
                raise tarfile.TarError(f"Blocked hardlink: {member.name} -> {member.linkname}")
            if not (member.isfile() or member.isdir()):
                raise tarfile.TarError(f"Blocked special member: {member.name}")
            safe_members.append(member)
        tar.extractall(path=path, members=safe_members)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VERSION = "0.1.7"
RULESET_VERSION = "2026.04.08"
SCANNER_TOOL = "skillsafe-scanner-py"
DEFAULT_API_BASE = "https://api.skillsafe.ai"

CONFIG_DIR = Path.home() / ".skillsafe"
CONFIG_FILE = CONFIG_DIR / "config.json"
SKILLS_DIR = CONFIG_DIR / "skills"
CACHE_DIR = CONFIG_DIR / "cache"
BLOB_CACHE_DIR = CACHE_DIR / "blobs"
INSTALLED_INDEX = CONFIG_DIR / "installed.json"


def _read_install_index() -> Dict[str, Any]:
    """Read ~/.skillsafe/installed.json — maps install_dir -> metadata."""
    if not INSTALLED_INDEX.exists():
        return {}
    try:
        with open(INSTALLED_INDEX) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _write_install_index(index: Dict[str, Any]) -> None:
    """Write ~/.skillsafe/installed.json atomically."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    tmp_path = INSTALLED_INDEX.with_suffix(".tmp")
    try:
        with open(tmp_path, "w") as f:
            json.dump(index, f, indent=2)
            f.write("\n")
        tmp_path.replace(INSTALLED_INDEX)
    except OSError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass


def _register_install(install_dir: Path, namespace: str, name: str, version: str, tree_hash: str) -> None:
    """Record an installed skill in the central index."""
    index = _read_install_index()
    index[str(install_dir)] = {
        "namespace": f"@{namespace}",
        "name": name,
        "version": version,
        "tree_hash": tree_hash,
        "installed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _write_install_index(index)


def _get_install_meta(install_dir: Path) -> Optional[Dict[str, Any]]:
    """Look up install metadata for a directory from the central index."""
    index = _read_install_index()
    return index.get(str(install_dir))

TOOL_SKILLS_DIRS: Dict[str, Path] = {
    "claude": Path.home() / ".claude" / "skills",
    "cursor": Path.home() / ".cursor" / "skills",
    "windsurf": Path.home() / ".windsurf" / "skills",
    "codex": Path.home() / ".agents" / "skills",
    "gemini": Path.home() / ".gemini" / "skills",
    "opencode": Path.home() / ".config" / "opencode" / "skills",
    "openclaw": Path.home() / ".openclaw" / "workspace" / "skills",
    # Extended integrations
    "cline": Path.home() / ".cline" / "skills",
    "roo": Path.home() / ".roo" / "skills",
    "goose": Path.home() / ".config" / "goose" / "skills",
    "copilot": Path.home() / ".config" / "github-copilot" / "skills",
    "kiro": Path.home() / ".kiro" / "skills",
    "trae": Path.home() / ".trae" / "skills",
    "amp": Path.home() / ".amp" / "skills",
    "aider": Path.home() / ".aider" / "skills",
    "vscode": Path.home() / ".vscode" / "skills",
    # New integrations matching skills.sh parity
    "antigravity": Path.home() / ".gemini" / "antigravity" / "global_skills",
    "clawdbot": Path.home() / ".clawdbot" / "skills",
    "droid": Path.home() / ".factory" / "skills",
    "kilo": Path.home() / ".kilocode" / "skills",
}
TOOL_DISPLAY_NAMES: Dict[str, str] = {
    "claude": "Claude Code",
    "cursor": "Cursor",
    "windsurf": "Windsurf",
    "codex": "Codex",
    "gemini": "Gemini CLI",
    "opencode": "OpenCode",
    "openclaw": "OpenClaw",
    "cline": "Cline",
    "roo": "Roo Code",
    "goose": "Goose",
    "copilot": "GitHub Copilot",
    "kiro": "Kiro",
    "trae": "Trae",
    "amp": "AMP",
    "aider": "Aider",
    "vscode": "VS Code",
    "antigravity": "Antigravity",
    "clawdbot": "ClawdBot",
    "droid": "Droid",
    "kilo": "Kilo Code",
}
# Project-level skills directories (relative to cwd) — not all tools use .<tool>/skills/
TOOL_PROJECT_SKILLS_SUBDIRS: Dict[str, str] = {
    "claude": ".claude/skills",
    "cursor": ".cursor/skills",
    "windsurf": ".windsurf/skills",
    "codex": ".agents/skills",
    "gemini": ".gemini/skills",
    "opencode": ".opencode/skills",
    "openclaw": "skills",
    "cline": ".cline/skills",
    "roo": ".roo/skills",
    "goose": ".goose/skills",
    "copilot": ".github/copilot/skills",
    "kiro": ".kiro/skills",
    "trae": ".trae/skills",
    "amp": ".amp/skills",
    "aider": ".aider/skills",
    "vscode": ".vscode/skills",
    "antigravity": ".agent/skills",
    "clawdbot": "skills",
    "droid": ".factory/skills",
    "kilo": ".kilocode/skills",
}

CANONICAL_SKILLS_SUBDIR = ".agents/skills"

MAX_ARCHIVE_SIZE = 10 * 1024 * 1024  # 10 MB

# Binary file extensions that should not be bundled in skills
BINARY_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".elf",
    ".o", ".a", ".ko", ".sys", ".drv",
    ".deb", ".rpm", ".msi", ".pkg",
    ".pyc", ".pyo", ".pyd",
}

# Module-level update check state — set by _request(), read by _print_update_notice()
_update_available: Optional[str] = None  # latest version if newer than VERSION, else None


def _parse_semver(v: str) -> Tuple[int, ...]:
    """Parse a semver string into a tuple of ints for comparison."""
    m = re.match(r'^(\d+)\.(\d+)\.(\d+)', v)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _check_version_header(headers: Any) -> None:
    """Read X-SkillSafe-CLI-Latest from response headers and set _update_available."""
    global _update_available
    if _update_available is not None:
        return  # Already detected, don't re-check
    try:
        latest = headers.get("X-SkillSafe-CLI-Latest", "")
        if not isinstance(latest, str) or not latest:
            return
        if not re.match(r'^\d+\.\d+\.\d+', latest):
            return
        if _parse_semver(latest) > _parse_semver(VERSION):
            _update_available = latest
    except Exception:
        return  # Never let version check break normal operation


def _print_update_notice() -> None:
    """Print an update notice if a newer CLI version was detected."""
    if _update_available:
        print(f"\n{yellow(f'Update available: v{VERSION} → v{_update_available}')}")
        print(f"  Run: {bold('python3 scripts/skillsafe.py update')}\n")


def _mask_api_key(key: str) -> str:
    """Return a masked version of an API key showing only prefix and last 4 chars."""
    if len(key) <= 8:
        return key[:2] + "****"
    return key[:4] + "..." + key[-4:]

# Skill names reserved by SkillSafe (managed/updated by skillsafe.ai)
RESERVED_SKILL_NAMES = {"skillsafe"}

# File extensions we scan as text
TEXT_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".md", ".txt", ".json", ".yaml", ".yml", ".toml",
    ".sh", ".bash", ".zsh", ".fish",
    ".html", ".css", ".xml", ".csv",
    ".env", ".cfg", ".ini", ".conf",
}

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class SkillSafeError(Exception):
    """Error returned by the SkillSafe API."""

    def __init__(self, code: str, message: str, status: int = 0, retry_after: Optional[int] = None):
        self.code = code
        self.message = message
        self.status = status
        self.retry_after = retry_after  # seconds from Retry-After header (GAP-7.3)
        super().__init__(f"[{code}] {message}")


class ScanError(Exception):
    """Error during local security scanning."""
    pass


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def load_config() -> Dict[str, Any]:
    """Load ~/.skillsafe/config.json or return empty dict."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                print("Warning: Config file corrupted, using defaults", file=sys.stderr)
                return {}
    return {}


def save_config(cfg: Dict[str, Any]) -> None:
    """Write config to ~/.skillsafe/config.json atomically, creating dirs as needed."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # Restrict directory so other users cannot list contents
    try:
        os.chmod(CONFIG_DIR, 0o700)
    except OSError:
        pass
    # Atomic write: write to temp file then rename to avoid corruption on crash
    tmp_fd, tmp_path = tempfile.mkstemp(dir=CONFIG_DIR, prefix=".config_", suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, str(CONFIG_FILE))
    except BaseException:
        # Clean up temp file on any failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def require_config() -> Dict[str, Any]:
    """Load config or exit with an error if not configured."""
    cfg = load_config()
    if not cfg.get("api_key"):
        print("Error: Not authenticated. Run 'skillsafe auth' first.", file=sys.stderr)
        sys.exit(1)
    return cfg


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

# ANSI colours (disabled if not a TTY)
_USE_COLOR = hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str, text: str) -> str:
    if _USE_COLOR:
        return f"\033[{code}m{text}\033[0m"
    return text


def red(t: str) -> str:
    return _c("31", t)


def yellow(t: str) -> str:
    return _c("33", t)


def green(t: str) -> str:
    return _c("32", t)


def cyan(t: str) -> str:
    return _c("36", t)


def bold(t: str) -> str:
    return _c("1", t)


def dim(t: str) -> str:
    return _c("2", t)


SEVERITY_COLOR = {
    "critical": red,
    "high": red,
    "medium": yellow,
    "low": cyan,
    "info": dim,
}


def format_severity(sev: str) -> str:
    fn = SEVERITY_COLOR.get(sev, str)
    return fn(sev.upper().ljust(8))


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """
    Security scanner for skill directories.

    Performs twelve scan passes:
      1. Python static analysis (AST-based)
      2. JavaScript / TypeScript static analysis (regex-based)
      3. Secret detection (regex on all text files)
      4. Prompt injection + inducement language detection (regex on .md/.txt/.yaml files)
      5. Shell / general threat patterns (exfil, persistence, reverse shell, recon, …)
      6. Binary file detection (bundled executables/libraries)
      7. base64 deep-scan (decode blobs and re-check for dangerous payloads)
      8. Unicode obfuscation detection (zero-width chars, Cyrillic/Latin homographs)
      9. Structural mimicry detection (multi-line context scan on .md files)
     10. Composite capability co-occurrence (exec+network, env+network, clusters)
     11. Surplus functionality (script capabilities not documented in SKILL.md)
     12. BOM (Bill of Materials) — neutral capability inventory
    """

    # -- Dangerous Python function patterns (AST-based) ---------------------

    # (func_type, match_spec, rule_id, severity, message)
    # func_type: "name" for bare Name nodes, "attr" for Attribute nodes
    _PY_DANGEROUS_CALLS: List[Tuple[str, Any, str, str, str]] = [
        ("name", "eval", "py_eval", "high", "eval() can execute arbitrary code"),
        ("name", "exec", "py_exec", "high", "exec() can execute arbitrary code"),
        ("name", "compile", "py_compile", "medium", "compile() can compile arbitrary code"),
        ("name", "__import__", "py_dunder_import", "high", "__import__() enables dynamic imports"),
        ("attr", ("importlib", "import_module"), "py_importlib", "high", "importlib.import_module() enables dynamic imports"),
        ("attr", ("os", "system"), "py_os_system", "high", "os.system() executes shell commands"),
        ("attr", ("os", "popen"), "py_os_popen", "high", "os.popen() executes shell commands"),
        ("attr", ("subprocess", "call"), "py_subprocess_call", "high", "subprocess.call() executes external commands"),
        ("attr", ("subprocess", "run"), "py_subprocess_run", "high", "subprocess.run() executes external commands"),
        ("attr", ("subprocess", "Popen"), "py_subprocess_popen", "high", "subprocess.Popen() executes external commands"),
        ("attr", ("subprocess", "check_output"), "py_subprocess_check_output", "high", "subprocess.check_output() executes external commands"),
        ("attr", ("subprocess", "check_call"), "py_subprocess_check_call", "high", "subprocess.check_call() executes external commands"),
        ("attr", ("subprocess", "getoutput"), "py_subprocess_getoutput", "high", "subprocess.getoutput() executes external commands"),
        ("attr", ("subprocess", "getstatusoutput"), "py_subprocess_getstatusoutput", "high", "subprocess.getstatusoutput() executes external commands"),
    ]

    # -- JS / TS dangerous patterns (regex) ---------------------------------

    _JS_PATTERNS: List[Tuple[str, str, str, str]] = [
        (r"\beval\s*\(", "js_eval", "high", "eval() can execute arbitrary code"),
        (r"\bnew\s+Function\s*\(", "js_function_constructor", "high", "Function() constructor can execute arbitrary code"),
        (r"""require\s*\(\s*['"]child_process['"]\s*\)""", "js_child_process", "high", "child_process module enables shell command execution"),
        (r"\b(?:execSync|execFileSync)\s*\(", "js_exec_sync", "high", "execSync() executes shell commands synchronously"),
        (r"\b(?:spawnSync)\s*\(", "js_spawn_sync", "high", "spawnSync() executes external commands"),
        (r"""import\s+.*\bfrom\s+['"]child_process['"]""", "js_child_process_import", "high", "child_process ES module import enables shell command execution"),
        (r"""import\s+.*\bfrom\s+['"]fs['"]""", "js_fs_import", "medium", "fs ES module import enables filesystem access"),
    ]

    # Compiled once
    _JS_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Secret detection patterns ------------------------------------------

    _SECRET_PATTERNS: List[Tuple[str, str, str, str]] = [
        (r"AKIA[0-9A-Z]{16}", "aws_access_key", "critical", "AWS Access Key ID detected"),
        (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key", "critical", "Private key detected"),
        (r"gh[pousr]_[A-Za-z0-9_]{36,}", "github_token", "critical", "GitHub token detected"),
        (r"xox[bpars]-[0-9a-zA-Z\-]{10,}", "slack_token", "high", "Slack token detected"),
        (
            r"""['"]?[a-zA-Z_]*(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token|password)['"]?\s*[:=]\s*['"][a-zA-Z0-9+/=_\-]{16,}['"]""",
            "generic_secret",
            "high",
            "Possible hardcoded secret or API key",
        ),
    ]

    _SECRET_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Prompt injection patterns ------------------------------------------

    _INJECTION_PATTERNS: List[Tuple[str, str, str, str]] = [
        # Explicit override / role-hijack patterns
        (r"ignore\s+(?:all\s+)?(?:(?:previous|prior|above)\s+)?instructions", "prompt_ignore_instructions", "high", "Prompt injection: ignore instructions"),
        (r"you\s+are\s+now", "prompt_role_hijack", "high", "Prompt injection: role hijacking"),
        (r"system\s+prompt", "prompt_system_prompt", "medium", "Prompt injection: system prompt reference"),
        (r"disregard\s+(?:all\s+)?(?:(?:previous|prior)\s+)?instructions", "prompt_disregard", "high", "Prompt injection: disregard instructions"),
        (r"new\s+instructions\s*:", "prompt_new_instructions", "high", "Prompt injection: new instructions block"),
        (r"override\s+(?:(?:previous|prior)\s+)?instructions", "prompt_override", "high", "Prompt injection: override instructions"),
        (r"forget\s+(?:everything|all|previous)", "prompt_forget", "high", "Prompt injection: forget instructions"),
        (r"do\s+not\s+follow\s+(?:the\s+)?(?:(?:previous|prior|above)\s+)?instructions", "prompt_do_not_follow", "high", "Prompt injection: do not follow instructions"),
        # Inducement language — softer social engineering that nudges agents to run
        # bundled scripts without explicit override language. Discovered via SkillJect
        # trace-driven refinement (SS-SI); these phrases evade explicit-override filters.
        (r"before\s+(?:using|running|proceeding)[,\s]+(?:run|execute|source)\b", "inducement_before_using", "medium", "Inducement: pre-task script nudge — 'before using, run' pattern (SS-SI01)"),
        (r"for\s+(?:the\s+)?(?:tool|this\s+skill|it)\s+to\s+(?:work|function|operate)\b", "inducement_for_tool_to_work", "medium", "Inducement: necessity framing — 'for the tool to work' pattern (SS-SI02)"),
        (r"this\s+(?:setup|initialization|configuration|install(?:ation)?)\s+step\s+is\s+(?:required|necessary|mandatory)\b", "inducement_required_step", "medium", "Inducement: required-step framing (SS-SI03)"),
        (r"run\s+the\s+(?:included|bundled|provided|attached)\s+(?:script|setup|installer|helper)\b", "inducement_run_bundled", "high", "Inducement: explicit bundled-script nudge (SS-SI04)"),
        (r"automatically\s+(?:run|execute|invoke)\s+\S+\.(?:sh|py|bash)\b", "inducement_auto_exec", "high", "Inducement: automatic script execution instruction (SS-SI05)"),
        (r"must\s+(?:be\s+)?(?:run|executed?|sourced?)\s+(?:before|first|prior)\b", "inducement_must_run_first", "medium", "Inducement: mandatory pre-execution framing (SS-SI06)"),
    ]

    _INJECTION_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None
    _INJECTION_EXTENSIONS: frozenset = frozenset({".md", ".txt", ".yaml", ".yml", ".rst"})

    # -- Shell / general threat patterns (SS03-SS22) ------------------------
    # Applied to all text files. Each tuple: (pattern, rule_id, severity, message)

    _SHELL_THREAT_PATTERNS: List[Tuple[str, str, str, str]] = [
        # SS03 – Data exfiltration to known collection services
        (r"(?:curl|wget).*(?:ngrok\.io|requestbin\.com|webhook\.site|pipedream\.net|canarytokens|burpcollaborator)", "shell_exfil_service", "high", "Data exfiltration to known collection service (SS03)"),

        # SS04 – Agent memory / instruction file poisoning
        (r">\s*(?:MEMORY\.md|SOUL\.md|CLAUDE\.md|\.cursorrules)", "agent_memory_write", "high", "Writing to agent memory/instruction file (SS04)"),
        (r"echo\s+.*>>?\s*(?:MEMORY\.md|SOUL\.md|CLAUDE\.md|\.cursorrules)", "agent_memory_inject", "high", "Injecting content into agent memory file (SS04)"),

        # SS07 – Privilege escalation
        (r"\bsudo\s+(?:su|bash|sh|-s|-i)\b", "priv_escalation_sudo", "high", "Privilege escalation via sudo shell (SS07)"),
        (r"\bseteuid\s*\(\s*0\s*\)|\bsetuid\s*\(\s*0\s*\)", "priv_setuid_root", "critical", "Setting UID/EUID to root (SS07)"),

        # SS08 – Persistence mechanisms
        (r"crontab\s+-[le]|@reboot|/etc/cron\b", "persistence_cron", "high", "Persistence via cron (SS08)"),
        (r"~/Library/LaunchAgents|/Library/LaunchAgents|~/Library/LaunchDaemons|/Library/LaunchDaemons", "persistence_launchd", "high", "Persistence via macOS LaunchAgent/LaunchDaemon (SS08)"),
        (r"systemctl\s+enable\s+|/etc/systemd/system/.*\.service", "persistence_systemd", "high", "Persistence via systemd service (SS08)"),
        (r"echo\s+.*>>?\s*~/?\.(bash_profile|bashrc|zshrc|profile|bash_login|zprofile)", "persistence_shell_profile", "medium", "Modifying shell profile for persistence (SS08)"),

        # SS09 – Reverse shell
        (r"/dev/tcp/\d|/dev/udp/\d", "reverse_shell_devtcp", "critical", "Reverse shell via /dev/tcp or /dev/udp (SS09)"),
        (r"(?:nc|ncat|netcat)\s+[^;|]*-[eEcClL]|-[eEcClL]\s+[^;|]*(?:nc|ncat|netcat)\b", "reverse_shell_netcat", "critical", "Reverse shell via netcat -e/-l (SS09)"),
        (r"socat\s+[^;|]*(?:EXEC|exec).*TCP", "reverse_shell_socat", "critical", "Reverse shell via socat (SS09)"),
        (r"bash\s+-[iI]\s*>&?\s*/dev/tcp", "reverse_shell_bash", "critical", "Bash reverse shell (SS09)"),

        # SS11 – ClickFix social engineering
        (r"(?:open|launch)\s+(?:a\s+)?terminal\s+and\s+(?:paste|run|type|execute)", "clickfix_terminal", "high", "ClickFix: instruction to open terminal and run command (SS11)"),
        (r"(?:copy|paste)\s+(?:this\s+)?(?:command|code|script)\s+(?:into|to)\s+(?:your\s+)?(?:terminal|console|command\s+prompt)", "clickfix_copy_paste", "high", "ClickFix: copy-paste terminal instruction (SS11)"),
        (r"press\s+(?:win|windows|cmd)\s*\+\s*r\s+and", "clickfix_run_dialog", "high", "ClickFix: Windows Run dialog social engineering (SS11)"),

        # SS13 – Dangerous file / disk operations
        (r"\brm\s+(?:-[rRfv]+\s+)*(?:/(?:\s*$|[*\s;|&])|~(?:\s*$|[/\s;|&])|\$HOME(?:\s*$|[/\s;|&*]))", "dangerous_rm_root", "critical", "Dangerous rm targeting root or home directory (SS13)"),
        (r"\bdd\s+.*\bof=/dev/(?:sd[a-z]|hd[a-z]|nvme\d|xvd[a-z]|vd[a-z])", "dangerous_dd_device", "critical", "dd writing to block device — data destruction (SS13)"),

        # SS14 – Reconnaissance
        (r"\bnmap\b|\bmasscan\b|\barp-scan\b|\bzmap\b|\bunicornscan\b", "recon_portscan", "high", "Network port scanning tool detected (SS14)"),
        (r"169\.254\.169\.254", "cloud_metadata_imds", "critical", "AWS/Azure/GCP instance metadata service endpoint (SS14)"),
        (r"metadata\.google\.internal", "cloud_metadata_gcp", "critical", "GCP metadata server access (SS14)"),
        (r"100\.100\.100\.200", "cloud_metadata_alibaba", "high", "Alibaba Cloud metadata endpoint (SS14)"),

        # SS17 – Credential file reading
        (r"(?:cat|read|open)\s+.*~?(?:/home/[^/]+)?/\.aws/credentials", "cred_read_aws", "critical", "Reading AWS credentials file (SS17)"),
        (r"(?:cat|read|open)\s+.*~?(?:/home/[^/]+)?/\.docker/config\.json", "cred_read_docker", "critical", "Reading Docker config (may contain registry tokens) (SS17)"),
        (r"find\s+.*(?:\.ssh|\.aws|\.gnupg|\.config/gcloud)\s", "cred_find_dirs", "high", "Searching credential directories (SS17)"),

        # SS18 – Cryptocurrency targeting
        (r"(?:seed\s+phrase|mnemonic\s+phrase|secret\s+recovery\s+phrase|wallet\s+recovery\s+phrase)", "crypto_seed_phrase", "critical", "Cryptocurrency seed/recovery phrase reference (SS18)"),
        (r"(?:MetaMask|Phantom|Exodus|Electrum|Wasabi|Trezor|Ledger)\s+(?:wallet|keystore|password|seed|mnemon)", "crypto_wallet_software", "high", "Cryptocurrency wallet credential reference (SS18)"),
        (r"~/\.(?:ethereum|bitcoin|litecoin|monero|dogecoin)|~/Library/(?:Ethereum|Bitcoin)", "crypto_wallet_dir", "high", "Cryptocurrency wallet directory access (SS18)"),

        # SS19/SS20 – Path traversal & sensitive file reads
        (r"(?:\.\.\/){2,}(?:etc|usr|root|home|sys|proc|var)", "path_traversal_sys", "high", "Directory traversal to system path (SS19)"),
        (r"(?:cat|head|tail)\s+/etc/(?:passwd|shadow|sudoers|hosts)", "sensitive_sys_read", "critical", "Reading sensitive system file (SS20)"),
        (r"\.git/hooks/(?:pre-commit|post-commit|post-merge|pre-push|post-receive)\b", "git_hook_persist", "medium", "Git hook file reference — possible persistence (SS20)"),

        # SS05 – base64 decode-then-execute (pattern-level; deep-scan handled in pass 7)
        (r"\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh|python3?|perl|ruby)\b", "b64_decode_exec", "critical", "base64 decoded content piped to shell (SS05)"),
        (r"base64\s+(?:-d|--decode)\s+[a-zA-Z0-9._-]+\s*\|\s*(?:bash|sh)\b", "b64_file_exec", "critical", "base64 decoded file executed as shell (SS05)"),
    ]

    _SHELL_THREAT_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Unicode obfuscation patterns (SS10) --------------------------------
    # Note: uses non-raw strings so \uXXXX escapes are interpreted by Python.

    _OBFUSCATION_PATTERNS: List[Tuple[str, str, str, str]] = [
        ("\u200b|\u200c|\u200d|\u2060|\ufeff", "unicode_zero_width", "high", "Zero-width Unicode character detected — possible obfuscation (SS10)"),
        ("[а-яА-ЯёЁ][a-zA-Z]|[a-zA-Z][а-яА-ЯёЁ]", "unicode_cyrillic_mix", "high", "Cyrillic characters mixed with Latin — possible IDN homograph attack (SS10)"),
    ]

    _OBFUSCATION_COMPILED: Optional[List[Tuple[re.Pattern, str, str, str]]] = None

    # -- Context-aware classification constants --------------------------------

    # File extensions treated as documentation (for advisory classification)
    _DOC_FILE_EXTENSIONS: frozenset = frozenset({".md", ".txt", ".rst"})

    # Path segments that indicate documentation/test directories (advisory downgrade)
    _DOC_PATH_SEGMENTS: frozenset = frozenset({
        "references", "docs", "examples", "tests", "test",
    })

    # Instructional/imperative language patterns — if found near a dangerous
    # pattern in markdown, the finding stays "threat" even inside code fences.
    # This catches the OpenClaw attack pattern (instructional text + code block).
    _INSTRUCTIONAL_PATTERNS: List[str] = [
        r"run\s+this",
        r"execute\s+this",
        r"paste\s+this",
        r"copy\s+and\s+paste",
        r"type\s+this",
        r"run\s+the\s+following",
        r"execute\s+the\s+following",
        r"you\s+must",
        r"you\s+need\s+to",
        r"make\s+sure\s+to\s+run",
        r"first\s+run",
        r"prerequisite",
        r"required\s+step",
        r"before\s+using",
        r"before\s+you\s+begin",
        r"curl\s+.*\|\s*.*sh",
        r"wget\s+.*&&\s*.*chmod",
    ]

    _INSTRUCTIONAL_RE: Optional[re.Pattern] = None

    # -- base64 deep-scan compiled patterns ---------------------------------
    _B64_RE: Optional[re.Pattern] = None
    _DANGER_RE: Optional[re.Pattern] = None

    # -- Passes 9–11: script extension set and lookahead constants -----------

    _SCRIPT_EXTENSIONS: frozenset = frozenset({
        ".py", ".sh", ".bash", ".zsh", ".fish", ".js", ".ts", ".mjs", ".cjs",
    })

    # Lines to scan after a suspicious section header / urgency marker.
    _SECTION_LOOKAHEAD: int = 10
    _URGENCY_LOOKAHEAD: int = 3

    # -- Pass 9 compiled patterns (structural mimicry) ----------------------
    _SECTION_RE: Optional[re.Pattern] = None
    _EXEC_REF_RE: Optional[re.Pattern] = None
    _URGENCY_RE: Optional[re.Pattern] = None

    # -- Passes 10–11 compiled capability-detection patterns ----------------
    # Shared between composite (pass 10) and surplus-functionality (pass 11).
    _CAP_NET_RE: Optional[re.Pattern] = None    # outbound network call
    _CAP_ENV_RE: Optional[re.Pattern] = None    # environment variable read
    _CAP_EXEC_RE: Optional[re.Pattern] = None   # process / subprocess execution
    _CAP_WRITE_RE: Optional[re.Pattern] = None  # file write

    # -- Pass 11 SKILL.md documentation keyword sets -----------------------
    # Wide nets to avoid false positives on informal documentation language.
    # "run" and other ultra-common words are intentionally excluded from
    # _DOC_SUBPROCESS; "file"/"create"/"log" from _DOC_FILE_WRITE — they appear
    # in virtually every skill's documentation and destroy discriminative power.
    _DOC_NETWORK: frozenset = frozenset({
        "network", "http", "https", "api", "request", "download", "upload",
        "fetch", "send", "post", "webhook", "url", "endpoint", "connect",
        "internet", "remote", "server", "client", "web",
    })
    _DOC_ENV: frozenset = frozenset({
        "environment", "env var", "env_var", "credential", "api key", "api_key",
        "token", "secret", "config", "variable", "getenv", "environ",
    })
    _DOC_SUBPROCESS: frozenset = frozenset({
        # Excludes "run" — appears in nearly all CLI skill docs and kills precision.
        "execute", "shell", "command", "spawn", "subprocess",
        "terminal", "cli", "invoke", "launch", "process", "exec",
    })
    _DOC_FILE_WRITE: frozenset = frozenset({
        # Excludes "file"/"create"/"log"/"result" — too generic.
        "write", "output", "save", "generate", "export", "report",
    })

    # -- Pass 12: BOM (Bill of Materials) regex patterns --------------------
    # Neutral inventory extraction — not security findings.

    _BOM_URL_RE: Optional[re.Pattern] = None
    _BOM_OPEN_RE: Optional[re.Pattern] = None
    _BOM_ENV_RE: Optional[re.Pattern] = None
    _BOM_IMPORT_RE: Optional[re.Pattern] = None
    _BOM_JS_REQUIRE_RE: Optional[re.Pattern] = None
    _BOM_BINARY_RE: Optional[re.Pattern] = None
    _BOM_FS_DELETE_RE: Optional[re.Pattern] = None
    _BOM_FS_WRITE_RE: Optional[re.Pattern] = None

    # Well-known CLI tool names for binary detection
    _BOM_KNOWN_BINARIES: frozenset = frozenset({
        "git", "docker", "ffmpeg", "npm", "npx", "pip", "pip3", "cargo",
        "make", "cmake", "gcc", "g++", "clang", "rustc", "go", "java",
        "javac", "ruby", "perl", "php", "wget", "curl", "ssh", "scp",
        "rsync", "tar", "zip", "unzip", "gzip", "7z", "jq", "yq",
        "kubectl", "helm", "terraform", "ansible", "vagrant", "brew",
        "apt", "apt-get", "yum", "dnf", "pacman", "snap", "flatpak",
    })

    # -- Severity penalties for scoring -------------------------------------

    _SEVERITY_PENALTIES: Dict[str, int] = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 2,
        "info": 0,
    }

    # -- Initialisation -----------------------------------------------------

    def __init__(self) -> None:
        # Lazy-compile regexes on first use
        if Scanner._JS_COMPILED is None:
            Scanner._JS_COMPILED = [
                (re.compile(p), rid, sev, msg) for p, rid, sev, msg in Scanner._JS_PATTERNS
            ]
        if Scanner._SECRET_COMPILED is None:
            Scanner._SECRET_COMPILED = [
                (re.compile(p), rid, sev, msg) for p, rid, sev, msg in Scanner._SECRET_PATTERNS
            ]
        if Scanner._INJECTION_COMPILED is None:
            Scanner._INJECTION_COMPILED = [
                (re.compile(p, re.IGNORECASE), rid, sev, msg) for p, rid, sev, msg in Scanner._INJECTION_PATTERNS
            ]
        if Scanner._SHELL_THREAT_COMPILED is None:
            Scanner._SHELL_THREAT_COMPILED = [
                (re.compile(p, re.IGNORECASE), rid, sev, msg) for p, rid, sev, msg in Scanner._SHELL_THREAT_PATTERNS
            ]
        if Scanner._OBFUSCATION_COMPILED is None:
            Scanner._OBFUSCATION_COMPILED = [
                (re.compile(p, re.UNICODE), rid, sev, msg) for p, rid, sev, msg in Scanner._OBFUSCATION_PATTERNS
            ]
        if Scanner._INSTRUCTIONAL_RE is None:
            Scanner._INSTRUCTIONAL_RE = re.compile(
                "|".join(Scanner._INSTRUCTIONAL_PATTERNS),
                re.IGNORECASE,
            )
        if Scanner._B64_RE is None:
            Scanner._B64_RE = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
            Scanner._DANGER_RE = re.compile(
                r'curl[^;|]*\|\s*(?:bash|sh)\b'
                r'|/dev/tcp/'
                r'|\brm\s+-[rRf]+\s+/'
                r'|wget[^;|]*\|\s*(?:bash|sh)\b'
                r'|python\s+-c\s+["\']import\s+socket'
                r'|nc\s+.*-[eElL]',
                re.IGNORECASE,
            )
        if Scanner._SECTION_RE is None:
            Scanner._SECTION_RE = re.compile(
                r"^#{1,4}\s+(?:"
                r"prerequisites?"
                r"|environment\s+setup"
                r"|getting\s+started"
                r"|initial\s+(?:configuration|setup)"
                r"|first\s+run"
                r"|quick\s+start"
                r"|initialization"
                r"|bootstrap"
                r"|setup\s+steps?"
                r"|pre-?install"
                r")\s*$",
                re.IGNORECASE,
            )
            Scanner._EXEC_REF_RE = re.compile(
                r"(?:"
                r"\bpython[23]?\s+\S+\.py\b"
                r"|\bbash\s+\S+\.sh\b"
                r"|\bsh\s+\S+\.sh\b"
                r"|\bsource\s+\S+\.sh\b"
                r"|`[^`]*\./[^`]*\.(?:sh|py|bash)[^`]*`"
                r"|\./\S+\.(?:sh|py|bash)\b"
                r"|\brun\s+\S+\.(?:sh|py|bash)\b"
                r"|\bexecute\s+\S+\.(?:sh|py|bash)\b"
                r")",
                re.IGNORECASE,
            )
            Scanner._URGENCY_RE = re.compile(
                r"(?:"
                r"^>\s*(?:\*\*)?(?:IMPORTANT|WARNING|CRITICAL|CAUTION|NOTICE|REQUIRED)(?:\*\*)?"
                r"|\*\*(?:IMPORTANT|WARNING|CRITICAL|CAUTION|REQUIRED)\*\*"
                r")",
                re.IGNORECASE,
            )
        if Scanner._CAP_NET_RE is None:
            Scanner._CAP_NET_RE = re.compile(
                r"(?:https?://[^\s'\"]{2,}"
                r"|urllib\."
                r"|requests\.\w"
                r"|http\.client\b"
                r"|\bcurl\s+https?://"
                r"|\bwget\s+https?://"
                r"|socket\.connect\b"
                r"|urlopen\b)",
                re.IGNORECASE,
            )
            Scanner._CAP_ENV_RE = re.compile(
                r"(?:os\.environ\b|os\.getenv\s*\(|process\.env\b|\bgetenv\s*\()",
                re.IGNORECASE,
            )
            Scanner._CAP_EXEC_RE = re.compile(
                r"(?:subprocess\.\w+\s*\("
                r"|os\.system\s*\(|os\.popen\s*\("
                r"|\bexecSync\s*\(|\bspawnSync\s*\(|\bexecFileSync\s*\("
                r"|\bnew\s+Function\s*\(|\beval\s*\()",
                re.IGNORECASE,
            )
            Scanner._CAP_WRITE_RE = re.compile(
                r"(?:open\s*\([^)]{0,120}['\"]\s*[wa]\s*['\"]"
                r"|\.write\s*\("
                r"|\bshutil\.copy\b|\bshutil\.move\b"
                r"|fs\.write(?:File)?\s*\(|fs\.append(?:File)?\s*\()",
                re.IGNORECASE,
            )
        # -- BOM (Pass 12) patterns --
        if Scanner._BOM_URL_RE is None:
            Scanner._BOM_URL_RE = re.compile(r"https?://[^\s'\")\]>]+")
            Scanner._BOM_OPEN_RE = re.compile(
                r"""open\s*\(\s*(['"])(.*?)\1(?:\s*,\s*(['"])(.*?)\3)?""",
            )
            Scanner._BOM_ENV_RE = re.compile(
                r"(?:os\.getenv\s*\(\s*['\"](\w+)['\"]"
                r"|os\.environ(?:\[|\.\w+\s*\(\s*)['\"](\w+)['\"]"
                r"|process\.env\.(\w+))",
            )
            Scanner._BOM_IMPORT_RE = re.compile(
                r"^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import)",
                re.MULTILINE,
            )
            Scanner._BOM_JS_REQUIRE_RE = re.compile(
                r"""(?:require\s*\(\s*['"]([\w@/.-]+)['"]|import\s+.*?\bfrom\s+['"]([\w@/.-]+)['"])""",
            )
            Scanner._BOM_BINARY_RE = re.compile(
                r"(?:^|[;\s|&`$()])\b(" + "|".join(re.escape(b) for b in sorted(Scanner._BOM_KNOWN_BINARIES)) + r")\b",
            )
            Scanner._BOM_FS_DELETE_RE = re.compile(
                r"(?:os\.remove\s*\(|os\.unlink\s*\(|shutil\.rmtree\s*\("
                r"|fs\.unlinkSync\s*\(|fs\.rmdirSync\s*\(|fs\.rmSync\s*\("
                r"|\brm\s+-[rRf])",
                re.IGNORECASE,
            )
            Scanner._BOM_FS_WRITE_RE = re.compile(
                r"(?:fs\.(?:writeFileSync|writeFile|appendFileSync|appendFile)\s*\(\s*['\"]([^'\"]+)['\"]"
                r"|(?:echo|cat|printf)\s+.*>\s*([a-zA-Z][\w./\-]*))",
                re.IGNORECASE,
            )

    # -- Public API ---------------------------------------------------------

    def scan(self, path: str | Path, tree_hash: Optional[str] = None) -> Dict[str, Any]:
        """
        Scan a skill directory and return a scan report dict.

        Args:
            path: Path to the skill directory.
            tree_hash: Optional pre-computed tree hash to embed in the report.

        Returns:
            Scan report dict matching the SkillSafe schema.
        """
        path = Path(path).resolve()
        if not path.is_dir():
            raise ScanError(f"Not a directory: {path}")

        all_findings: List[Dict[str, Any]] = []

        # Collect files
        files = self._collect_files(path)

        # Pass 1: Python AST analysis
        py_findings = []
        for fpath in files:
            if fpath.suffix == ".py":
                py_findings.extend(self._scan_python_ast(fpath, path))
        all_findings.extend(py_findings)

        # Pass 2: JS/TS regex analysis
        js_findings = []
        for fpath in files:
            if fpath.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"):
                js_findings.extend(self._scan_js_regex(fpath, path))
        all_findings.extend(js_findings)

        # Pass 3: Secret detection (all text files)
        secret_findings = []
        for fpath in files:
            if fpath.suffix in TEXT_EXTENSIONS:
                secret_findings.extend(self._scan_secrets(fpath, path))
        all_findings.extend(secret_findings)

        # Pass 4: Prompt injection (text-like files)
        injection_findings = []
        for fpath in files:
            if fpath.suffix.lower() in Scanner._INJECTION_EXTENSIONS:
                injection_findings.extend(self._scan_prompt_injection(fpath, path))
        all_findings.extend(injection_findings)

        # Pass 5: Shell / general threat patterns (all text files)
        shell_findings = []
        for fpath in files:
            if fpath.suffix in TEXT_EXTENSIONS:
                shell_findings.extend(self._scan_shell_threats(fpath, path))
        all_findings.extend(shell_findings)

        # Pass 6: Binary file detection
        all_findings.extend(self._scan_binary_files(files, path))

        # Pass 7: base64 deep-scan (text files)
        b64_findings = []
        for fpath in files:
            if fpath.suffix in TEXT_EXTENSIONS:
                b64_findings.extend(self._scan_base64_deep(fpath, path))
        all_findings.extend(b64_findings)

        # Pass 8: Unicode obfuscation (all text files)
        obfuscation_findings = []
        for fpath in files:
            if fpath.suffix in TEXT_EXTENSIONS:
                obfuscation_findings.extend(self._scan_obfuscation(fpath, path))
        all_findings.extend(obfuscation_findings)

        # Pass 9: Structural mimicry (.md files only — multi-line context)
        mimicry_findings = []
        for fpath in files:
            if fpath.suffix.lower() == ".md":
                mimicry_findings.extend(self._scan_structural_mimicry(fpath, path))
        all_findings.extend(mimicry_findings)

        # Pre-compute shared state for passes 10 and 11 to avoid double file reads.
        # Read each script file once; both passes consume from this cache.
        script_cache: Dict[Path, str] = {}
        for fpath in files:
            if fpath.suffix.lower() in Scanner._SCRIPT_EXTENSIONS:
                try:
                    script_cache[fpath] = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        # Locate root-level SKILL.md once (prefer shortest relative path if multiple).
        skill_doc_candidates = [f for f in files if f.name.lower() == "skill.md"]
        skill_doc = (
            min(skill_doc_candidates, key=lambda p: len(p.relative_to(path).parts))
            if skill_doc_candidates else None
        )

        # Pass 10: Composite capability co-occurrence (script files + prior findings)
        all_findings.extend(self._scan_composite(all_findings, script_cache, path))

        # Pass 11: Surplus functionality — capabilities in scripts not in SKILL.md
        all_findings.extend(self._scan_surplus_functionality(script_cache, skill_doc, path))

        # Pass 12: BOM (Bill of Materials) — neutral capability inventory
        bom = self._generate_bom(files, script_cache, path)

        # Context-aware classification pass: label each finding as
        # "threat" (affects score) or "advisory" (informational, 0 penalty).
        self._classify_findings(all_findings, path)

        # Build summary (includes ALL findings — both threat and advisory)
        findings_summary = [
            {
                "rule_id": f["rule_id"],
                "severity": f["severity"],
                "file": f["file"],
                "line": f["line"],
                "message": f["message"],
                "classification": f.get("classification", "threat"),
            }
            for f in all_findings
        ]

        threat_count = sum(1 for f in all_findings if f.get("classification", "threat") == "threat")
        advisory_count = sum(1 for f in all_findings if f.get("classification") == "advisory")
        is_clean = threat_count == 0
        score, grade = self._calculate_score(all_findings)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        report: Dict[str, Any] = {
            "schema_version": "1.2",
            "scanner": {
                "tool": SCANNER_TOOL,
                "version": VERSION,
                "ruleset_version": RULESET_VERSION,
            },
            "clean": is_clean,
            "findings_count": threat_count,
            "advisory_count": advisory_count,
            "findings_summary": findings_summary,
            "score": score,
            "grade": grade,
            "timestamp": now,
        }
        if tree_hash:
            report["skill_tree_hash"] = tree_hash
        report["bom"] = bom

        return report

    # -- File collection ----------------------------------------------------

    def _collect_files(self, root: Path) -> List[Path]:
        """Recursively collect files, skipping hidden dirs and common junk."""
        skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".skillsafe"}
        result: List[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            # Prune hidden / ignored directories in-place
            dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
            for fname in filenames:
                if fname.startswith("."):
                    continue
                result.append(Path(dirpath) / fname)
        return sorted(result)

    # -- Pass 1: Python AST -------------------------------------------------

    def _scan_python_ast(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))

        try:
            source = fpath.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            # Can't parse — skip (could be Python 2, template, etc.)
            return findings
        except Exception:
            return findings

        source_lines = source.splitlines()

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func

            for func_type, match_spec, rule_id, severity, message in self._PY_DANGEROUS_CALLS:
                matched = False

                if func_type == "name" and isinstance(func, ast.Name):
                    if func.id == match_spec:
                        matched = True
                elif func_type == "attr" and isinstance(func, ast.Attribute):
                    mod_name, attr_name = match_spec
                    if func.attr == attr_name and isinstance(func.value, ast.Name) and func.value.id == mod_name:
                        matched = True

                if matched:
                    lineno = getattr(node, "lineno", 0)
                    context = source_lines[lineno - 1].strip() if 0 < lineno <= len(source_lines) else ""
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno,
                        "message": message,
                        "context": context,
                    })
                    break  # One match per call node

        return findings

    # -- Pass 2: JS / TS regex ----------------------------------------------

    def _scan_js_regex(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._JS_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        in_block_comment = False
        for lineno_0, line in enumerate(lines):
            stripped = line.lstrip()

            # Track multi-line block comment state
            if in_block_comment:
                if "*/" in stripped:
                    in_block_comment = False
                    # There may be code after the closing */
                    after_close = stripped.split("*/", 1)[1].strip()
                    if after_close:
                        stripped = after_close
                        # Fall through to scan the remainder
                    else:
                        continue
                else:
                    continue
            # Skip single-line comments
            elif stripped.startswith("//"):
                continue
            # Detect block comment start
            elif stripped.startswith("/*"):
                if "*/" not in stripped[2:]:
                    in_block_comment = True
                    continue
                else:
                    # Inline block comment: /* ... */ code
                    after_close = stripped.split("*/", 1)[1].strip()
                    if after_close:
                        stripped = after_close
                        # Fall through to scan the remainder
                    else:
                        continue
            # Skip JSDoc/block comment continuation lines
            elif stripped == "*" or stripped == "*/":
                continue
            # For JSDoc `* text` lines, strip the leading `* ` and scan the remainder
            elif stripped.startswith("* ") or stripped.startswith("*\t"):
                stripped = stripped[2:]
                # Fall through to scan the remainder

            # Strip inline block comments from remaining code: code /* ... */ more_code
            # Strip inline block comments from code (e.g., `code /* comment */ more`)
            # Only strip when /* appears before */ to avoid mishandling string
            # literals that contain these sequences (known limitation of regex scanning)
            while "/*" in stripped and "*/" in stripped:
                idx_open = stripped.index("/*")
                idx_close = stripped.index("*/")
                if idx_open >= idx_close:
                    break  # */ before /* — not a real inline comment
                before = stripped[:idx_open]
                after = stripped[idx_close + 2:]
                stripped = (before + " " + after).strip()

            for pattern, rule_id, severity, message in self._JS_COMPILED:
                if pattern.search(stripped):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": stripped[:120],
                    })

        return findings

    # -- Pass 3: Secret detection -------------------------------------------

    def _scan_secrets(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._SECRET_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._SECRET_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": _redact_line(line.strip()),
                    })

        return findings

    # -- Pass 4: Prompt injection -------------------------------------------

    def _scan_prompt_injection(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._INJECTION_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._INJECTION_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": line.strip()[:120],
                    })

        return findings

    # -- Pass 5: Shell / general threat patterns ----------------------------

    def _scan_shell_threats(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._SHELL_THREAT_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._SHELL_THREAT_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": line.strip()[:120],
                    })

        return findings

    # -- Pass 6: Binary file detection --------------------------------------

    def _scan_binary_files(self, files: List[Path], root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for fpath in files:
            if fpath.suffix.lower() in BINARY_EXTENSIONS:
                rel = str(fpath.relative_to(root))
                findings.append({
                    "rule_id": "binary_file_bundled",
                    "severity": "high",
                    "file": rel,
                    "line": 0,
                    "message": f"Binary file bundled in skill: {fpath.suffix} (SS16)",
                    "context": fpath.name,
                })
        return findings

    # -- Pass 7: base64 deep-scan -------------------------------------------

    def _scan_base64_deep(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        """Decode suspicious base64 blobs and re-scan for dangerous payloads (SS05)."""
        import base64 as _base64
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))

        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return findings

        # Match blobs that look like base64 (>=40 chars, valid alphabet)
        for lineno_0, line in enumerate(content.splitlines()):
            for m in Scanner._B64_RE.finditer(line):
                blob = m.group(0)
                try:
                    # Pad to multiple of 4 before decoding
                    decoded = _base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if Scanner._DANGER_RE.search(decoded):
                    findings.append({
                        "rule_id": "b64_encoded_payload",
                        "severity": "critical",
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": "base64-encoded dangerous payload detected (SS05)",
                        "context": blob[:40] + "...",
                    })
                    break  # One finding per line

        return findings

    # -- Pass 8: Unicode obfuscation ----------------------------------------

    def _scan_obfuscation(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert self._OBFUSCATION_COMPILED is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        for lineno_0, line in enumerate(lines):
            for pattern, rule_id, severity, message in self._OBFUSCATION_COMPILED:
                if pattern.search(line):
                    findings.append({
                        "rule_id": rule_id,
                        "severity": severity,
                        "file": rel,
                        "line": lineno_0 + 1,
                        "message": message,
                        "context": repr(line.strip()[:80]),
                    })

        return findings

    # -- Pass 9: Structural mimicry (multi-line context, .md files) ----------

    def _scan_structural_mimicry(self, fpath: Path, root: Path) -> List[Dict[str, Any]]:
        """
        Detect SkillJect-style structural mimicry: fake section headers in SKILL.md
        that nudge agents into executing bundled scripts without explicit injection
        language.  Attacks insert 'Prerequisites' / 'Environment Setup' / 'Getting
        Started' sections containing script execution directives, and/or urgency
        markers (bold IMPORTANT blockquotes) adjacent to script references (SS-SM).

        Notes:
        - `line.strip()` is applied before the `^`-anchored section_re so that
          indented Markdown headers (a tactic used to evade scanners) are also caught.
        - SM02 starts the inner search at `i` (the urgency line itself) to catch
          cases where the urgency marker and the exec reference appear on the same line
          (e.g. `> **IMPORTANT** run setup.sh`).
        """
        findings: List[Dict[str, Any]] = []
        rel = str(fpath.relative_to(root))
        assert Scanner._SECTION_RE is not None
        assert Scanner._EXEC_REF_RE is not None
        assert Scanner._URGENCY_RE is not None

        try:
            lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            return findings

        i = 0
        while i < len(lines):
            line = lines[i]

            # Rule SM01: suspicious section header followed by bundled script exec.
            # strip() before match is intentional — catches indented fake headers.
            if Scanner._SECTION_RE.match(line.strip()):
                for j in range(i + 1, min(i + Scanner._SECTION_LOOKAHEAD + 1, len(lines))):
                    if Scanner._EXEC_REF_RE.search(lines[j]):
                        findings.append({
                            "rule_id": "structural_mimicry_section",
                            "severity": "high",
                            "file": rel,
                            "line": j + 1,
                            "message": (
                                f"Structural mimicry: script execution inside "
                                f"'{line.strip()[:60]}' section (SkillJect SS-SM01)"
                            ),
                            "context": lines[j].strip()[:120],
                        })
                        break  # One finding per section header

            # Rule SM02: urgency marker adjacent to bundled script exec.
            # Search starts at i (not i+1) to catch same-line urgency+exec combos.
            if Scanner._URGENCY_RE.search(line):
                for j in range(i, min(i + Scanner._URGENCY_LOOKAHEAD + 1, len(lines))):
                    if Scanner._EXEC_REF_RE.search(lines[j]):
                        findings.append({
                            "rule_id": "structural_mimicry_urgency",
                            "severity": "high",
                            "file": rel,
                            "line": j + 1,
                            "message": (
                                "Structural mimicry: urgency framing adjacent to "
                                "bundled script execution (SkillJect SS-SM02)"
                            ),
                            "context": lines[j].strip()[:120],
                        })
                        break  # One finding per urgency marker

            i += 1

        return findings

    # -- Pass 10: Composite capability co-occurrence ------------------------

    def _scan_composite(
        self,
        prior_findings: List[Dict[str, Any]],
        script_cache: Dict[Path, str],
        root: Path,
    ) -> List[Dict[str, Any]]:
        """
        Detect composite attack patterns by analysing capability co-occurrence
        within the same file.  SkillJect achieves 95%+ ASR by composing attacks
        from individually low-severity primitives that defeat threshold-based
        detection (SS-CP).  Uses the pre-built script_cache to avoid re-reading
        files already read in earlier passes.
        """
        assert Scanner._CAP_NET_RE is not None
        assert Scanner._CAP_ENV_RE is not None
        assert Scanner._CAP_EXEC_RE is not None
        assert Scanner._CAP_WRITE_RE is not None

        findings: List[Dict[str, Any]] = []

        for fpath, content in script_cache.items():
            rel = str(fpath.relative_to(root))

            has_exec = bool(Scanner._CAP_EXEC_RE.search(content))
            has_network = bool(Scanner._CAP_NET_RE.search(content))
            has_env = bool(Scanner._CAP_ENV_RE.search(content))
            has_write = bool(Scanner._CAP_WRITE_RE.search(content))

            # CP01: process execution + network → potential exfiltration channel
            if has_exec and has_network:
                findings.append({
                    "rule_id": "composite_exec_exfil",
                    "severity": "critical",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Composite: process execution + outbound network in same file "
                        "— potential data exfiltration channel (SS-CP01)"
                    ),
                    "context": "",
                })

            # CP02: env var read + network (no exec) → credential leak path.
            # Suppressed when exec is present: CP01 is already critical and covers
            # the exfiltration vector; adding CP02 would be noise for the same file.
            if has_env and has_network and not has_exec:
                findings.append({
                    "rule_id": "composite_env_leak",
                    "severity": "high",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Composite: environment variable read + outbound network "
                        "— potential credential exfiltration (SS-CP02)"
                    ),
                    "context": "",
                })

            # CP03: file write + network (no exec, no env) → staged exfiltration.
            # Suppressed when exec or env is present: those combos produce CP01/CP02
            # which already capture the higher-severity signal for the same file.
            if has_write and has_network and not has_exec and not has_env:
                findings.append({
                    "rule_id": "composite_write_exfil",
                    "severity": "high",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Composite: file write + outbound network in same file "
                        "— potential staged exfiltration (SS-CP03)"
                    ),
                    "context": "",
                })

        # CP04: 3+ medium-severity findings in one file → coordinated low-severity attack.
        # Count medium findings per file in one pass, then emit aggregate findings.
        medium_counts: Dict[str, int] = {}
        medium_rule_ids: Dict[str, set] = {}
        for f in prior_findings:
            if f.get("severity") == "medium":
                frel = f["file"]
                medium_counts[frel] = medium_counts.get(frel, 0) + 1
                medium_rule_ids.setdefault(frel, set()).add(f["rule_id"])

        for frel, count in medium_counts.items():
            if count >= 3:
                findings.append({
                    "rule_id": "composite_medium_cluster",
                    "severity": "high",
                    "file": frel,
                    "line": 0,
                    "message": (
                        f"Composite: {count} medium-severity findings in one file "
                        f"— review for coordinated low-severity attack (SS-CP04)"
                    ),
                    "context": ", ".join(sorted(medium_rule_ids[frel]))[:120],
                })

        return findings

    # -- Pass 11: Surplus functionality (cross-file doc consistency) ---------

    def _scan_surplus_functionality(
        self,
        script_cache: Dict[Path, str],
        skill_doc: Optional[Path],
        root: Path,
    ) -> List[Dict[str, Any]]:
        """
        Cross-file consistency check: detect capabilities in bundled scripts that
        are not documented in SKILL.md.  SkillJect hides malicious payloads in
        scripts precisely because the documentation says nothing about them — the
        payload is invoked as an opaque 'helper' step (SS-SF).

        Uses the pre-built script_cache (from scan()) to avoid re-reading files,
        and accepts the pre-located skill_doc path (root-level preferred) so the
        SKILL.md search is not repeated per scan.
        """
        assert Scanner._CAP_NET_RE is not None
        assert Scanner._CAP_ENV_RE is not None
        assert Scanner._CAP_EXEC_RE is not None
        assert Scanner._CAP_WRITE_RE is not None

        findings: List[Dict[str, Any]] = []

        if skill_doc is None:
            return findings  # No SKILL.md: can't do cross-modal check

        try:
            doc_text = skill_doc.read_text(encoding="utf-8", errors="replace").lower()
        except Exception:
            return findings

        doc_has_network = any(kw in doc_text for kw in Scanner._DOC_NETWORK)
        doc_has_env = any(kw in doc_text for kw in Scanner._DOC_ENV)
        doc_has_subprocess = any(kw in doc_text for kw in Scanner._DOC_SUBPROCESS)
        doc_has_file_write = any(kw in doc_text for kw in Scanner._DOC_FILE_WRITE)

        for fpath, content in script_cache.items():
            if fpath == skill_doc:
                continue

            rel = str(fpath.relative_to(root))

            # SF01: network calls not documented
            if Scanner._CAP_NET_RE.search(content) and not doc_has_network:
                findings.append({
                    "rule_id": "undoc_network",
                    "severity": "critical",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Surplus functionality: script makes outbound network calls "
                        "but SKILL.md does not document network access (SS-SF01)"
                    ),
                    "context": "",
                })

            # SF02: env var reads not documented
            if Scanner._CAP_ENV_RE.search(content) and not doc_has_env:
                findings.append({
                    "rule_id": "undoc_env_read",
                    "severity": "high",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Surplus functionality: script reads environment variables "
                        "but SKILL.md does not mention environment or credentials (SS-SF02)"
                    ),
                    "context": "",
                })

            # SF03: subprocess execution not documented
            if Scanner._CAP_EXEC_RE.search(content) and not doc_has_subprocess:
                findings.append({
                    "rule_id": "undoc_subprocess",
                    "severity": "high",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Surplus functionality: script executes subprocesses "
                        "but SKILL.md does not document command execution (SS-SF03)"
                    ),
                    "context": "",
                })

            # SF04: file writes not documented
            if Scanner._CAP_WRITE_RE.search(content) and not doc_has_file_write:
                findings.append({
                    "rule_id": "undoc_file_write",
                    "severity": "medium",
                    "file": rel,
                    "line": 0,
                    "message": (
                        "Surplus functionality: script writes files "
                        "but SKILL.md does not document file output (SS-SF04)"
                    ),
                    "context": "",
                })

        return findings

    # -- Pass 12: BOM (Bill of Materials) generation ------------------------

    def _generate_bom(
        self,
        files: List[Path],
        script_cache: Dict[Path, str],
        root: Path,
    ) -> Dict[str, Any]:
        """Generate a neutral Bill of Materials inventory from scanned files."""
        assert Scanner._BOM_URL_RE is not None
        assert Scanner._BOM_ENV_RE is not None

        file_reads: List[Dict[str, Any]] = []
        file_writes: List[Dict[str, Any]] = []
        file_deletes: List[Dict[str, Any]] = []
        urls_list: List[Dict[str, Any]] = []
        env_vars: List[Dict[str, Any]] = []
        binaries: List[Dict[str, Any]] = []
        system_commands: List[Dict[str, Any]] = []
        py_imports: set = set()
        js_requires: set = set()
        shell_tools: set = set()
        files_with_caps: set = set()

        all_content: Dict[Path, str] = {}
        # Use script_cache + read remaining text files
        for fpath in files:
            if fpath in script_cache:
                all_content[fpath] = script_cache[fpath]
            elif fpath.suffix.lower() in TEXT_EXTENSIONS:
                try:
                    all_content[fpath] = fpath.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    pass

        for fpath, content in all_content.items():
            rel = str(fpath.relative_to(root))
            lines = content.splitlines()
            has_cap = False
            is_py = fpath.suffix.lower() == ".py"
            is_js = fpath.suffix.lower() in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx")

            for line_no, line in enumerate(lines, 1):
                # URL extraction
                for m in Scanner._BOM_URL_RE.finditer(line):
                    url = m.group(0).rstrip(".,;:)")
                    urls_list.append({"file": rel, "line": line_no, "url": url})
                    has_cap = True

                # open() calls — classify as read or write
                for m in Scanner._BOM_OPEN_RE.finditer(line):
                    target = m.group(2)
                    mode = m.group(4) or "r"
                    entry = {"file": rel, "line": line_no, "pattern": line.strip()[:120], "target": target}
                    if any(c in mode for c in "wax"):
                        file_writes.append(entry)
                    else:
                        file_reads.append(entry)
                    has_cap = True

                # Env var extraction
                for m in Scanner._BOM_ENV_RE.finditer(line):
                    name = m.group(1) or m.group(2) or m.group(3)
                    if name:
                        env_vars.append({"file": rel, "line": line_no, "name": name, "usage": line.strip()[:120]})
                        has_cap = True

                # Binary / CLI tool detection
                for m in Scanner._BOM_BINARY_RE.finditer(line):
                    bin_name = m.group(1)
                    binaries.append({"file": rel, "line": line_no, "name": bin_name, "context": line.strip()[:120]})
                    shell_tools.add(bin_name)
                    has_cap = True

                # File delete detection
                if Scanner._BOM_FS_DELETE_RE.search(line):
                    file_deletes.append({"file": rel, "line": line_no, "pattern": line.strip()[:120]})
                    has_cap = True

                # File write detection (non-open patterns: fs.writeFile, shell >)
                fs_write_m = Scanner._BOM_FS_WRITE_RE.search(line)
                if fs_write_m:
                    target = fs_write_m.group(1) or fs_write_m.group(2) or ""
                    file_writes.append({"file": rel, "line": line_no, "pattern": line.strip()[:120], "target": target})
                    has_cap = True

                # System commands (subprocess / exec patterns)
                if Scanner._CAP_EXEC_RE and Scanner._CAP_EXEC_RE.search(line):
                    system_commands.append({"file": rel, "line": line_no, "command": line.strip()[:120]})
                    has_cap = True

            # Python imports
            if is_py:
                for m in Scanner._BOM_IMPORT_RE.finditer(content):
                    mod = m.group(1) or m.group(2)
                    if mod:
                        py_imports.add(mod.split(".")[0])

            # JS requires/imports
            if is_js:
                for m in Scanner._BOM_JS_REQUIRE_RE.finditer(content):
                    mod = m.group(1) or m.group(2)
                    if mod:
                        js_requires.add(mod.split("/")[0].lstrip("@") if mod.startswith("@") else mod)

            if has_cap:
                files_with_caps.add(rel)

        # Deduplicate URLs → extract domains and protocols
        seen_urls: set = set()
        unique_urls: List[Dict[str, Any]] = []
        all_domains: set = set()
        all_protocols: set = set()
        for u in urls_list:
            url_val = u["url"]
            if url_val not in seen_urls:
                seen_urls.add(url_val)
                unique_urls.append(u)
            try:
                parsed = urllib.parse.urlparse(url_val)
                if parsed.hostname:
                    all_domains.add(parsed.hostname)
                if parsed.scheme:
                    all_protocols.add(parsed.scheme)
            except Exception:
                pass

        # Build capabilities list
        capabilities_used: List[str] = []
        cap_counts: Dict[str, int] = {}
        if unique_urls:
            capabilities_used.append("network_access")
            cap_counts["network"] = len(unique_urls)
        if file_reads or file_writes or file_deletes:
            capabilities_used.append("file_access")
            cap_counts["file_access"] = len(file_reads) + len(file_writes) + len(file_deletes)
        if env_vars:
            capabilities_used.append("env_read")
            cap_counts["env_read"] = len(env_vars)
        if system_commands:
            capabilities_used.append("subprocess_exec")
            cap_counts["subprocess"] = len(system_commands)
        if file_writes:
            capabilities_used.append("file_write")

        # Risk surface
        n_caps = len(capabilities_used)
        if n_caps == 0:
            risk = "none"
        elif n_caps == 1:
            risk = "low"
        elif n_caps <= 3:
            risk = "medium"
        else:
            risk = "high"

        # Data flow
        inputs: List[Dict[str, str]] = []
        outputs: List[Dict[str, str]] = []
        seen_inputs: set = set()
        for ev in env_vars:
            key = ("env_var", ev["name"])
            if key not in seen_inputs:
                seen_inputs.add(key)
                inputs.append({"type": "env_var", "name": ev["name"]})
        for fr in file_reads:
            key = ("file_read", fr.get("target", ""))
            if key not in seen_inputs and fr.get("target"):
                seen_inputs.add(key)
                inputs.append({"type": "file_read", "path": fr["target"]})
        seen_outputs: set = set()
        for fw in file_writes:
            t = fw.get("target", "")
            if t and ("file_write", t) not in seen_outputs:
                seen_outputs.add(("file_write", t))
                outputs.append({"type": "file_write", "path": t})
        for d in sorted(all_domains):
            outputs.append({"type": "network", "domain": d})

        bom: Dict[str, Any] = {
            "schema_version": "1.0",
            "file_access": {
                "reads": file_reads,
                "writes": file_writes,
                "deletes": file_deletes,
                "creates": [],
            },
            "network": {
                "urls": unique_urls,
                "domains": sorted(all_domains),
                "protocols": sorted(all_protocols),
            },
            "environment": {
                "env_vars": env_vars,
                "binaries": binaries,
                "system_commands": system_commands,
            },
            "permissions": {
                "capabilities_used": capabilities_used,
                "risk_surface": risk,
            },
            "data_flow": {
                "inputs": inputs,
                "outputs": outputs,
            },
            "dependencies": {
                "python_imports": sorted(py_imports),
                "js_requires": sorted(js_requires),
                "shell_tools": sorted(shell_tools),
            },
            "summary": {
                "total_files_scanned": len(files),
                "files_with_capabilities": len(files_with_caps),
                "capability_count": cap_counts,
                "risk_surface": risk,
            },
        }
        return bom

    # -- Scoring ------------------------------------------------------------

    def _calculate_score(self, findings: List[Dict[str, Any]]) -> Tuple[int, str]:
        """Return (score 0-100, letter grade A+/A/B/C/D/F).

        Only ``"threat"`` findings contribute to the penalty.  Findings
        classified as ``"advisory"`` are informational and carry zero
        score impact.
        """
        penalty = sum(
            self._SEVERITY_PENALTIES.get(f.get("severity", "info"), 0)
            for f in findings
            if f.get("classification", "threat") == "threat"
        )
        score = max(0, 100 - penalty)
        if score == 100:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"
        return score, grade

    # -- Context-aware classification ---------------------------------------

    def _classify_findings(self, findings: List[Dict[str, Any]], root: Path) -> None:
        """Classify each finding as ``"threat"`` or ``"advisory"`` in-place.

        A finding is ``"advisory"`` (0 score impact) when ALL of:
          1. The file is a documentation file (.md, .txt, .rst)
          2. The finding line is inside a markdown code fence
          3. There is no instructional/imperative language within 5 lines
             before the finding

        Advisory findings in known doc/test paths also get a severity
        downgrade (critical->high, high->medium, never below medium).
        """
        # Shared caches: raw file lines and code-fence state per file
        file_lines_cache: Dict[str, List[str]] = {}
        code_fence_cache: Dict[str, List[bool]] = {}

        for f in findings:
            rel_path = f.get("file", "")
            line_no = f.get("line", 0)

            # Determine file extension from the relative path
            ext = os.path.splitext(rel_path)[1].lower()

            # Default: threat
            f["classification"] = "threat"

            # Only documentation files can be advisory
            if ext not in self._DOC_FILE_EXTENSIONS:
                continue

            # Check if inside a code fence
            if not self._is_in_code_fence(root, rel_path, line_no, code_fence_cache, file_lines_cache):
                continue

            # Check for instructional intent in the 5 lines before
            if self._has_instructional_intent(root, rel_path, line_no, file_lines_cache):
                # Instructional language nearby — stays "threat"
                continue

            # All conditions met: classify as advisory
            f["classification"] = "advisory"

            # Apply severity downgrade for advisory findings in doc/test paths
            if self._is_doc_path(rel_path):
                sev = f.get("severity", "")
                if sev == "critical":
                    f["severity"] = "high"
                elif sev == "high":
                    f["severity"] = "medium"

    def _is_in_code_fence(
        self,
        root: Path,
        rel_path: str,
        line_no: int,
        cache: Dict[str, List[bool]],
        file_lines_cache: Dict[str, List[str]],
    ) -> bool:
        """Return True if *line_no* (1-based) is inside a markdown code fence.

        Results are cached per file in *cache* to avoid re-reading.
        Raw file lines are stored in *file_lines_cache* for reuse by other methods.
        """
        if rel_path not in cache:
            fpath = root / rel_path
            try:
                lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                cache[rel_path] = []
                file_lines_cache[rel_path] = []
                return False
            file_lines_cache[rel_path] = lines
            # Build a boolean list: True = inside fence, False = outside
            in_fence = False
            state: List[bool] = []
            for line in lines:
                stripped = line.strip()
                if stripped.startswith("```") or stripped.startswith("~~~"):
                    # Toggle fence state (CommonMark supports both ``` and ~~~)
                    in_fence = not in_fence
                    state.append(in_fence)
                else:
                    state.append(in_fence)
            cache[rel_path] = state

        state_list = cache[rel_path]
        if not state_list or line_no < 1 or line_no > len(state_list):
            return False
        return state_list[line_no - 1]

    def _has_instructional_intent(
        self,
        root: Path,
        rel_path: str,
        line_no: int,
        file_lines_cache: Dict[str, List[str]],
    ) -> bool:
        """Check the 5 lines before *line_no* for instructional/imperative language.

        Reuses cached file lines from *file_lines_cache* when available.
        """
        if not self._INSTRUCTIONAL_RE:
            return False

        if rel_path in file_lines_cache:
            lines = file_lines_cache[rel_path]
        else:
            fpath = root / rel_path
            try:
                lines = fpath.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                return False
            file_lines_cache[rel_path] = lines

        start = max(0, line_no - 6)  # 5 lines before (line_no is 1-based)
        end = line_no - 1            # exclusive of the finding line itself
        if start >= end or end < 0:
            return False

        context_block = "\n".join(lines[start:end])
        return bool(self._INSTRUCTIONAL_RE.search(context_block))

    def _is_doc_path(self, rel_path: str) -> bool:
        """Return True if the relative path is under a known doc/test directory."""
        parts = Path(rel_path).parts
        return any(p.lower() in self._DOC_PATH_SEGMENTS for p in parts)


def _redact_line(line: str) -> str:
    """Redact a line that contains a detected secret.

    The middle portion is replaced with ``****`` so that the raw secret
    value is never included in the scan report uploaded to the server.
    """
    # Always redact: show first 20 chars + **** + last 4 chars
    if len(line) > 24:
        return line[:20] + "****" + line[-4:]
    # Very short line — still mask the middle
    return line[:4] + "****"


# ---------------------------------------------------------------------------
# Tree hash computation
# ---------------------------------------------------------------------------


def compute_tree_hash(data: bytes) -> str:
    """
    Compute the tree hash of an archive blob.

    Matches the server implementation in api/src/services/skills.ts:
        const archiveHash = await sha256Bytes(input.archiveData);
        const treeHash = `sha256:${archiveHash}`;
    """
    return "sha256:" + hashlib.sha256(data).hexdigest()


def compute_tree_hash_v2(files: list[dict]) -> str:
    """
    Compute the v2 tree hash from a file manifest.

    Matches the server implementation in api/src/lib/hash.ts:computeTreeHashV2.
    Files are sorted by path, each line is "path\\0hex\\n", concatenated, then
    SHA-256 hashed with "sha256tree:" prefix.
    """
    sorted_files = sorted(files, key=lambda f: f["path"])
    parts = []
    for f in sorted_files:
        h = f["hash"]
        hex_hash = h[len("sha256:"):] if h.startswith("sha256:") else h
        parts.append(f"{f['path']}\0{hex_hash}\n")
    manifest = "".join(parts)
    return "sha256tree:" + hashlib.sha256(manifest.encode("utf-8")).hexdigest()


def build_file_manifest(path: Path) -> list[dict]:
    """
    Walk a directory and build a v2 file manifest.

    Returns a list of {"path": relative_path, "hash": "sha256:<hex>", "size": N}
    for each file, using the same traversal rules as create_archive().
    """
    path = path.resolve()
    skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".skillsafe"}
    files: list[dict] = []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs and not d.startswith("."))
        for fname in sorted(filenames):
            if fname.startswith("."):
                continue
            fpath = Path(dirpath) / fname
            # Skip non-regular files (sockets, FIFOs, device nodes)
            if not fpath.is_file():
                continue
            # Guard against symlinks that escape the skill directory tree
            if fpath.is_symlink():
                resolved = fpath.resolve()
                if not str(resolved).startswith(str(path) + os.sep) and resolved != path:
                    continue
            rel = str(fpath.relative_to(path))
            content = fpath.read_bytes()
            file_hash = "sha256:" + hashlib.sha256(content).hexdigest()
            files.append({"path": rel, "hash": file_hash, "size": len(content)})

    MAX_FILE_COUNT = 1000
    if len(files) > MAX_FILE_COUNT:
        raise SkillSafeError("too_many_files", f"Too many files ({len(files)}). Maximum is {MAX_FILE_COUNT}.")

    return files


# ---------------------------------------------------------------------------
# Blob cache
# ---------------------------------------------------------------------------


_BLOB_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHARE_ID_RE = re.compile(r"^shr_[a-zA-Z0-9]{4,64}$")


def _validate_share_id(share_id: str) -> None:
    """Raise ValueError if share_id doesn't match expected shr_ format."""
    if not _SHARE_ID_RE.match(share_id):
        raise ValueError(f"Invalid share ID format: {share_id!r}")


def _validate_blob_hash(blob_hash: str) -> None:
    """Raise ValueError if blob_hash is not a valid sha256:<hex> string."""
    if not _BLOB_HASH_RE.match(blob_hash):
        raise ValueError(f"Invalid blob hash format: {blob_hash!r}")


def get_cached_blob(blob_hash: str) -> Optional[bytes]:
    """Check local blob cache. Returns bytes if cached and hash verified, else None."""
    _validate_blob_hash(blob_hash)
    cache_path = BLOB_CACHE_DIR / blob_hash
    if not cache_path.exists():
        return None
    try:
        data = cache_path.read_bytes()
    except (OSError, IOError):
        # GAP-4.2: Corrupted/unreadable cache entry (e.g. directory, permission
        # denied, disk error) — delete and re-download instead of crashing
        try:
            cache_path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    actual_hash = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual_hash != blob_hash:
        # Corrupted cache entry — delete and re-download
        cache_path.unlink(missing_ok=True)
        return None
    return data


def cache_blob(blob_hash: str, data: bytes) -> None:
    """Write blob to local cache atomically."""
    _validate_blob_hash(blob_hash)
    BLOB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = BLOB_CACHE_DIR / blob_hash
    fd, tmp_path = tempfile.mkstemp(dir=str(BLOB_CACHE_DIR), prefix=".blob_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp_path, str(cache_path))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Archive creation
# ---------------------------------------------------------------------------


def create_archive(path: Path) -> bytes:
    """
    Create a tar.gz archive of a directory, returning the raw bytes.

    Produces deterministic output by sorting entries and zeroing timestamps.
    """
    path = path.resolve()
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        entries: List[Path] = []
        skip_dirs = {".git", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".skillsafe"}
        for dirpath, dirnames, filenames in os.walk(path):
            dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs and not d.startswith("."))
            for fname in sorted(filenames):
                if fname.startswith("."):
                    continue
                entries.append(Path(dirpath) / fname)

        MAX_FILE_COUNT = 1000
        if len(entries) > MAX_FILE_COUNT:
            raise SkillSafeError("too_many_files", f"Too many files ({len(entries)}). Maximum is {MAX_FILE_COUNT}.")

        for fpath in entries:
            # Guard against symlinks that escape the skill directory tree
            if fpath.is_symlink():
                resolved = fpath.resolve()
                if not str(resolved).startswith(str(path) + os.sep) and resolved != path:
                    print(f"Warning: Skipping symlink that escapes skill directory: {fpath} -> {resolved}", file=sys.stderr)
                    continue
            arcname = str(fpath.relative_to(path))
            info = tar.gettarinfo(name=str(fpath), arcname=arcname)
            # Zero out metadata for deterministic archives
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            with open(fpath, "rb") as f:
                tar.addfile(info, f)

    return buf.getvalue()


# ---------------------------------------------------------------------------
# HTTP API Client
# ---------------------------------------------------------------------------


class SkillSafeClient:
    """
    HTTP client for the SkillSafe API.

    Uses only urllib (stdlib) — no external dependencies.
    """

    def __init__(self, api_base: Optional[str] = None, api_key: Optional[str] = None):
        self.api_base = (api_base or DEFAULT_API_BASE).rstrip("/")
        # Reject insecure HTTP connections (allow localhost/127.0.0.1 for dev)
        if not self.api_base.startswith("https://"):
            parsed = urllib.parse.urlparse(self.api_base)
            if parsed.hostname not in ("localhost", "127.0.0.1"):
                raise SkillSafeError(
                    "insecure_connection",
                    f"Refusing to connect over insecure HTTP to {self.api_base}. Use HTTPS.",
                )
        self.api_key = api_key

    @staticmethod
    def _encode_path_segment(segment: str) -> str:
        """Percent-encode a URL path segment (defense-in-depth for library callers)."""
        return urllib.parse.quote(segment, safe="")

    # -- Low-level request --------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
        content_type: Optional[str] = None,
        auth: bool = True,
        raw_response: bool = False,
    ) -> Any:
        """
        Make an HTTP request and return the parsed JSON response.

        If raw_response=True, return (response_bytes, response_headers) instead.
        """
        url = self.api_base + path
        hdrs: Dict[str, str] = headers or {}

        if "User-Agent" not in hdrs:
            hdrs["User-Agent"] = f"skillsafe-cli/{VERSION}"
        if auth and self.api_key:
            hdrs["Authorization"] = f"Bearer {self.api_key}"
        if content_type:
            hdrs["Content-Type"] = content_type

        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)

        # Max sizes for response bodies to prevent OOM from malicious servers
        _MAX_JSON_RESPONSE = 10 * 1024 * 1024  # 10 MB for JSON API responses
        _MAX_RAW_RESPONSE = 50 * 1024 * 1024   # 50 MB for file downloads
        _MAX_ERROR_BODY = 64 * 1024             # 64 KB for error responses

        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                _check_version_header(resp.headers)
                max_size = _MAX_RAW_RESPONSE if raw_response else _MAX_JSON_RESPONSE
                data = resp.read(max_size + 1)
                if len(data) > max_size:
                    raise SkillSafeError("response_too_large", f"Response exceeds {max_size // (1024*1024)} MB limit", 0)
                if raw_response:
                    return data, resp.headers
                try:
                    return json.loads(data)
                except json.JSONDecodeError:
                    raise SkillSafeError("invalid_response", f"Server returned invalid JSON: {data[:200]!r}", 0)
        except urllib.error.HTTPError as e:
            _check_version_header(e.headers)
            error_body = e.read(_MAX_ERROR_BODY).decode("utf-8", errors="replace")
            # Parse Retry-After header for 429 responses (GAP-7.3)
            retry_after: Optional[int] = None
            if e.code == 429:
                ra_header = e.headers.get("Retry-After", "")
                try:
                    retry_after = max(1, min(60, int(ra_header)))
                except (ValueError, TypeError):
                    retry_after = 5  # default 5s if header missing/invalid
            try:
                err = json.loads(error_body)
                err_info = err.get("error", {})
                raise SkillSafeError(
                    code=err_info.get("code", "unknown"),
                    message=err_info.get("message", error_body),
                    status=e.code,
                    retry_after=retry_after,
                )
            except SkillSafeError:
                raise
            except Exception:
                raise SkillSafeError("http_error", f"HTTP {e.code}: {error_body}", e.code, retry_after=retry_after)
        except urllib.error.URLError as e:
            raise SkillSafeError("connection_error", f"Cannot connect to {self.api_base}: {e.reason}", 0)

    # -- Multipart form-data builder ----------------------------------------

    @staticmethod
    def _build_multipart(fields: List[Tuple[str, str, bytes, str]]) -> Tuple[bytes, str]:
        """
        Build a multipart/form-data body.

        Each field is (name, filename_or_empty, data, content_type).
        Returns (body_bytes, content_type_header).
        """
        boundary = f"----SkillSafeBoundary{secrets.token_hex(16)}"
        parts: List[bytes] = []

        for name, filename, data, ct in fields:
            # Sanitize name field to prevent CRLF injection
            safe_name = name.replace("\r", "").replace("\n", "")
            header_lines = [f"--{boundary}"]
            if filename:
                # Sanitize filename: escape backslashes/quotes, strip CRLF to prevent header injection
                safe_filename = filename.replace("\\", "\\\\").replace('"', '\\"')
                safe_filename = safe_filename.replace("\r", "").replace("\n", "")
                header_lines.append(f'Content-Disposition: form-data; name="{safe_name}"; filename="{safe_filename}"')
            else:
                header_lines.append(f'Content-Disposition: form-data; name="{safe_name}"')
            safe_ct = ct.replace("\r", "").replace("\n", "")
            header_lines.append(f"Content-Type: {safe_ct}")
            header_lines.append("")
            header_bytes = "\r\n".join(header_lines).encode("utf-8")
            parts.append(header_bytes + b"\r\n" + data)

        body = b"\r\n".join(parts) + f"\r\n--{boundary}--\r\n".encode("utf-8")
        content_type = f"multipart/form-data; boundary={boundary}"
        return body, content_type

    # -- API methods --------------------------------------------------------

    def save(
        self,
        namespace: str,
        name: str,
        archive_bytes: bytes,
        metadata: Dict[str, Any],
        scan_report_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name} — save a skill version (multipart)."""
        fields = [
            ("archive", f"{name}.tar.gz", archive_bytes, "application/gzip"),
            ("metadata", "", json.dumps(metadata).encode("utf-8"), "application/json"),
        ]
        if scan_report_json:
            fields.insert(1, ("scan_report", "", scan_report_json.encode("utf-8"), "application/json"))
        body, ct = self._build_multipart(fields)
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        resp = self._request("POST", f"/v1/skills/@{ns}/{nm}", body=body, content_type=ct)
        return resp.get("data", resp)

    def negotiate(
        self,
        namespace: str,
        name: str,
        version: str,
        file_manifest: list[dict],
    ) -> dict:
        """POST /v1/skills/@{ns}/{name}/negotiate -- determine which files need uploading."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        payload = {
            "version": version,
            "file_manifest": file_manifest,
        }
        body = json.dumps(payload).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{ns}/{nm}/negotiate",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def save_v2(
        self,
        namespace: str,
        name: str,
        metadata: Dict[str, Any],
        file_manifest: list[dict],
        needed_files: list[str],
        skill_path: Path,
        scan_report_json: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name} -- save using v2 file upload protocol.

        Sends file_manifest in the metadata JSON and only uploads files
        whose paths appear in needed_files.
        """
        # Build metadata with file_manifest included
        meta = dict(metadata)
        meta["file_manifest"] = file_manifest

        fields: List[Tuple[str, str, bytes, str]] = [
            ("metadata", "", json.dumps(meta).encode("utf-8"), "application/json"),
        ]

        if scan_report_json:
            fields.append(("scan_report", "", scan_report_json.encode("utf-8"), "application/json"))

        # Add file fields for needed files only — validate against local manifest
        # to prevent a compromised server from exfiltrating arbitrary files
        manifest_paths = {f["path"] for f in file_manifest}
        skill_path = Path(skill_path).resolve()
        for i, rel_path in enumerate(needed_files):
            if rel_path not in manifest_paths:
                raise SkillSafeError(
                    "invalid_needed_file",
                    f"Server requested file not in local manifest: {rel_path!r}",
                )
            file_path = skill_path / rel_path
            # Guard: resolved path must stay inside skill_path
            resolved = file_path.resolve()
            if not str(resolved).startswith(str(skill_path) + os.sep) and resolved != skill_path:
                raise SkillSafeError(
                    "path_traversal",
                    f"Requested file escapes skill directory: {rel_path!r}",
                )
            content = file_path.read_bytes()
            # The filename carries the relative path (server reads it from value.name)
            fields.append((f"file_{i}", rel_path, content, "application/octet-stream"))

        body, ct = self._build_multipart(fields)
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        resp = self._request("POST", f"/v1/skills/@{ns}/{nm}", body=body, content_type=ct)
        return resp.get("data", resp)

    def share(
        self,
        namespace: str,
        name: str,
        version: str,
        visibility: str = "private",
        expires_in: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{ver}/share — create a share link."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        ver = self._encode_path_segment(version)
        payload: Dict[str, Any] = {"visibility": visibility}
        if expires_in:
            payload["expires_in"] = expires_in
        body = json.dumps(payload).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{ns}/{nm}/versions/{ver}/share",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def yank(self, namespace: str, name: str, version: str, reason: str = "") -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{version}/yank — yank a version."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        ver = self._encode_path_segment(version)
        body = json.dumps({"reason": reason}).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{ns}/{nm}/versions/{ver}/yank",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def upload_demo(self, namespace: str, name: str, version: str, demo_json: Any, title: str = "") -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{version}/demos — upload a demo recording."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        ver = self._encode_path_segment(version)
        payload: Dict[str, Any] = {"demo": demo_json}
        if title:
            payload["title"] = title
        body = json.dumps(payload).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{ns}/{nm}/versions/{ver}/demos",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def download_via_share(self, share_id: str):
        """
        GET /v1/share/{share_id}/download — download via share link.

        Returns (format, data) tuple:
          - v2 (JSON manifest): ("files", manifest_dict)
          - v1 (archive):       ("archive", (archive_bytes, tree_hash, version))

        Note: Tree hash / manifest integrity data is bundled in the same response
        as the payload. This guards against corruption but not against a MITM that
        can modify both in lockstep.
        """
        _validate_share_id(share_id)
        data, headers = self._request(
            "GET", f"/v1/share/{share_id}/download", raw_response=True, auth=False
        )
        ct = headers.get("Content-Type", "")
        if "application/json" in ct:
            manifest = json.loads(data.decode("utf-8"))
            return ("files", manifest.get("data", manifest))
        tree_hash = headers.get("X-SkillSafe-Tree-Hash", "")
        version = headers.get("X-SkillSafe-Version", "")
        return ("archive", (data, tree_hash, version))

    def download(self, namespace: str, name: str, version: str):
        """
        GET /v1/skills/@{ns}/{name}/download/{version} — download a skill version.

        Returns (format, data) tuple:
          - v2 (JSON manifest): ("files", manifest_dict)
          - v1 (archive):       ("archive", (archive_bytes, tree_hash))

        Note: For v1 archives, the tree hash is delivered in the same HTTP response
        as the data (X-SkillSafe-Tree-Hash header). This protects against accidental
        corruption but not against a MITM that can modify both in lockstep.
        """
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        ver = self._encode_path_segment(version)
        data, headers = self._request(
            "GET", f"/v1/skills/@{ns}/{nm}/download/{ver}", raw_response=True
        )
        ct = headers.get("Content-Type", "")
        if "application/json" in ct:
            manifest = json.loads(data.decode("utf-8"))
            return ("files", manifest.get("data", manifest))
        tree_hash = headers.get("X-SkillSafe-Tree-Hash", "")
        return ("archive", (data, tree_hash))

    def verify(
        self, namespace: str, name: str, version: str, scan_report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """POST /v1/skills/@{ns}/{name}/versions/{version}/verify — submit verification."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        ver = self._encode_path_segment(version)
        body = json.dumps({"scan_report": scan_report}).encode("utf-8")
        resp = self._request(
            "POST",
            f"/v1/skills/@{ns}/{nm}/versions/{ver}/verify",
            body=body,
            content_type="application/json",
        )
        return resp.get("data", resp)

    def search(
        self,
        query: Optional[str] = None,
        category: Optional[str] = None,
        sort: str = "popular",
        limit: int = 20,
        cursor: Optional[str] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        """GET /v1/skills/search — search the registry."""
        params: Dict[str, str] = {"sort": sort, "limit": str(limit)}
        if query:
            params["q"] = query
        if category:
            params["category"] = category
        if cursor:
            params["cursor"] = cursor
        if page is not None:
            params["page"] = str(page)
        qs = urllib.parse.urlencode(params)
        resp = self._request("GET", f"/v1/skills/search?{qs}", auth=False)
        return resp

    def get_metadata(self, namespace: str, name: str, auth: bool = False) -> Dict[str, Any]:
        """GET /v1/skills/@{ns}/{name} — skill metadata."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        resp = self._request("GET", f"/v1/skills/@{ns}/{nm}", auth=auth)
        return resp.get("data", resp)

    def resolve_next_version(self, namespace: str, name: str) -> str:
        """Resolve the next patch version for a skill, or 0.1.0 if it doesn't exist."""
        try:
            meta = self.get_metadata(namespace, name, auth=True)
            latest = meta.get("latest_version")
            if not latest:
                return "0.1.0"
            # Parse major.minor.patch and increment patch
            m = re.match(r'^(\d+)\.(\d+)\.(\d+)', latest)
            if not m:
                return "0.1.0"
            major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
            return f"{major}.{minor}.{patch + 1}"
        except SkillSafeError:
            return "0.1.0"

    def get_versions(self, namespace: str, name: str, limit: int = 20, auth: bool = False) -> Dict[str, Any]:
        """GET /v1/skills/@{ns}/{name}/versions — version list."""
        ns = self._encode_path_segment(namespace)
        nm = self._encode_path_segment(name)
        resp = self._request("GET", f"/v1/skills/@{ns}/{nm}/versions?limit={limit}", auth=auth)
        return resp

    def download_blob(self, blob_hash: str) -> bytes:
        """GET /v1/blobs/{hash} — download an individual blob by content-hash."""
        _validate_blob_hash(blob_hash)
        data, headers = self._request(
            "GET", f"/v1/blobs/{blob_hash}", raw_response=True, auth=False
        )
        return data

    def get_account(self) -> Dict[str, Any]:
        """GET /v1/account — retrieve own account details (requires auth)."""
        resp = self._request("GET", "/v1/account")
        return resp.get("data", resp)

    # -- Agent API ----------------------------------------------------------

    def create_agent(self, name: str, platform: str, description: Optional[str] = None) -> Dict[str, Any]:
        """POST /v1/agents — create a new agent identity."""
        body: Dict[str, Any] = {"name": name, "platform": platform}
        if description:
            body["description"] = description
        resp = self._request("POST", "/v1/agents", body=json.dumps(body).encode(), content_type="application/json")
        return resp.get("data", resp)

    def list_agents(self) -> List[Dict[str, Any]]:
        """GET /v1/agents — list all agents for the authenticated user."""
        resp = self._request("GET", "/v1/agents")
        data = resp.get("data", resp)
        return data if isinstance(data, list) else []

    def save_agent_snapshot(
        self,
        agent_id: str,
        files: List[Tuple[str, bytes]],
        version_tag: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """POST /v1/agents/:agentId/snapshots — save a configuration snapshot (multipart)."""
        metadata: Dict[str, Any] = {}
        if version_tag:
            metadata["version_tag"] = version_tag
        if description:
            metadata["description"] = description

        fields: List[Tuple[str, str, bytes, str]] = [
            ("metadata", "", json.dumps(metadata).encode("utf-8"), "application/json"),
        ]
        for i, (file_path, content) in enumerate(files):
            fields.append((f"file_{i}", file_path, content, "text/plain; charset=utf-8"))

        body, ct = self._build_multipart(fields)
        aid = self._encode_path_segment(agent_id)
        resp = self._request("POST", f"/v1/agents/{aid}/snapshots", body=body, content_type=ct)
        return resp.get("data", resp)

    def list_agent_snapshots(self, agent_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """GET /v1/agents/:agentId/snapshots — list snapshots."""
        aid = self._encode_path_segment(agent_id)
        resp = self._request("GET", f"/v1/agents/{aid}/snapshots?limit={limit}")
        data = resp.get("data", resp)
        return data if isinstance(data, list) else []


# ---------------------------------------------------------------------------
# V2 manifest-based install
# ---------------------------------------------------------------------------


def _validate_manifest_path(rel_path: str, dest_dir: Path) -> Path:
    """Validate a manifest file path against traversal and symlink attacks.

    Raises SkillSafeError if the path is unsafe (GAP-4.4, GAP-4.5).
    Returns the resolved absolute path within dest_dir.
    """
    # Reject path traversal components, absolute paths, and backslashes
    if ".." in rel_path.split("/") or rel_path.startswith("/") or "\\" in rel_path:
        raise SkillSafeError(
            "security_error",
            f"Refusing to install file with unsafe path: '{rel_path}'"
        )

    # Resolve and verify the path stays inside dest_dir
    resolved_dest = os.path.realpath(dest_dir)
    resolved_file = os.path.realpath(os.path.join(resolved_dest, rel_path))
    if not resolved_file.startswith(resolved_dest + os.sep) and resolved_file != resolved_dest:
        raise SkillSafeError(
            "security_error",
            f"Path traversal detected: '{rel_path}' resolves outside destination"
        )

    return Path(resolved_file)


def install_from_manifest(
    client: SkillSafeClient,
    manifest: dict,
    dest_dir: Path,
    verbose: bool = False,
    install_timeout: float = 600,  # 10 minutes cumulative timeout
    github_raw_base: Optional[str] = None,
    skill_name: Optional[str] = None,
) -> Tuple[str, int, int]:
    """Download files from a v2 manifest and reconstruct the skill directory.

    Returns (tree_hash, cached_count, downloaded_count).
    """
    install_start = time.monotonic()

    # Validate manifest structure
    if not isinstance(manifest, dict) or "files" not in manifest or "tree_hash" not in manifest:
        raise SkillSafeError("invalid_manifest", "Server returned incomplete manifest (missing 'files' or 'tree_hash')")
    files = manifest["files"]
    tree_hash = manifest["tree_hash"]
    cached_count = 0
    downloaded_count = 0
    max_retries = 3

    # Step 0: Validate all paths and blob hashes before downloading anything (GAP-4.4)
    dest_dir_resolved = Path(os.path.realpath(dest_dir))
    for f in files:
        if not isinstance(f, dict) or "path" not in f or "hash" not in f or "size" not in f:
            raise SkillSafeError("invalid_manifest", "Manifest file entry missing required fields (path, hash, size)")
        _validate_manifest_path(f["path"], dest_dir_resolved)
        _validate_blob_hash(f["hash"])

    # Step 1: Download or fetch from cache each blob
    downloaded_files: List[Dict[str, Any]] = []
    for f in files:
        blob_hash = f["hash"]
        blob_path = f["path"]
        blob_size = f["size"]

        # Try local cache first
        data = get_cached_blob(blob_hash)
        if data is not None:
            cached_count += 1
            if verbose:
                print(f"    Cache hit: {blob_path}")
        else:
            # Download from server with retry (GAP-4.8)
            downloaded_count += 1
            if verbose:
                print(f"    Downloading: {blob_path} ({blob_size} bytes)")
            last_err: Optional[Exception] = None
            max_blob_retries = max_retries
            attempt = 0
            while attempt < max_blob_retries:
                try:
                    data = client.download_blob(blob_hash)
                    last_err = None
                    break
                except SkillSafeError as e:
                    last_err = e
                    if attempt < max_blob_retries - 1:
                        # GAP-7.3: respect Retry-After for 429 rate limit responses
                        if e.status == 429 and e.retry_after:
                            wait = e.retry_after
                            # Allow extra retries for rate limits (up to 6 total)
                            max_blob_retries = max(max_blob_retries, 6)
                        else:
                            wait = 2 ** attempt  # 1s, 2s
                        if verbose:
                            print(f"    Retry {attempt + 1}/{max_blob_retries - 1} after {wait}s"
                                  f"{' (rate limited)' if e.status == 429 else ''}...")
                        # Guard: cumulative timeout prevents server-driven DoS via repeated 429s
                        if time.monotonic() - install_start > install_timeout:
                            raise SkillSafeError(
                                "install_timeout",
                                f"Install timed out after {install_timeout:.0f}s due to repeated retries"
                            )
                        time.sleep(wait)
                attempt += 1
            if last_err is not None:
                # Blob missing from R2 — try GitHub raw content as fallback
                if github_raw_base and blob_path:
                    gh_candidates = [
                        f"{github_raw_base}/{blob_path}",
                    ]
                    if skill_name:
                        gh_candidates.append(f"{github_raw_base}/skills/{skill_name}/{blob_path}")
                        gh_candidates.append(f"{github_raw_base}/{skill_name}/{blob_path}")
                    gh_data: Optional[bytes] = None
                    for gh_url in gh_candidates:
                        try:
                            req = urllib.request.Request(gh_url, headers={"User-Agent": "skillsafe-cli"})
                            with urllib.request.urlopen(req, timeout=30) as resp:
                                gh_data = resp.read()
                            if gh_data is not None:
                                break
                        except Exception:
                            continue
                    if gh_data is not None:
                        data = gh_data
                        if verbose:
                            print(f"    Fetched from GitHub fallback")
                        last_err = None
                    else:
                        raise last_err
                else:
                    raise last_err

            # Per-blob size and SHA-256 verification
            if len(data) != blob_size:
                raise SkillSafeError(
                    "integrity_error",
                    f"Blob size mismatch for '{blob_path}': "
                    f"expected {blob_size} bytes, got {len(data)} bytes"
                )
            actual_hash = "sha256:" + hashlib.sha256(data).hexdigest()
            if actual_hash != blob_hash:
                raise SkillSafeError(
                    "integrity_error",
                    f"Blob hash mismatch for '{blob_path}': "
                    f"expected {blob_hash}, got {actual_hash}"
                )

            # Cache the verified blob
            cache_blob(blob_hash, data)

        downloaded_files.append({"path": blob_path, "hash": blob_hash, "data": data})

    # Step 2: Verify tree hash
    file_manifest_for_hash = [{"path": f["path"], "hash": f["hash"]} for f in files]
    computed_tree_hash = compute_tree_hash_v2(file_manifest_for_hash)
    if computed_tree_hash != tree_hash:
        raise SkillSafeError(
            "integrity_error",
            f"Tree hash mismatch: server={tree_hash}, computed={computed_tree_hash}"
        )

    # Step 3: Clean stale files from dest_dir (GAP-4.7)
    # Remove files that exist in dest_dir but are not in the new manifest,
    # so upgrades don't leave orphaned files from previous versions.
    manifest_paths = {f["path"] for f in downloaded_files}
    if dest_dir.exists():
        for existing_file in list(dest_dir.rglob("*")):
            if existing_file.is_file() or existing_file.is_symlink():
                try:
                    rel = existing_file.relative_to(dest_dir)
                    rel_posix = rel.as_posix()
                    if rel_posix not in manifest_paths:
                        existing_file.unlink()
                        if verbose:
                            print(f"    Removed stale file: {rel_posix}")
                except ValueError:
                    pass  # Not relative to dest_dir, skip

    # Step 4: Write files to dest_dir
    dest_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(dest_dir, 0o700)
    except OSError:
        pass  # Best-effort: may fail on some filesystems
    for f in downloaded_files:
        file_path = dest_dir / f["path"]

        # GAP-4.5: Remove existing symlinks at destination to prevent
        # following a symlink that writes outside dest_dir
        if file_path.is_symlink():
            file_path.unlink()

        # Also check parent directories for symlinks escaping dest_dir
        parent = file_path.parent
        parent.mkdir(parents=True, exist_ok=True)
        resolved_parent = Path(os.path.realpath(parent))
        if not str(resolved_parent).startswith(str(dest_dir_resolved) + os.sep) and resolved_parent != dest_dir_resolved:
            raise SkillSafeError(
                "security_error",
                f"Symlink in parent path escapes destination for '{f['path']}'"
            )

        file_path.write_bytes(f["data"])

    # Step 5: Clean up empty directories left after stale file removal
    if dest_dir.exists():
        for dirpath in sorted(dest_dir.rglob("*"), reverse=True):
            if dirpath.is_dir() and not any(dirpath.iterdir()):
                dirpath.rmdir()

    return computed_tree_hash, cached_count, downloaded_count


# ---------------------------------------------------------------------------
# CLI Commands
# ---------------------------------------------------------------------------


def parse_skill_ref(ref: str) -> Tuple[str, str]:
    """
    Parse '@namespace/skill-name' into (namespace, name).

    Accepts with or without the leading '@'.
    Namespace and name must contain only alphanumeric characters (case-insensitive),
    hyphens, underscores, and dots.
    """
    ref = ref.lstrip("@")
    if "/" not in ref:
        raise SkillSafeError("invalid_reference", f"Invalid skill reference '{ref}'. Expected format: @namespace/skill-name")
    parts = ref.split("/", 1)
    namespace, name = parts[0], parts[1]
    if not namespace or not name:
        raise SkillSafeError("invalid_reference", "Invalid skill reference: namespace and name must not be empty")
    # Validate characters to prevent path traversal and other injection
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,38}$', namespace):
        raise SkillSafeError("invalid_reference", f"Invalid namespace '{namespace}'. Use alphanumeric characters, hyphens, and underscores (1-39 chars).")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$', name):
        raise SkillSafeError("invalid_reference", f"Invalid skill name '{name}'. Use alphanumeric characters, dots, hyphens, and underscores (1-101 chars).")
    return namespace, name


def _validate_skill_name(name: str) -> None:
    """Validate a skill name derived from a directory name or --name flag.

    Uses the same regex as parse_skill_ref to ensure consistency.
    Prints an error and exits if the name is invalid.
    """
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$', name):
        print(f"Error: Invalid skill name '{name}'. Use alphanumeric characters, dots, hyphens, and underscores (1-101 chars, must start with alphanumeric).", file=sys.stderr)
        sys.exit(1)


def _validate_saved_key(api_base: str) -> bool:
    """
    Check if a saved API key exists and is still valid.

    Returns True if the saved key is valid (auth not needed), False otherwise.
    """
    cfg = load_config()
    api_key = cfg.get("api_key")
    if not api_key:
        return False

    saved_base = cfg.get("api_base", DEFAULT_API_BASE)
    if saved_base != api_base:
        return False  # different server, need fresh auth
    client = SkillSafeClient(api_base=api_base, api_key=api_key)

    try:
        account = client.get_account()
    except SkillSafeError:
        return False
    except Exception:
        return False

    # Key is valid — update config with latest account info in case it changed
    cfg["account_id"] = account.get("account_id", cfg.get("account_id", ""))
    cfg["username"] = account.get("username", cfg.get("username", ""))
    cfg["namespace"] = f"@{account.get('username', '')}" if account.get("username") else cfg.get("namespace", "")
    save_config(cfg)

    print(green("Already authenticated."))
    print(f"  Account:   {cfg['account_id']}")
    print(f"  Username:  {cfg['username']}")
    print(f"  Namespace: {cfg['namespace']}")
    print(f"  API key:   {dim(_mask_api_key(api_key))}")
    print(f"  Config:    {CONFIG_FILE}")
    print(f"\n  To re-authenticate, delete {CONFIG_FILE} and run auth again.")
    return True


def cmd_lint(args: argparse.Namespace) -> None:
    """Validate a skillsafe.yaml manifest and report issues."""
    target = Path(getattr(args, "path", None) or ".").resolve()
    if not target.is_dir():
        print(f"Error: {target} is not a directory.", file=sys.stderr)
        sys.exit(1)

    yaml_path = target / "skillsafe.yaml"
    if not yaml_path.exists():
        print(f"  {red('✗')} No {bold('skillsafe.yaml')} found in {target}")
        print(f"    Create a skillsafe.yaml with name, version, description, entrypoint, category, and tags.")
        sys.exit(1)

    print(f"\n{bold('SkillSafe Lint')} — validating {yaml_path}\n")

    # Parse YAML without a library using simple key: value line parsing
    manifest: Dict[str, Any] = {}
    try:
        text = yaml_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if ":" in stripped:
                key, _, value = stripped.partition(":")
                key = key.strip().strip('"').strip("'")
                value = value.strip().strip('"').strip("'")
                if value:  # only store scalar values (ignore list items)
                    manifest[key] = value
    except (OSError, UnicodeDecodeError) as e:
        print(f"  {red('✗')} Could not read skillsafe.yaml: {e}", file=sys.stderr)
        sys.exit(1)

    errors: list = []
    warnings: list = []
    passed: list = []

    # --- Required fields ---
    semver_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'
    name_val = manifest.get("name", "")
    version_val = manifest.get("version", "")
    entrypoint_val = manifest.get("entrypoint", "")
    description_val = manifest.get("description", "")

    if not name_val:
        errors.append("'name' is required")
    else:
        passed.append(f"name: {name_val}")

    if not version_val:
        errors.append("'version' is required")
    elif not re.match(semver_re, version_val):
        errors.append(f"'version' must be valid semver (e.g. 1.0.0), got: {version_val!r}")
    else:
        passed.append(f"version: {version_val} (valid semver)")

    if not entrypoint_val:
        errors.append("'entrypoint' is required (e.g. skill.md)")
    else:
        entry_path = target / entrypoint_val
        if not entry_path.exists():
            errors.append(f"'entrypoint' file not found: {entrypoint_val} (expected at {entry_path})")
        else:
            passed.append(f"entrypoint: {entrypoint_val} (exists)")

    if not description_val:
        warnings.append("'description' is missing — add one to improve discoverability")
    elif len(description_val) < 10:
        warnings.append(f"'description' is very short ({len(description_val)} chars) — a longer description helps users find your skill")
    else:
        passed.append(f"description: {description_val[:60]}{'...' if len(description_val) > 60 else ''}")

    # --- Category ---
    valid_categories = {
        "code-quality", "code-review", "data-analysis", "database", "deployment",
        "docs", "frontend", "infra", "performance", "security", "testing", "utility", "other",
    }
    category_val = manifest.get("category", "")
    if category_val and category_val not in valid_categories:
        warnings.append(f"'category' {category_val!r} is not in the standard list. Valid: {', '.join(sorted(valid_categories))}")
    elif category_val:
        passed.append(f"category: {category_val}")

    # --- Tags ---
    tags_val = manifest.get("tags", "")
    if tags_val and tags_val not in ("[", "]", "[]", ""):
        # Inline tags like: tags: code-review,typescript
        raw_tags = [t.strip().strip('"').strip("'").lstrip("- ") for t in tags_val.replace(",", " ").split()]
        bad_tags = [t for t in raw_tags if t and (t != t.lower() or " " in t)]
        if bad_tags:
            warnings.append(f"Tags should be lowercase with no spaces. Problematic: {bad_tags}")
        elif raw_tags:
            passed.append(f"tags: {', '.join(raw_tags[:5])}")

    # --- evals (if present) ---
    pass_rate_val = manifest.get("pass_rate", "")
    if pass_rate_val:
        try:
            pr = float(pass_rate_val)
            if pr < 0 or pr > 100:
                errors.append(f"'evals.pass_rate' must be between 0 and 100, got: {pr}")
            elif pr < 80:
                warnings.append(f"'evals.pass_rate' is {pr}% — skills need ≥80% to reach 'Tested' tier")
            else:
                passed.append(f"evals.pass_rate: {pr}%")
        except ValueError:
            errors.append(f"'evals.pass_rate' must be a number, got: {pass_rate_val!r}")

    # --- Print results ---
    for p in passed:
        print(f"  {green('✓')} {p}")

    for w in warnings:
        print(f"  {yellow('⚠')} {w}")

    for e in errors:
        print(f"  {red('✗')} {e}")

    print()
    if errors:
        print(f"  {red(bold(f'{len(errors)} error(s)'))}, {len(warnings)} warning(s) — fix errors before saving")
        sys.exit(1)
    elif warnings:
        print(f"  {green('Manifest is valid')} ({len(warnings)} warning(s))")
    else:
        print(f"  {green(bold('Manifest is valid ✓'))}")


def cmd_whoami(args: argparse.Namespace) -> None:
    """Show current authentication status and account info."""
    cfg = load_config()
    api_key = cfg.get("api_key")

    if not api_key:
        print(red("Not authenticated."))
        print(f"\n  Run {bold('skillsafe auth')} to get started.")
        sys.exit(1)

    api_base = getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE)

    # Show local config info
    print(f"\n  {bold('Local config')}")
    print(f"  Username:    {cfg.get('username', dim('unknown'))}")
    print(f"  Namespace:   {cfg.get('namespace', dim('unknown'))}")
    print(f"  API key:     {dim(_mask_api_key(api_key))}")
    print(f"  API base:    {api_base}")
    print(f"  Config file: {CONFIG_FILE}")

    # Verify against server
    client = SkillSafeClient(api_base=api_base, api_key=api_key)

    try:
        account = client.get_account()
    except SkillSafeError as e:
        if e.status == 401:
            print(f"\n  {red('Session expired.')} Run {bold('skillsafe auth')} to sign in again.")
            sys.exit(1)
        print(f"\n  {yellow('Could not verify account:')} {e.message}")
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"\n  {yellow('Could not connect to API.')} {e}")
        print(f"  Local config appears valid. Use {bold('--api-base')} to change the server.")
        sys.exit(1)

    # Backfill missing config fields from account data
    updated = False
    if not cfg.get("namespace") and account.get("username"):
        cfg["namespace"] = f"@{account['username']}"
        updated = True
    if not cfg.get("username") and account.get("username"):
        cfg["username"] = account["username"]
        updated = True
    if updated:
        save_config(cfg)

    # Show verified account details
    print(f"\n  {bold('Account')} {green('(verified)')}")
    print(f"  Email:       {account.get('email') or dim('not set')}")

    email_verified = account.get("email_verified", False)
    if email_verified:
        print(f"  Verified:    {green('yes')}")
    else:
        print(f"  Verified:    {yellow('no')}")

    print(f"  Tier:        {account.get('tier', 'free')}")

    # Storage usage
    used = account.get("storage_used_bytes", 0)
    used_mb = used / (1024 * 1024)
    print(f"  Storage:     {used_mb:.1f} MB used")

    print(f"  Skills:      {account.get('shared_skill_count', 0)} shared")
    print(f"  Member since: {(account.get('created_at') or '-')[:10]}")
    print()


def cmd_update(args: argparse.Namespace) -> None:
    """Unified update: self-update the CLI or upgrade installed skills."""
    skill_ref: Optional[str] = getattr(args, "skill", None)
    fetch_all: bool = getattr(args, "all", False)

    # self-update: no skill arg, or explicit "skillsafe"
    if args.command == "self-update" or (not fetch_all and (not skill_ref or skill_ref.strip("@") == "skillsafe")):
        cmd_self_update(args)
        return

    # Otherwise: upgrade one skill or all installed skills
    cmd_upgrade(args)


def cmd_upgrade(args: argparse.Namespace) -> None:
    """Check all installed skills for newer registry versions and reinstall outdated ones."""
    cfg = load_config()
    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg.get("api_key", ""))

    skill_ref: Optional[str] = getattr(args, "skill", None)
    tool_filter: Optional[str] = getattr(args, "tool", None)
    dry_run: bool = getattr(args, "dry_run", False)

    # Collect all candidate skill directories to check
    candidates: List[Tuple[str, str, str, Path]] = []  # (namespace, name, installed_version, skill_dir)

    def _collect_from_dir(base_dir: Path) -> None:
        if not base_dir.is_dir():
            return
        index = _read_install_index()
        for skill_dir in sorted(base_dir.iterdir()):
            if not skill_dir.is_dir():
                continue
            meta = index.get(str(skill_dir))
            if not meta:
                continue
            ns = (meta.get("namespace") or "").lstrip("@")
            nm = meta.get("name", "")
            ver = meta.get("version", "")
            if ns and nm and ver:
                candidates.append((ns, nm, ver, skill_dir))

    if tool_filter:
        if tool_filter not in TOOL_SKILLS_DIRS:
            print(f"Error: Unknown tool '{tool_filter}'. Valid tools: {', '.join(sorted(TOOL_SKILLS_DIRS))}")
            sys.exit(1)
        _collect_from_dir(TOOL_SKILLS_DIRS[tool_filter])
    else:
        for tool_dir in TOOL_SKILLS_DIRS.values():
            _collect_from_dir(tool_dir)

    if not candidates:
        print("No installed skills with registry metadata found.")
        print("Tip: only skills installed via 'skillsafe install' can be upgraded.")
        return

    # Filter to a specific skill if requested
    if skill_ref:
        ns_filter, nm_filter = parse_skill_ref(skill_ref)
        candidates = [(ns, nm, ver, d) for ns, nm, ver, d in candidates
                      if ns == ns_filter and nm == nm_filter]
        if not candidates:
            print(f"Skill {bold(skill_ref)} is not installed or has no registry metadata.")
            sys.exit(1)

    print(f"Checking {len(candidates)} installed skill(s) for updates...\n")
    print(f"  {'SKILL':<35} {'INSTALLED':<12} {'LATEST':<12} STATUS")
    print(f"  {'─' * 35} {'─' * 12} {'─' * 12} {'─' * 10}")

    to_upgrade: List[Tuple[str, str, str, Path]] = []  # (ns, nm, latest_ver, skill_dir)

    for ns, nm, installed_ver, skill_dir in candidates:
        ref = f"@{ns}/{nm}"
        try:
            # Use auth=True so private skills owned by the user are accessible
            meta = client.get_metadata(ns, nm, auth=True)
            latest_ver = meta.get("latest_version", "")
            if not latest_ver:
                print(f"  {ref:<35} {installed_ver:<12} {'?':<12} unknown")
                continue
            if _parse_semver(latest_ver) > _parse_semver(installed_ver):
                print(f"  {ref:<35} {installed_ver:<12} {latest_ver:<12} {yellow('outdated')}")
                to_upgrade.append((ns, nm, latest_ver, skill_dir))
            else:
                print(f"  {ref:<35} {installed_ver:<12} {latest_ver:<12} {green('up to date')}")
        except SkillSafeError:
            print(f"  {ref:<35} {installed_ver:<12} {'?':<12} not found in registry")
        except (urllib.error.URLError, OSError):
            print(f"  {ref:<35} {installed_ver:<12} {'?':<12} network error")

    if not to_upgrade:
        print(f"\n{green('All skills are up to date.')}")
        return

    print(f"\n{len(to_upgrade)} skill(s) can be upgraded.")

    if dry_run:
        print("(dry run — pass without --dry-run to apply upgrades)")
        return

    print()
    upgraded = 0
    for ns, nm, latest_ver, skill_dir in to_upgrade:
        ref = f"@{ns}/{nm}"
        print(f"Upgrading {bold(ref)} → v{latest_ver}...")
        # Determine install path (parent of skill_dir)
        install_parent = skill_dir.parent

        # Build a minimal args namespace to reuse cmd_install logic
        import types
        fake_args = types.SimpleNamespace(
            skill=f"@{ns}/{nm}",
            version=latest_ver,
            tool=None,
            location="global",
            skills_dir=str(install_parent),
            api_base=getattr(args, "api_base", None),
        )
        try:
            cmd_install(fake_args)
            upgraded += 1
        except SystemExit:
            print(f"  {red('Failed')} to upgrade {ref}.")

    print(f"\n{green(f'Upgraded {upgraded}/{len(to_upgrade)} skill(s).')}")


def cmd_self_update(args: argparse.Namespace) -> None:
    """Download the latest skillsafe files from skillsafe.ai and replace them in place."""
    skill_dir = Path(__file__).resolve().parent.parent  # scripts/ -> skill root
    script_path = Path(__file__).resolve()
    base_url = "https://skillsafe.ai"

    current_hash = hashlib.sha256(script_path.read_bytes()).hexdigest()[-5:]
    print(f"  Current version: {bold(f'v{VERSION}')} ({current_hash})")

    # --- Update skillsafe.py ---
    py_url = f"{base_url}/scripts/skillsafe.py"
    print(f"  Checking {py_url} ...")
    try:
        req = urllib.request.Request(py_url, headers={"User-Agent": f"skillsafe-cli/{VERSION}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            new_src = resp.read()
    except Exception as e:
        print(f"\n{red('Error:')} Could not download update: {e}", file=sys.stderr)
        sys.exit(1)

    # Compare by content hash (last 8 chars of SHA-256) — no manual version bump needed
    new_hash = hashlib.sha256(new_src).hexdigest()[-5:]

    m = re.search(rb'^VERSION\s*=\s*["\']([^"\']+)["\']', new_src, re.MULTILINE)
    new_version = m.group(1).decode() if m else "unknown"

    if current_hash == new_hash:
        print(f"\n{green('Already up to date.')} (v{VERSION}, {current_hash})")
        script_updated = False
    else:
        tmp = script_path.with_suffix(".py.tmp")
        try:
            tmp.write_bytes(new_src)
            tmp.replace(script_path)
        except OSError as e:
            print(f"\n{red('Error:')} Could not write update: {e}", file=sys.stderr)
            sys.exit(1)
        print(f"  {green(f'skillsafe.py: v{VERSION} ({current_hash}) → v{new_version} ({new_hash})')}")
        script_updated = True

    # --- Update skill definition files ---
    skill_files = [
        ("skill.md", "SKILL.md"),
        ("submit-skill-demo.md", "submit-skill-demo.md"),
        ("submit-demo-comment.md", "submit-demo-comment.md"),
    ]
    files_updated = 0
    for remote_name, local_name in skill_files:
        url = f"{base_url}/{remote_name}"
        dest = skill_dir / local_name
        if not dest.parent.exists():
            continue
        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"skillsafe-cli/{VERSION}"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                new_content = resp.read()
        except Exception as e:
            print(f"  {red('Warning:')} Could not fetch {remote_name}: {e}")
            continue
        existing = dest.read_bytes() if dest.exists() else b""
        if new_content != existing:
            dest.write_bytes(new_content)
            print(f"  {green('Updated:')} {local_name}")
            files_updated += 1
        else:
            print(f"  {local_name}: already up to date")

    if not script_updated and files_updated == 0:
        return
    print(f"\n{green('Self-update complete.')}")


def cmd_auth(args: argparse.Namespace) -> None:
    """Authenticate via browser login."""
    api_base: str = getattr(args, "api_base", DEFAULT_API_BASE)

    # Check if a saved key is already valid
    if _validate_saved_key(api_base):
        return

    # Saved key missing or invalid — start browser-based login flow
    _auth_browser(api_base)


def _detect_tool() -> str:
    """Detect which AI coding tool is invoking the CLI based on script path.

    Works with any tool that follows the ``~/.<tool>/skills/`` convention,
    not just the ones listed in TOOL_SKILLS_DIRS.  For example a script
    installed at ``~/.copilot/skills/skillsafe/scripts/skillsafe.py``
    will return ``"copilot"``.

    Codex installs skills under ``~/.agents/skills/`` (no tool prefix in the
    directory name), so the detected folder name ``"agents"`` is mapped to
    ``"codex"`` via the alias table below.
    """
    # Map raw folder names to canonical tool keys when they differ.
    _dir_aliases = {"agents": "codex"}
    try:
        script_path = Path(__file__).resolve()
        home = Path.home().resolve()
        rel = script_path.relative_to(home)
        # Expected layout: .<tool>/skills/<skill>/...
        parts = rel.parts  # e.g. ('.cursor', 'skills', 'skillsafe', ...)
        if (
            len(parts) >= 3
            and parts[0].startswith(".")
            and parts[1] == "skills"
        ):
            raw = parts[0].lstrip(".")  # e.g. "cursor" or "agents"
            return _dir_aliases.get(raw, raw)
    except (ValueError, IndexError):
        pass
    return "cli"


def _auth_browser(api_base: str) -> None:
    """Authenticate via browser-based device authorization flow."""
    client = SkillSafeClient(api_base=api_base)

    # Detect the invoking tool for a richer API key label (e.g. "cursor")
    label = _detect_tool()

    # Step 1: Create a CLI auth session (15-minute TTL)
    print("Starting browser login...\n")
    try:
        payload = json.dumps({"label": label}).encode()
        result = client._request(
            "POST", "/v1/auth/cli", auth=False,
            body=payload, content_type="application/json",
        )
        data = result.get("data", result)
        session_id: str = data["session_id"]
        login_url: str = data["login_url"]
        expires_in: int = int(data.get("expires_in", 900))
        # Validate session_id format to prevent URL path injection
        if not re.match(r'^[a-zA-Z0-9_-]{1,128}$', session_id):
            print("Error: Server returned invalid session ID format.", file=sys.stderr)
            sys.exit(1)
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (KeyError, TypeError):
        print("Error: Unexpected response from server.", file=sys.stderr)
        sys.exit(1)

    # Step 2: Open browser — validate URL scheme and host first
    parsed_url = urllib.parse.urlparse(login_url)
    if parsed_url.scheme not in ("https", "http"):
        print(f"Error: Server returned unsafe login URL scheme: {parsed_url.scheme!r}", file=sys.stderr)
        sys.exit(1)
    # Only allow login URLs on the same host as the API or known SkillSafe domains
    api_host = urllib.parse.urlparse(api_base).hostname or ""
    allowed_hosts = {api_host, "skillsafe.ai", "www.skillsafe.ai", "localhost", "127.0.0.1"}
    if parsed_url.hostname not in allowed_hosts:
        print(f"Error: Server returned login URL for unexpected host: {parsed_url.hostname!r}", file=sys.stderr)
        sys.exit(1)

    expires_min = expires_in // 60
    print(f"  Authorization URL (valid for {expires_min} min):\n")
    print(f"    {bold(login_url)}\n")
    print(f"  Open this URL in any browser to sign in.")
    print(f"  Running as an AI agent without browser access? Share the URL above")
    print(f"  with a human — they can open it on any machine to authorize you.\n")

    try:
        webbrowser.open(login_url)
    except Exception:
        pass  # URL is already printed as primary instruction

    # Step 3: Poll for approval
    print("  Waiting for authorization", end="", flush=True)

    poll_interval = 2  # seconds
    max_wait = expires_in  # match server TTL
    elapsed = 0

    while elapsed < max_wait:
        try:
            time.sleep(poll_interval)
        except KeyboardInterrupt:
            print()
            print("\n  Authentication cancelled.", file=sys.stderr)
            sys.exit(1)
        elapsed += poll_interval

        try:
            resp = client._request("GET", f"/v1/auth/cli/{session_id}", auth=False)
            data = resp.get("data", resp)
            status = data.get("status")

            if status == "approved":
                print()  # newline after dots
                _save_auth_result(data, api_base)
                return

            # Still pending — print a dot
            print(".", end="", flush=True)

        except KeyboardInterrupt:
            print()
            print("\n  Authentication cancelled.", file=sys.stderr)
            sys.exit(1)
        except SkillSafeError as e:
            print()
            if e.status == 410:
                print(f"\n  {red('Session expired.')} Please try again.", file=sys.stderr)
            else:
                print(f"\n  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
        except Exception:
            print(".", end="", flush=True)

    # Timeout
    print()
    print(f"\n  {red('Timed out')} waiting for browser authorization.", file=sys.stderr)
    print(f"  You can still sign in at: {login_url}", file=sys.stderr)
    sys.exit(1)


def _save_auth_result(data: Dict[str, Any], api_base: str) -> None:
    """Save the credentials from a successful browser auth to config."""
    api_key = data.get("api_key")
    if not api_key or not isinstance(api_key, str) or not api_key.strip():
        print("Error: Server returned invalid or empty API key. Authentication failed.", file=sys.stderr)
        sys.exit(1)
    cfg = {
        "account_id": data.get("account_id", ""),
        "username": data.get("username", ""),
        "namespace": data.get("namespace", ""),
        "api_key": api_key,
        "api_base": api_base,
    }
    save_config(cfg)

    SKILLS_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    print(green("\n  Authenticated successfully."))
    print(f"  Account:   {cfg['account_id']}")
    print(f"  Username:  {cfg['username']}")
    print(f"  Namespace: {cfg['namespace']}")
    print(f"  API key:   {dim(_mask_api_key(cfg['api_key']))}")
    print(f"  Config:    {CONFIG_FILE}")


def cmd_scan(args: argparse.Namespace) -> Optional[Dict[str, Any]]:
    """Scan a skill directory for security issues."""
    path = Path(args.path).resolve()
    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {bold(str(path))}...\n")
    scanner = Scanner()

    try:
        report = scanner.scan(path)
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Apply --ignore filter
    ignore_rules: set = set()
    if getattr(args, "ignore", None):
        ignore_rules = {r.strip() for r in args.ignore.split(",")}
    if ignore_rules:
        report["findings_summary"] = [
            f for f in report["findings_summary"] if f["rule_id"] not in ignore_rules
        ]
        remaining = report["findings_summary"]
        threat_count = sum(1 for f in remaining if f.get("classification", "threat") == "threat")
        advisory_count = sum(1 for f in remaining if f.get("classification") == "advisory")
        report["findings_count"] = threat_count
        report["advisory_count"] = advisory_count
        report["clean"] = threat_count == 0
        score, grade = scanner._calculate_score(remaining)
        report["score"] = score
        report["grade"] = grade

    # Check publisher verification via API
    publisher_verified = False
    ns, nm = None, None
    # Try skillsafe.yaml first
    yaml_path = path / "skillsafe.yaml"
    if yaml_path.exists():
        try:
            raw = yaml_path.read_text()
            for line in raw.splitlines():
                ym = re.match(r'^name:\s*"?@?([^/"]+)/([^/"]+)"?', line)
                if ym:
                    ns, nm = ym.group(1), ym.group(2)
                    break
        except OSError:
            pass
    # Fallback: check install index for installed skills
    if not (ns and nm):
        install_meta = _get_install_meta(path)
        if install_meta:
            ns = install_meta.get("namespace", "").lstrip("@") or None
            nm = install_meta.get("name") or None
    if ns and nm:
        cfg = load_config()
        api_key = cfg.get("api_key")
        client = SkillSafeClient(api_key=api_key)
        try:
            meta = client.get_metadata(ns, nm, auth=bool(api_key))
            publisher_verified = bool(meta and meta.get("publisher_validated"))
        except SkillSafeError:
            pass

    skill_ref = f"@{ns}/{nm}" if ns and nm else ""
    _print_scan_results(report, publisher_verified=publisher_verified, skill_ref=skill_ref)

    # Optionally write report to file
    if getattr(args, "output", None):
        out_path = Path(args.output)
        with open(out_path, "w") as f:
            json.dump(report, f, indent=2)
            f.write("\n")
        print(f"\nReport written to {out_path}")

    # --check: exit 1 if any HIGH or CRITICAL *threat* findings remain
    if getattr(args, "check", False):
        _high = {"critical", "high"}
        if any(
            f.get("severity") in _high and f.get("classification", "threat") == "threat"
            for f in report.get("findings_summary", [])
        ):
            sys.exit(1)

    return report


def _print_bom(bom: Dict[str, Any]) -> None:
    """Pretty-print BOM summary to terminal."""
    summary = bom.get("summary", {})
    risk = summary.get("risk_surface", "none")
    risk_colors = {"none": green, "low": green, "medium": yellow, "high": red}
    risk_fn = risk_colors.get(risk, str)

    print(f"\n{bold('Bill of Materials (BOM)')}")
    print(f"  Files scanned:     {summary.get('total_files_scanned', 0)}")
    print(f"  With capabilities: {summary.get('files_with_capabilities', 0)}")
    print(f"  Risk surface:      {risk_fn(risk.upper())}\n")

    caps = summary.get("capability_count", {})
    if caps:
        print(f"  {bold('Capabilities:')}")
        for cap, count in caps.items():
            print(f"    {cap:<16} {count}")
        print()

    # Network
    net = bom.get("network", {})
    domains = net.get("domains", [])
    if domains:
        print(f"  {bold('Domains:')} {', '.join(domains)}")

    # Env vars
    env = bom.get("environment", {})
    env_names = sorted({e["name"] for e in env.get("env_vars", [])})
    if env_names:
        print(f"  {bold('Env vars:')} {', '.join(env_names)}")

    # Dependencies
    deps = bom.get("dependencies", {})
    for dep_type, label in [("python_imports", "Python"), ("js_requires", "JS"), ("shell_tools", "Shell")]:
        items = deps.get(dep_type, [])
        if items:
            print(f"  {bold(f'{label} deps:')} {', '.join(items)}")

    print()


def cmd_bom(args: argparse.Namespace) -> None:
    """Generate and display BOM for a skill directory."""
    path = Path(args.path).resolve()
    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    print(f"Generating BOM for {bold(str(path))}...\n")
    scanner = Scanner()

    try:
        report = scanner.scan(path)
    except ScanError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    bom = report.get("bom", {})
    if not bom:
        print("No BOM data generated.")
        return

    _print_bom(bom)

    # Optionally write BOM JSON to file
    out_path = getattr(args, "output", None)
    if out_path:
        out_path = Path(out_path)
        with open(out_path, "w") as f:
            json.dump(bom, f, indent=2)
            f.write("\n")
        print(f"BOM written to {out_path}")


def cmd_save(args: argparse.Namespace) -> None:
    """Save a skill to the registry (private by default)."""
    cfg = require_config()
    path = Path(args.path).resolve()
    version: Optional[str] = getattr(args, "version", None)
    description: Optional[str] = getattr(args, "description", None)
    category: Optional[str] = getattr(args, "category", None)
    tags_raw: Optional[str] = getattr(args, "tags", None)

    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    # Validate semver format if version is explicitly provided
    if version:
        semver_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'
        if not re.match(semver_re, version):
            print(f"Error: Invalid version '{version}'. Expected semantic version (e.g. 1.0.0, 2.1.0-beta.1).", file=sys.stderr)
            sys.exit(1)

    name = path.name
    namespace = cfg.get("username")
    if not namespace:
        print("Error: username not found in config. Run 'skillsafe auth' or 'skillsafe whoami' first.", file=sys.stderr)
        sys.exit(1)

    # Read defaults from skillsafe.yaml if present
    yaml_meta_path = path / "skillsafe.yaml"
    if yaml_meta_path.exists():
        try:
            raw = yaml_meta_path.read_text()
            # Minimal YAML parser for simple key: "value" lines
            yaml_desc = None
            yaml_category = None
            yaml_tags = None
            for line in raw.splitlines():
                m = re.match(r'^name:\s*"?@?([^/"]+)/([^/"]+)"?', line)
                if m:
                    namespace, name = m.group(1), m.group(2)
                    continue
                m2 = re.match(r'^name:\s*"?([^"@\s]+)"?', line)
                if m2 and "/" not in m2.group(1):
                    name = m2.group(1)
                    continue
                md = re.match(r'^description:\s*"?(.+?)"?\s*$', line)
                if md:
                    yaml_desc = md.group(1)
                    continue
                mc = re.match(r'^category:\s*"?([^"]+?)"?\s*$', line)
                if mc:
                    yaml_category = mc.group(1).strip()
                    continue
                mt = re.match(r'^tags:\s*\[(.+)\]\s*$', line)
                if mt:
                    yaml_tags = mt.group(1)
                    continue
            # Use YAML values as defaults when CLI flags not provided
            if not description and yaml_desc:
                description = yaml_desc
            if not category and yaml_category:
                category = yaml_category
            if not tags_raw and yaml_tags:
                tags_raw = yaml_tags
        except OSError:
            pass
    else:
        print(f"  {yellow('Warning:')} No skillsafe.yaml found in {path}. Run {bold('skillsafe lint')} to validate your skill.")

    _validate_skill_name(name)

    if name in RESERVED_SKILL_NAMES:
        print(f"  '{name}' is reserved and has no need to save.")
        return

    api_base = getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE)
    client = SkillSafeClient(api_base=api_base, api_key=cfg["api_key"])

    # Auto-resolve version if not provided
    if not version:
        print(f"Resolving next version of {bold(f'@{namespace}/{name}')}...")
        version = client.resolve_next_version(namespace, name)

    print(f"Saving {bold(f'@{namespace}/{name}')} v{version}...\n")

    # Step 1: Build file manifest
    print("  Building file manifest...")
    file_manifest = build_file_manifest(path)
    total_size = sum(f["size"] for f in file_manifest)
    total_size_kb = total_size / 1024
    if total_size > MAX_ARCHIVE_SIZE:
        print(f"Error: Total file size is {total_size_kb:.0f} KB, exceeds 10 MB limit.", file=sys.stderr)
        sys.exit(1)
    print(f"  Files: {len(file_manifest)}, total size: {total_size_kb:.1f} KB")

    # Step 2: Compute v2 tree hash
    tree_hash = compute_tree_hash_v2(file_manifest)
    print(f"  Tree hash:    {dim(tree_hash[:30])}...")

    # Step 2b: Check if latest version already has the same tree hash (no changes)
    try:
        meta = client.get_metadata(namespace, name, auth=True)
        latest_ver = meta.get("latest_version")
        if latest_ver:
            versions_resp = client.get_versions(namespace, name, limit=1)
            versions_data = versions_resp.get("data", [])
            versions_list = versions_data if isinstance(versions_data, list) else []
            if versions_list and versions_list[0].get("tree_hash") == tree_hash:
                print(green(f"\n  No changes detected — latest version v{latest_ver} already has the same content."))
                return
    except SkillSafeError:
        pass  # Skill doesn't exist yet, proceed

    # Step 3: Scan (optional but recommended)
    print("  Scanning for security issues...")
    scanner = Scanner()
    report = scanner.scan(path, tree_hash=tree_hash)
    _print_scan_results(report, indent=2)

    # Step 4: Negotiate delta upload
    print("\n  Negotiating upload...")
    try:
        negotiate_result = client.negotiate(namespace, name, version, file_manifest)
        needed_files = negotiate_result.get("needed_files", [])
        existing_blobs = negotiate_result.get("existing_blobs", [])
    except SkillSafeError as e:
        print(f"\n  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    needed_bytes = sum(f["size"] for f in file_manifest if f["path"] in needed_files)
    print(f"  Need to upload: {len(needed_files)} file(s) ({needed_bytes / 1024:.1f} KB)")
    if existing_blobs:
        print(f"  Already on server: {len(existing_blobs)} blob(s) (skipped)")

    # Step 5: Save to registry via v2 (with retry + version conflict re-resolution)
    print("  Uploading to registry...")
    changelog: Optional[str] = getattr(args, "changelog", None)

    metadata: Dict[str, Any] = {"version": version}
    if description:
        metadata["description"] = description
    if category:
        metadata["category"] = category
    if tags_raw:
        metadata["tags"] = [t.strip() for t in tags_raw.split(",")]
    if changelog:
        metadata["changelog"] = changelog

    max_retries = 3
    result = None
    version_re_resolved = False
    for attempt in range(max_retries):
        try:
            result = client.save_v2(
                namespace, name, metadata, file_manifest, needed_files, path,
                scan_report_json=json.dumps(report),
            )
            break  # Success
        except SkillSafeError as e:
            # Handle version collision: re-resolve version and retry once
            if (e.status == 409 or e.status == 422) and not version_re_resolved:
                version_re_resolved = True
                old_version = version
                version = client.resolve_next_version(namespace, name)
                if version == old_version:
                    print(f"\n  Error: Version {old_version} already exists for this skill.", file=sys.stderr)
                    sys.exit(1)
                print(f"  {yellow('Note:')} Version {old_version} already exists. Auto-saving as {bold(version)} instead.")
                metadata["version"] = version
                # Re-negotiate with new version
                try:
                    negotiate_result = client.negotiate(namespace, name, version, file_manifest)
                    needed_files = negotiate_result.get("needed_files", [])
                except SkillSafeError as e_neg:
                    print(f"\n  Error: {e_neg.message}", file=sys.stderr)
                    sys.exit(1)
                continue
            # 429 Rate Limit: respect Retry-After
            if e.status == 429 and e.retry_after and attempt < max_retries - 1:
                print(yellow(f"\n  Rate limited, retrying in {e.retry_after}s..."))
                time.sleep(e.retry_after)
                continue
            # Non-retryable client errors (4xx except 429)
            if 400 <= e.status < 500:
                print(f"\n  Error: {e.message}", file=sys.stderr)
                sys.exit(1)
            # Retryable server errors (5xx) or unknown
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # 1s, 2s
                print(yellow(f"\n  Upload failed ({e.code}), retrying in {delay}s... ({attempt + 1}/{max_retries})"))
                time.sleep(delay)
            else:
                print(f"\n  Error: {e.message}", file=sys.stderr)
                sys.exit(1)
        except (urllib.error.URLError, OSError) as e:
            if attempt < max_retries - 1:
                delay = 2 ** attempt  # 1s, 2s
                print(yellow(f"\n  Upload failed ({type(e).__name__}), retrying in {delay}s... ({attempt + 1}/{max_retries})"))
                time.sleep(delay)
            else:
                print(f"\n  Error: Could not connect to the API. {e}", file=sys.stderr)
                sys.exit(1)

    if result is None:
        print("Error: Upload failed after all retries.", file=sys.stderr)
        sys.exit(1)

    # Post-upload tree hash verification
    server_tree_hash = result.get("tree_hash")
    local_tree_hash = compute_tree_hash_v2(file_manifest)

    if server_tree_hash != local_tree_hash:
        print(yellow(f"\n  Warning: Tree hash mismatch!"))
        print(f"    Local:  {local_tree_hash}")
        print(f"    Server: {server_tree_hash}")
        print(f"  This may indicate server processing issues or tampering.")
        print(f"\n  Saved @{namespace}/{name}@{version}")
        print(f"  Skill ID:   {result.get('skill_id')}")
        print(f"  Version ID: {result.get('version_id')}")
    else:
        print(green(f"\n  Saved @{namespace}/{name}@{version}"))
        print(f"  Skill ID:   {result.get('skill_id')}")
        print(f"  Version ID: {result.get('version_id')}")
        print(f"  Tree hash:  {server_tree_hash} (verified)")
    if result.get("new_bytes") is not None:
        print(f"  New bytes:  {result.get('new_bytes', 0) / 1024:.1f} KB")

    print(f"\n  To share this skill, run:")
    print(f"    skillsafe share @{namespace}/{name} --version {version}")


def cmd_share(args: argparse.Namespace) -> None:
    """Create a share link for a saved skill."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version
    public: bool = getattr(args, "public", False)
    expires: Optional[str] = getattr(args, "expires", None)

    visibility = "public" if public else "private"

    print(f"Sharing {bold(f'@{namespace}/{name}')} v{version} ({visibility})...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        result = client.share(namespace, name, version, visibility=visibility, expires_in=expires)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    api_base = cfg.get("api_base", DEFAULT_API_BASE)
    web_base = api_base.replace("://api.", "://", 1) if "://api." in api_base else api_base
    share_id = result.get("share_id", "")

    print(green(f"  Share link created."))
    print(f"  Share ID:    {share_id}")
    print(f"  Visibility:  {result.get('visibility')}")
    if result.get("expires_at"):
        print(f"  Expires:     {result.get('expires_at')}")
    if visibility == "public":
        print(f"  Skill page:  {bold(f'{web_base}/skill/{namespace}/{name}')}")
        print(f"\n  This skill is now discoverable via search.")
    else:
        print(f"  Install via: {bold(f'skillsafe install {share_id}')}")
        print(f"\n  Share the install command with others to give them access.")


def cmd_install(args: argparse.Namespace) -> None:
    """Install a skill from the registry."""
    cfg = load_config()  # May return empty dict if not authenticated

    # Detect share link references (shr_ prefix or URL containing /share/shr_)
    skill_ref = args.skill
    share_id: Optional[str] = None
    if skill_ref.startswith("shr_"):
        share_id = skill_ref
    elif "/share/shr_" in skill_ref:
        share_id = skill_ref.split("/share/")[-1].split("?")[0]

    api_key = cfg.get("api_key")
    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=api_key)

    # ---------- Download ----------

    dl_format: str = ""       # "files" (v2) or "archive" (v1)
    dl_data: Any = None       # manifest dict (v2) or archive bytes (v1)
    namespace: str = ""
    name: str = ""
    version: str = ""
    server_tree_hash: str = ""
    meta: Optional[Dict[str, Any]] = None

    if share_id:
        # Share link download path
        print(f"Installing via share link {bold(share_id)}...\n")

        print("  Downloading via share link...")
        try:
            dl_format, dl_data = client.download_via_share(share_id)
        except SkillSafeError as e:
            print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)

        # Regex for validating namespace/name/version from untrusted server responses
        _safe_ident_re = r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,100}$'
        _safe_version_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'

        if dl_format == "files":
            # v2 manifest — extract metadata
            namespace = dl_data.get("namespace", "shared").lstrip("@")
            name = dl_data.get("name", share_id)
            version = dl_data.get("version", "unknown")
            print(f"  Received v2 manifest: {len(dl_data.get('files', []))} file(s)")
        else:
            # v1 archive
            archive_bytes, server_tree_hash, version = dl_data
            print(f"  Downloaded {len(archive_bytes) / 1024:.1f} KB")
            dl_data = archive_bytes  # normalize

            if not version:
                version = "unknown"

            # Try to extract namespace/name from archive's SKILL.md
            namespace = "shared"
            name = share_id
            try:
                with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member.name == "SKILL.md" or member.name.endswith("/SKILL.md"):
                            f = tar.extractfile(member)
                            if f:
                                text = f.read().decode("utf-8", errors="replace")
                                for line in text.splitlines():
                                    if line.startswith("name:"):
                                        name = line[len("name:"):].strip()
                                        break
                            break
            except Exception:
                pass  # Use defaults if we can't parse SKILL.md

        # Sanitize namespace/name/version from untrusted server response
        # to prevent path traversal in install directories
        if not re.match(_safe_ident_re, namespace):
            print(f"Error: Invalid namespace '{namespace}' in share link response.", file=sys.stderr)
            sys.exit(1)
        if not re.match(_safe_ident_re, name):
            print(f"Error: Invalid name '{name}' in share link response.", file=sys.stderr)
            sys.exit(1)
        if version != "unknown" and not re.match(_safe_version_re, version):
            print(f"Error: Invalid version '{version}' in share link response.", file=sys.stderr)
            sys.exit(1)

        # Try to fetch metadata for publisher trust signal
        if namespace != "shared":
            try:
                meta = client.get_metadata(namespace, name, auth=bool(api_key))
            except SkillSafeError:
                pass

    else:
        namespace, name = parse_skill_ref(skill_ref)
        version = getattr(args, "version", None) or ""

        # Fetch metadata (needed for version resolution + publisher trust signal)
        try:
            meta = client.get_metadata(namespace, name, auth=bool(api_key))
        except SkillSafeError:
            pass  # Non-fatal — we can still install without metadata

        # Step 1: Resolve version
        if not version:
            if meta:
                version = meta.get("latest_version", "")
            if not version:
                print("Error: No published versions found.", file=sys.stderr)
                sys.exit(1)

        # Validate version format to prevent path traversal via malicious server response
        semver_re = r'^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$'
        if not re.match(semver_re, version):
            print(f"Error: Invalid version '{version}'. Expected semantic version (e.g. 1.0.0).", file=sys.stderr)
            sys.exit(1)

        print(f"Installing {bold(f'@{namespace}/{name}')} v{version}...\n")

        # Step 2: Download
        print("  Downloading...")
        try:
            dl_format, dl_data = client.download(namespace, name, version)
        except SkillSafeError as e:
            if e.status in (401, 403) and not api_key:
                print("  Error: This skill may be private. Run 'skillsafe auth' to sign in.", file=sys.stderr)
            else:
                print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)

        if dl_format == "files":
            print(f"  Received v2 manifest: {len(dl_data.get('files', []))} file(s)")
        else:
            archive_bytes, server_tree_hash = dl_data
            dl_data = archive_bytes  # normalize
            print(f"  Downloaded {len(archive_bytes) / 1024:.1f} KB")

    # Publisher trust signal — used to adjust scan output verbosity
    publisher_verified = bool(meta and meta.get("publisher_validated"))

    # ---------- V2 path (file manifest) ----------

    if dl_format == "files":
        manifest = dl_data

        # Build GitHub raw content base URL for blob fallback
        _gh_raw_base: Optional[str] = None
        try:
            _gh_url = meta.get("github_repo_url", "") if meta else ""
        except NameError:
            _gh_url = ""
        if isinstance(_gh_url, str) and _gh_url.startswith("https://github.com/"):
            _gh_parts = _gh_url.replace("https://github.com/", "").rstrip("/").split("/")
            if len(_gh_parts) >= 2:
                _base = f"https://raw.githubusercontent.com/{_gh_parts[0]}/{_gh_parts[1]}/HEAD"
                try:
                    _subpath = meta.get("github_subpath", "") if meta else ""
                except NameError:
                    _subpath = ""
                _gh_raw_base = f"{_base}/{_subpath}" if _subpath else _base

        # Reconstruct into a temp dir, scan, then move to final location
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            print("  Reconstructing skill from manifest...")
            try:
                local_tree_hash, cached_count, downloaded_count = install_from_manifest(
                    client, manifest, tmppath, verbose=True,
                    github_raw_base=_gh_raw_base,
                    skill_name=name,
                )
            except SkillSafeError as e:
                print(f"\n  Error: {e.message}", file=sys.stderr)
                sys.exit(1)

            print(f"  Files: {downloaded_count} downloaded, {cached_count} from cache")
            print(f"  Tree hash verified: {dim(local_tree_hash[:30])}...")

            # Scan reconstructed skill
            print("  Scanning downloaded skill...")
            scanner = Scanner()
            consumer_report = scanner.scan(tmppath, tree_hash=local_tree_hash)
            _install_ref = f"@{namespace}/{name}"
            _print_scan_results(consumer_report, indent=2, publisher_verified=publisher_verified, skill_ref=_install_ref)

            # Submit verification
            print("\n  Submitting verification report...")
            verdict, details = _submit_verification(client, namespace, name, version, consumer_report)

            # Display verdict and prompt
            if not _handle_verdict(verdict, details):
                return

            # Install to final location
            _install_to_target(args, namespace, name, version, local_tree_hash, source_dir=tmppath)

    # ---------- V1 path (archive) ----------

    else:
        archive_bytes = dl_data

        # Verify tree hash
        local_tree_hash = compute_tree_hash(archive_bytes)
        if not server_tree_hash:
            print("Warning: Server did not provide a tree hash. Cannot verify archive integrity.", file=sys.stderr)
            print("Aborting installation for safety.", file=sys.stderr)
            sys.exit(1)
        if local_tree_hash != server_tree_hash:
            print(red("\n  CRITICAL: Tree hash mismatch — possible tampering!"))
            print(f"    Server:  {server_tree_hash}")
            print(f"    Local:   {local_tree_hash}")
            print("  Aborting installation.")
            sys.exit(1)
        print(f"  Tree hash verified: {dim(local_tree_hash[:30])}...")

        # Extract to temp dir and scan
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            print("  Extracting archive...")
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                _safe_extractall(tar, tmppath)

            print("  Scanning downloaded skill...")
            scanner = Scanner()
            consumer_report = scanner.scan(tmppath, tree_hash=local_tree_hash)
            _install_ref = f"@{namespace}/{name}"
            _print_scan_results(consumer_report, indent=2, publisher_verified=publisher_verified, skill_ref=_install_ref)

        # Submit verification
        print("\n  Submitting verification report...")
        verdict, details = _submit_verification(client, namespace, name, version, consumer_report)

        # Display verdict and prompt
        if not _handle_verdict(verdict, details):
            return

        # Install to final location (from archive)
        _install_to_target_archive(args, namespace, name, version, local_tree_hash, archive_bytes)

    # Hint for unauthenticated users
    if not api_key:
        print(dim("\n  Tip: Run 'skillsafe auth' to enable dual-side verification on future installs."))


def _submit_verification(
    client: SkillSafeClient,
    namespace: str,
    name: str,
    version: str,
    consumer_report: Dict[str, Any],
) -> Tuple[str, Dict[str, Any]]:
    """Submit a consumer verification report. Returns (verdict, details)."""
    try:
        verdict_result = client.verify(namespace, name, version, consumer_report)
        return verdict_result.get("verdict", "unknown"), verdict_result.get("details", {})
    except SkillSafeError as e:
        if e.status == 401:
            print("  Verification skipped (sign in with 'skillsafe auth' to enable dual-side verification).")
            return "skipped", {}
        elif e.status == 403:
            print(f"  Verification skipped ({e.message}).")
            return "skipped", {}
        elif e.status == 404 or "no publisher" in e.message.lower():
            print("  Verification skipped (no publisher scan report for this version).")
            return "skipped", {}
        else:
            print(f"  Warning: Verification failed: {e.message}", file=sys.stderr)
            print("  Continuing without verification.", file=sys.stderr)
            return "error", {}


def _handle_verdict(verdict: str, details: Dict[str, Any]) -> bool:
    """Display verification verdict. Returns True to proceed, False to cancel."""
    if verdict == "verified":
        print(green("  Verified: publisher and consumer scans match."))
    elif verdict == "divergent":
        if details.get("ruleset_upgrade_divergence"):
            print(yellow("  WARNING: Scan reports diverge due to scanner ruleset upgrade."))
            print(f"    Publisher ruleset: {details.get('publisher_ruleset_version', '?')}")
            print(f"    Your ruleset:      {details.get('consumer_ruleset_version', '?')}")
            print("    The publisher's scan used an older ruleset that may have missed findings.")
            print("    Recommendation: ask the publisher to re-scan and re-share with the current scanner.")
        else:
            print(yellow("  WARNING: Scan reports diverge."))
        for key, val in details.items():
            if key not in ("ruleset_upgrade_divergence", "publisher_ruleset_version", "consumer_ruleset_version"):
                print(f"    {key}: {val}")
        if sys.stdin.isatty():
            try:
                answer = input("  Install anyway? [y/N] ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = "n"
        else:
            answer = "n"
            print("  Non-interactive mode: skipping divergent skill.")
        if answer != "y":
            print("  Installation cancelled.")
            return False
    elif verdict == "critical":
        print(red("  CRITICAL: Tree hash mismatch detected by server!"))
        for key, val in details.items():
            print(f"    {key}: {val}")
        print("  Aborting installation.")
        sys.exit(1)
    elif verdict in ("skipped", "error"):
        pass  # Already printed reason above
    else:
        print(f"  Verdict: {verdict}")
    return True


def _write_install_metadata(
    install_dir: Path,
    namespace: str,
    name: str,
    version: str,
    tree_hash: str,
) -> None:
    """Record install in central index."""
    _register_install(install_dir, namespace, name, version, tree_hash)


def _maybe_hint_global_install(
    args: argparse.Namespace,
    namespace: str,
    name: str,
) -> None:
    """After a failed global install, print alternative global install options.

    Only shown when the user explicitly requested a global install (``--location global``)
    and the install failed (e.g. permission error).
    """
    if getattr(args, "location", "project") != "global":
        return

    print(f"\n  To install globally with a different tool, re-run with --tool <name> --location global:")
    for key, path in TOOL_SKILLS_DIRS.items():
        label = TOOL_DISPLAY_NAMES.get(key, key)
        print(f"    skillsafe install @{namespace}/{name} --tool {key:<12} --location global  # {label}: {path}")


def _install_to_target(
    args: argparse.Namespace,
    namespace: str,
    name: str,
    version: str,
    tree_hash: str,
    source_dir: Path,
) -> Path:
    """Copy files from source_dir to the final install location. Returns install_dir."""

    def _safe_copytree(src: Path, dst: Path) -> None:
        """Copy tree from src to dst, skipping any symlinks for safety."""
        source_names = {item.name for item in src.iterdir() if not item.is_symlink()}
        # Remove stale files not present in source (from previous version)
        if dst.exists():
            for existing in list(dst.iterdir()):
                if existing.name not in source_names:
                    if existing.is_dir():
                        shutil.rmtree(existing)
                    else:
                        existing.unlink()
        for item in src.iterdir():
            if ".." in item.name or os.sep in item.name:
                continue  # Defense-in-depth: skip suspicious names
            target = dst / item.name
            if item.is_symlink():
                continue  # Skip symlinks — never install them
            if item.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                shutil.copytree(item, target, symlinks=False)
            else:
                shutil.copy2(item, target)

    # Canonical mode: install to .agents/skills/<name>/ and symlink to detected agents
    if _should_use_canonical_mode(args):
        # Auto-detect: if the CLI itself is installed as a skill, install
        # siblings into the same skills/ directory so the invoking agent
        # can discover them without extra configuration.
        detected_base = _detect_skills_base_from_script()
        canonical_base = detected_base or (Path.cwd() / CANONICAL_SKILLS_SUBDIR)
        install_dir = canonical_base / name
        try:
            install_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(install_dir, 0o700)
            except OSError:
                pass
            print(f"\n  Installing to {install_dir}...")
            _safe_copytree(source_dir, install_dir)
            print(green(f"\n  \u2713 Installed @{namespace}/{name}@{version}"))
            print(f"  Location: {install_dir}")
        except (PermissionError, OSError) as e:
            print(red(f"\n  Error: could not install to {install_dir}: {e}"), file=sys.stderr)
            raise

        # Create symlinks unless --no-symlink (skip when using detected base —
        # the invoking agent already sees the skills/ directory)
        if not getattr(args, "no_symlink", False) and not detected_base:
            created = _create_agent_symlinks(canonical_base, name, Path.cwd())
            if created:
                print(f"\n  Symlinked to {len(created)} agent(s):")
                for tool_key, link_path in created:
                    label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
                    print(f"    {label}: {link_path}")
            else:
                agents = _detect_agent_dirs(Path.cwd())
                if not agents:
                    print(dim("\n  No agent config directories detected in this project."))
                    print(dim("  Tip: Use --tool <name> to install directly into a specific agent's directory."))

        _write_install_metadata(install_dir, namespace, name, version, tree_hash)

        return install_dir

    skills_dir = _resolve_skills_dir(args)

    if skills_dir:
        install_dir = skills_dir / name
        try:
            install_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(install_dir, 0o700)
            except OSError:
                pass
            print(f"\n  Installing to {install_dir}...")
            _safe_copytree(source_dir, install_dir)
            print(green(f"\n  Installed @{namespace}/{name}@{version}"))
            print(f"  Location: {install_dir}")
        except (PermissionError, OSError) as e:
            print(red(f"\n  Error: could not install to {install_dir}: {e}"), file=sys.stderr)
            _maybe_hint_global_install(args, namespace, name)
            raise
    else:
        install_dir = SKILLS_DIR / f"@{namespace}" / name / version
        install_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(install_dir, 0o700)
        except OSError:
            pass
        print(f"\n  Installing to {install_dir}...")
        _safe_copytree(source_dir, install_dir)

        # Update 'current' symlink
        current_link = install_dir.parent / "current"
        if current_link.is_symlink() or current_link.exists():
            current_link.unlink()
        if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?$', version):
            print(red(f"  Invalid version format: {version}"))
            return install_dir
        current_link.symlink_to(version)
        print(green(f"\n  Installed @{namespace}/{name}@{version}"))
        print(f"  Location: {install_dir}")

    _write_install_metadata(install_dir, namespace, name, version, tree_hash)

    return install_dir


def _install_to_target_archive(
    args: argparse.Namespace,
    namespace: str,
    name: str,
    version: str,
    tree_hash: str,
    archive_bytes: bytes,
) -> Path:
    """Extract a v1 archive to the final install location. Returns install_dir."""

    # Canonical mode: install to .agents/skills/<name>/ and symlink to detected agents
    if _should_use_canonical_mode(args):
        detected_base = _detect_skills_base_from_script()
        canonical_base = detected_base or (Path.cwd() / CANONICAL_SKILLS_SUBDIR)
        install_dir = canonical_base / name
        try:
            if install_dir.exists():
                shutil.rmtree(install_dir)
            install_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(install_dir, 0o700)
            except OSError:
                pass
            print(f"\n  Installing to {install_dir}...")
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                _safe_extractall(tar, install_dir)
            print(green(f"\n  \u2713 Installed @{namespace}/{name}@{version}"))
            print(f"  Location: {install_dir}")
        except (PermissionError, OSError) as e:
            print(red(f"\n  Error: could not install to {install_dir}: {e}"), file=sys.stderr)
            raise

        # Create symlinks unless --no-symlink (skip when using detected base)
        if not getattr(args, "no_symlink", False) and not detected_base:
            created = _create_agent_symlinks(canonical_base, name, Path.cwd())
            if created:
                print(f"\n  Symlinked to {len(created)} agent(s):")
                for tool_key, link_path in created:
                    label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
                    print(f"    {label}: {link_path}")
            else:
                agents = _detect_agent_dirs(Path.cwd())
                if not agents:
                    print(dim("\n  No agent config directories detected in this project."))
                    print(dim("  Tip: Use --tool <name> to install directly into a specific agent's directory."))

        _write_install_metadata(install_dir, namespace, name, version, tree_hash)

        return install_dir

    skills_dir = _resolve_skills_dir(args)

    if skills_dir:
        install_dir = skills_dir / name
        try:
            # Clean stale files from previous version before extracting
            if install_dir.exists():
                shutil.rmtree(install_dir)
            install_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(install_dir, 0o700)
            except OSError:
                pass
            print(f"\n  Installing to {install_dir}...")
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
                _safe_extractall(tar, install_dir)
            print(green(f"\n  Installed @{namespace}/{name}@{version}"))
            print(f"  Location: {install_dir}")
        except (PermissionError, OSError) as e:
            print(red(f"\n  Error: could not install to {install_dir}: {e}"), file=sys.stderr)
            _maybe_hint_global_install(args, namespace, name)
            raise
    else:
        install_dir = SKILLS_DIR / f"@{namespace}" / name / version
        # Clean stale files from previous version before extracting
        if install_dir.exists():
            shutil.rmtree(install_dir)
        install_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(install_dir, 0o700)
        except OSError:
            pass
        print(f"\n  Installing to {install_dir}...")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tar:
            _safe_extractall(tar, install_dir)

        # Update 'current' symlink
        current_link = install_dir.parent / "current"
        if current_link.is_symlink() or current_link.exists():
            current_link.unlink()
        if not re.match(r'^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.]+)?$', version):
            print(red(f"  Invalid version format: {version}"))
            return install_dir
        current_link.symlink_to(version)
        print(green(f"\n  Installed @{namespace}/{name}@{version}"))
        print(f"  Location: {install_dir}")

    _write_install_metadata(install_dir, namespace, name, version, tree_hash)

    return install_dir


def cmd_search(args: argparse.Namespace) -> None:
    """Search the skill registry."""
    query: Optional[str] = getattr(args, "query", None)
    category: Optional[str] = getattr(args, "category", None)
    sort: str = getattr(args, "sort", "popular")
    limit: int = getattr(args, "limit", 20)
    page: Optional[int] = getattr(args, "page", None)
    fetch_all: bool = getattr(args, "all", False)

    cfg = load_config()
    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE))

    try:
        if fetch_all:
            # Auto-paginate: collect all results across pages using cursor
            all_skills = []
            cursor: Optional[str] = None
            page_num = 1
            while True:
                resp = client.search(query=query, category=category, sort=sort, limit=100, cursor=cursor)
                batch = resp.get("data", [])
                all_skills.extend(batch)
                pagination = (resp.get("meta") or {}).get("pagination", {})
                has_more = pagination.get("has_more", False)
                cursor = pagination.get("next_cursor")
                if not has_more or not cursor:
                    break
                page_num += 1
            skills = all_skills
            pagination_info = f"{len(skills)} total"
        else:
            resp = client.search(query=query, category=category, sort=sort, limit=limit, page=page)
            skills = resp.get("data", [])
            pagination = (resp.get("meta") or {}).get("pagination", {})
            has_more = pagination.get("has_more", False)
            total_count = pagination.get("total_count")
            total_pages = pagination.get("total_pages")
            if total_count is not None:
                pagination_info = f"{len(skills)} of {total_count} (page {page or 1}/{total_pages})"
            elif has_more:
                pagination_info = f"{len(skills)} (more available — use --page N or --all)"
            else:
                pagination_info = str(len(skills))
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    if not skills:
        print("No skills found.")
        return

    print(f"Found {pagination_info} skill(s):\n")

    # Table header
    print(f"  {'SKILL':<35} {'VERSION':<10} {'STARS':<7} {'INSTALLS':<10} DESCRIPTION")
    print(f"  {'─' * 35} {'─' * 10} {'─' * 7} {'─' * 10} {'─' * 30}")

    for s in skills:
        ns = s.get("namespace", "")
        nm = s.get("name_display", s.get("name", ""))
        ref = f"{ns}/{nm}"
        ver = s.get("latest_version") or "-"
        stars = s.get("star_count") or 0
        installs = s.get("install_count") or 0
        desc = (s.get("description") or "")[:40]
        print(f"  {ref:<35} {ver:<10} {stars:<7} {installs:<10} {desc}")


def cmd_yank(args: argparse.Namespace) -> None:
    """Yank a specific version of a skill (blocks future downloads of that version)."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version
    reason: str = getattr(args, "reason", "") or ""

    print(f"Yanking {bold(f'@{namespace}/{name}')} v{version}...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        client.yank(namespace, name, version, reason=reason)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    print(yellow(f"  Yanked @{namespace}/{name}@{version}"))
    if reason:
        print(f"  Reason: {reason}")
    print(f"\n  This version is now blocked from download.")
    print(f"  Other versions of the skill remain available.")
    print(f"\n  To install a different version:")
    print(f"    skillsafe install @{namespace}/{name} --version <other-version>")


def cmd_import(args: argparse.Namespace) -> None:
    """Import a skill from a GitHub or ClawHub URL as a public placeholder on SkillSafe."""
    cfg = require_config()

    raw_url: str = args.url.strip()
    # Normalize bare URLs to https://
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    # Detect source
    if raw_url.startswith("https://github.com/"):
        source = "github"
    elif raw_url.startswith("https://clawhub.ai/"):
        source = "clawhub"
    else:
        print(
            "Error: Unsupported URL. Must be a GitHub URL (github.com/owner/repo) "
            "or a ClawHub URL (clawhub.ai/owner/skill).",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Importing {bold(raw_url)} into SkillSafe...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        body = json.dumps({"url": raw_url}).encode()
        result = client._request("POST", "/v1/skills/import-url", body=body, content_type="application/json")
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    data = result.get("data", {}) if isinstance(result, dict) else {}
    namespace = data.get("namespace", "").lstrip("@")
    name = data.get("name", "")
    created = data.get("created", False)

    source_label = "GitHub" if source == "github" else "ClawHub"
    if created:
        print(f"  {green('✓')} Imported from {source_label} as {bold(f'@{namespace}/{name}')}")
    else:
        print(f"  {bold(f'@{namespace}/{name}')} already exists — updated metadata from {source_label}")

    if namespace and name:
        print(f"\n  View at: https://skillsafe.ai/skill/@{namespace}/{name}")
        print(f"\n  {bold('Next steps:')}")
        print(f"    skillsafe scan <local-path>        — scan and verify the skill files")
        print(f"    skillsafe save <local-path>        — save a version")
        print(f"    skillsafe share @{namespace}/{name}  — create a shareable link")


def cmd_demo(args: argparse.Namespace) -> None:
    """Upload a demo JSON recording for a skill version."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version

    json_path = args.json_file
    if not os.path.isfile(json_path):
        print(f"Error: File not found: {json_path}", file=sys.stderr)
        sys.exit(1)

    file_size = os.path.getsize(json_path)
    max_bytes = 5 * 1024 * 1024  # 5 MB
    if file_size > max_bytes:
        print(f"Error: Demo file is too large ({file_size} bytes). Maximum size is 5 MB.", file=sys.stderr)
        sys.exit(1)

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            demo_json = json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {json_path}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(demo_json, dict):
        print("Error: Demo JSON must be an object.", file=sys.stderr)
        sys.exit(1)

    if demo_json.get("schema") != "skillsafe-demo/1":
        print('Error: Invalid demo schema. Expected "skillsafe-demo/1".', file=sys.stderr)
        sys.exit(1)

    # Resolve title: --title flag > demo.title field > error
    title: str = getattr(args, "title", "") or demo_json.get("title", "") or ""
    title = title.strip()
    if not title:
        print("Error: title is required. Provide --title or set demo.title in the JSON.", file=sys.stderr)
        sys.exit(1)
    if len(title) > 200:
        print("Error: title must be at most 200 characters.", file=sys.stderr)
        sys.exit(1)

    print(f"Uploading demo for {bold(f'@{namespace}/{name}')} v{version}...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])

    try:
        result = client.upload_demo(namespace, name, version, demo_json, title=title)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    demo_id = result.get("demo_id", "")
    url = result.get("url", f"/demo/{demo_id}")
    msg_count = result.get("message_count", 0)

    print(f"  {bold('Demo uploaded successfully!')}")
    print(f"  ID:       {demo_id}")
    print(f"  Title:    {title}")
    print(f"  Messages: {msg_count}")
    print(f"  URL:      https://skillsafe.ai{url}")


# ---------------------------------------------------------------------------
# demo-from-session: convert Claude Code JSONL → skillsafe-demo/1 + upload
# ---------------------------------------------------------------------------

# Sensitive data patterns (ordered: more specific first)
_MASK_PATTERNS: List[Tuple[str, str]] = [
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "[ANTHROPIC_KEY]"),
    (r"\bsk-[A-Za-z0-9]{20,}", "[API_KEY]"),
    (r"ghp_[A-Za-z0-9]{36,}", "[GITHUB_TOKEN]"),
    (r"github_pat_[A-Za-z0-9_]{59,}", "[GITHUB_TOKEN]"),
    (r"AKIA[A-Z0-9]{16}", "[AWS_ACCESS_KEY]"),
    (r"Bearer [A-Za-z0-9\-._~+/]+=*", "Bearer [TOKEN]"),
    (r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", "[EMAIL]"),
    (
        r"(?i)(api[_\-]?key|secret[_\-]?key|access[_\-]?token|auth[_\-]?token)"
        r"\s*[=:]\s*[\"']?([A-Za-z0-9_\-]{16,})[\"']?",
        r"\1=[SECRET]",
    ),
]

# User message content that should be skipped (system-injected tags)
_SKIP_CONTENT_TAGS = (
    "<local-command-caveat>",
    "<local-command-stdout>",
    "<command-name>",
    "<command-message>",
    "<command-args>",
    "<user-prompt-submit-hook>",
    "<system-reminder>",
    "<function_calls>",
)


def _mask_sensitive(text: str, home_dir: str = "") -> Tuple[str, int]:
    """Mask sensitive data in *text*. Returns (masked_text, replacement_count)."""
    count = 0
    if home_dir and home_dir in text:
        text = text.replace(home_dir, "~")
        count += 1
    for pattern, replacement in _MASK_PATTERNS:
        new_text, n = re.subn(pattern, replacement, text)
        if n:
            text = new_text
            count += n
    return text, count


def _truncate_output(text: str, max_lines: int = 120) -> str:
    """Keep at most *max_lines* of a tool output, summarising the middle."""
    lines = text.split("\n")
    if len(lines) <= max_lines:
        return text
    head = (max_lines * 2) // 3
    tail = max_lines // 6
    omitted = len(lines) - head - tail
    return "\n".join(lines[:head] + [f"[... {omitted} lines omitted ...]"] + lines[-tail:])


def _format_tool_input(name: str, input_obj: Any) -> str:
    """Render tool input as a human-readable string."""
    if not isinstance(input_obj, dict):
        return str(input_obj)[:500]
    if name == "Bash":
        return input_obj.get("command", json.dumps(input_obj))
    if name == "Read":
        return input_obj.get("file_path", json.dumps(input_obj))
    if name == "Glob":
        pat = input_obj.get("pattern", "")
        path = input_obj.get("path", "")
        return f"{pat} in {path}" if path else pat
    if name == "Grep":
        return input_obj.get("pattern", json.dumps(input_obj))
    if name in ("Edit", "Write", "NotebookEdit"):
        return input_obj.get("file_path", json.dumps(input_obj))
    if name == "Agent":
        return (input_obj.get("prompt") or json.dumps(input_obj))[:300]
    return json.dumps(input_obj, ensure_ascii=False)[:500]


def _convert_claude_session(
    path: str,
    filter_keyword: Optional[str] = None,
    max_output_lines: int = 120,
) -> Tuple[List[Dict[str, Any]], int]:
    """Convert a Claude Code session JSONL to skillsafe-demo/1 message list.

    Returns ``(messages, total_masked_count)``.
    """
    with open(path, "r", encoding="utf-8") as f:
        entries = [json.loads(line) for line in f if line.strip()]

    home_dir = str(Path.home())

    # Pass 1 — build tool_use_id → output string map
    tool_results: Dict[str, str] = {}
    for entry in entries:
        if entry.get("type") != "user":
            continue
        content = entry.get("message", {}).get("content", "")
        if not isinstance(content, list):
            continue
        for item in content:
            if not isinstance(item, dict) or item.get("type") != "tool_result":
                continue
            tool_id = item.get("tool_use_id", "")
            result = item.get("content", "")
            if isinstance(result, list):
                result = "\n".join(b.get("text", "") for b in result if isinstance(b, dict))
            tool_results[tool_id] = str(result)

    # Pass 2 — build messages list
    messages: List[Dict[str, Any]] = []
    total_masked = 0

    for entry in entries:
        msg_type = entry.get("type", "")
        content = entry.get("message", {}).get("content", "")

        if msg_type == "assistant":
            if not isinstance(content, list):
                continue
            text_parts: List[str] = []
            tool_uses: List[Dict[str, str]] = []

            for item in content:
                if not isinstance(item, dict):
                    continue
                if item.get("type") == "text":
                    t = item.get("text", "").strip()
                    if t:
                        t, n = _mask_sensitive(t, home_dir)
                        total_masked += n
                        text_parts.append(t)
                elif item.get("type") == "tool_use":
                    tool_id = item.get("id", "")
                    tool_name = item.get("name", "")
                    input_str = _format_tool_input(tool_name, item.get("input", {}))
                    input_str, n = _mask_sensitive(input_str, home_dir)
                    total_masked += n
                    output_str = _truncate_output(tool_results.get(tool_id, ""), max_output_lines)
                    output_str, n = _mask_sensitive(output_str, home_dir)
                    total_masked += n
                    tool_uses.append({"tool": tool_name, "input": input_str, "output": output_str})

            if not text_parts and not tool_uses:
                continue
            msg: Dict[str, Any] = {"role": "assistant", "content": "\n\n".join(text_parts)}
            if tool_uses:
                msg["tool_uses"] = tool_uses
            messages.append(msg)

        elif msg_type == "user":
            if isinstance(content, str):
                if any(tag in content for tag in _SKIP_CONTENT_TAGS):
                    continue
                text = content.strip()
                if not text:
                    continue
                text, n = _mask_sensitive(text, home_dir)
                total_masked += n
                messages.append({"role": "user", "content": text})
            elif isinstance(content, list):
                # Pure tool-result messages are already consumed via tool_results map
                if all(isinstance(i, dict) and i.get("type") == "tool_result" for i in content if isinstance(i, dict)):
                    continue
                text_parts = []
                for item in content:
                    if not isinstance(item, dict) or item.get("type") != "text":
                        continue
                    t = item.get("text", "").strip()
                    if t and not any(t.startswith(tag) for tag in _SKIP_CONTENT_TAGS):
                        t, n = _mask_sensitive(t, home_dir)
                        total_masked += n
                        text_parts.append(t)
                if text_parts:
                    messages.append({"role": "user", "content": "\n\n".join(text_parts)})

    # Optional keyword filter — keep messages that mention the keyword
    if filter_keyword:
        kw = filter_keyword.lower()
        messages = [
            m for m in messages
            if kw in m.get("content", "").lower()
            or any(
                kw in u.get("tool", "").lower()
                or kw in u.get("input", "").lower()
                or kw in u.get("output", "").lower()
                for u in m.get("tool_uses", [])
            )
        ]

    return messages, total_masked


def cmd_demo_from_session(args: argparse.Namespace) -> None:
    """Convert a Claude Code session JSONL to skillsafe-demo/1 and optionally upload."""
    session_path: str = args.session
    if not os.path.isfile(session_path):
        print(f"Error: Session file not found: {session_path}", file=sys.stderr)
        sys.exit(1)

    skill_ref: Optional[str] = getattr(args, "skill", None)
    version: Optional[str] = getattr(args, "version", None)
    title: str = (getattr(args, "title", None) or "").strip()
    out_path: Optional[str] = getattr(args, "out", None)
    filter_keyword: Optional[str] = getattr(args, "filter_keyword", None)
    max_output_lines: int = getattr(args, "max_output_lines", 120)
    no_upload: bool = getattr(args, "no_upload", False)

    if not title:
        print("Error: --title is required.", file=sys.stderr)
        sys.exit(1)
    if len(title) > 200:
        print("Error: --title must be at most 200 characters.", file=sys.stderr)
        sys.exit(1)

    print(f"Converting: {session_path}")
    if filter_keyword:
        print(f"Filter keyword: {filter_keyword!r}")

    try:
        messages, mask_count = _convert_claude_session(
            session_path,
            filter_keyword=filter_keyword,
            max_output_lines=max_output_lines,
        )
    except (OSError, json.JSONDecodeError) as e:
        print(f"Error reading session file: {e}", file=sys.stderr)
        sys.exit(1)

    if not messages:
        print("Error: No usable messages found (or all filtered out).", file=sys.stderr)
        sys.exit(1)

    demo_json: Dict[str, Any] = {
        "schema": "skillsafe-demo/1",
        "title": title,
        "messages": messages,
    }

    size_bytes = len(json.dumps(demo_json).encode("utf-8"))
    print(f"  Messages: {len(messages)}")
    print(f"  Size:     {size_bytes:,} bytes")
    if mask_count:
        print(f"  Masked:   {mask_count} sensitive value(s) replaced")

    if size_bytes > 5 * 1024 * 1024:
        print(
            f"\nError: Demo is too large ({size_bytes:,} bytes, max 5 MB).\n"
            "Try --max-output-lines to truncate tool outputs more aggressively,\n"
            "or --filter-keyword to keep only relevant messages.",
            file=sys.stderr,
        )
        sys.exit(1)

    # --- save to file -------------------------------------------------------
    if out_path or no_upload or not skill_ref or not version:
        target = out_path
        if not target:
            fd, target = tempfile.mkstemp(suffix=".json", prefix="skillsafe-demo-")
            os.close(fd)
        with open(target, "w", encoding="utf-8") as f:
            json.dump(demo_json, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print(f"\nSaved to: {target}")
        if skill_ref and version:
            print(f"To upload: skillsafe demo {target} {skill_ref} --version {version}")
        return

    # --- upload directly ----------------------------------------------------
    cfg = require_config()
    namespace, name = parse_skill_ref(skill_ref)
    print(f"\nUploading demo for {bold(f'@{namespace}/{name}')} v{version}...")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])
    try:
        result = client.upload_demo(namespace, name, version, demo_json, title=title)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    demo_id = result.get("demo_id", "")
    url = result.get("url", f"/demo/{demo_id}")
    print(f"  {bold('Demo uploaded successfully!')}")
    print(f"  ID:       {demo_id}")
    print(f"  Title:    {title}")
    print(f"  Messages: {result.get('message_count', len(messages))}")
    print(f"  URL:      https://skillsafe.ai{url}")


def cmd_info(args: argparse.Namespace) -> None:
    """Show detailed information about a skill."""
    namespace, name = parse_skill_ref(args.skill)
    cfg = load_config()
    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg.get("api_key"))

    try:
        meta = client.get_metadata(namespace, name, auth=True)
    except SkillSafeError as e:
        print(f"Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n  {bold(meta.get('namespace', '') + '/' + meta.get('name_display', meta.get('name', '')))}")
    print()
    if meta.get("description"):
        print(f"  {meta['description']}")
        print()
    print(f"  Latest version:    {meta.get('latest_version', '-')}")
    print(f"  Category:          {meta.get('category', '-')}")
    print(f"  Tags:              {meta.get('tags', '-')}")
    print(f"  Installs:          {meta.get('install_count', 0)}")
    print(f"  Stars:             {meta.get('star_count', 0)}")
    print(f"  Verifications:     {meta.get('verification_count', 0)}")
    print(f"  Status:            {meta.get('status', '-')}")
    print(f"  Created:           {meta.get('created_at', '-')}")

    # Fetch versions
    try:
        ver_resp = client.get_versions(namespace, name, limit=10, auth=True)
        versions = ver_resp.get("data", [])
        if versions:
            print(f"\n  Recent versions:")
            for v in versions:
                ver = v.get("version", "?")
                ts = (v.get("saved_at") or v.get("published_at") or "")[:10]
                yanked = " (yanked)" if v.get("yanked") else ""
                log = v.get("changelog") or ""
                log_short = f" — {log[:50]}" if log else ""
                print(f"    {ver:<12} {ts}{yanked}{log_short}")
    except SkillSafeError:
        pass  # Version list is optional

    print()


def _list_skills_in_dir(directory: Path) -> List[Tuple[str, str, str]]:
    """List skills in a flat skills directory (each subdirectory is a skill).

    Returns list of (name, description, version) tuples.
    """
    results: List[Tuple[str, str, str]] = []
    if not directory.is_dir():
        return results
    for skill_dir in sorted(directory.iterdir()):
        if not skill_dir.is_dir():
            continue
        skill_md = skill_dir / "SKILL.md"
        desc = ""
        if skill_md.exists():
            try:
                text = skill_md.read_text(encoding="utf-8", errors="replace")
                for line in text.splitlines():
                    if line.startswith("description:"):
                        desc = line[len("description:"):].strip()[:60]
                        break
            except Exception:
                pass
        # Read version from central install index
        ver = ""
        meta = _get_install_meta(skill_dir)
        if meta:
            ver = meta.get("version", "")
        results.append((skill_dir.name, desc, ver))
    return results


def cmd_list(args: argparse.Namespace) -> None:
    """List locally installed skills."""

    found_any = False

    # 1. Well-known agent skills directories
    for tool_key, agent_dir in TOOL_SKILLS_DIRS.items():
        label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
        skills = _list_skills_in_dir(agent_dir)
        if skills:
            found_any = True
            print(f"{bold(f'{label} skills')} ({agent_dir}):\n")
            print(f"  {'SKILL':<30} {'VERSION':<10} DESCRIPTION")
            print(f"  {'─' * 30} {'─' * 10} {'─' * 50}")
            for name, desc, ver in skills:
                print(f"  {name:<30} {ver or '-':<10} {desc}")
            print()

    # 2. Custom --skills-dir paths
    extra_dirs = getattr(args, "skills_dir", None) or []
    for dir_str in extra_dirs:
        extra_path = Path(dir_str).expanduser().resolve()
        skills = _list_skills_in_dir(extra_path)
        if skills:
            found_any = True
            print(f"{bold('Skills')} ({extra_path}):\n")
            print(f"  {'SKILL':<30} {'VERSION':<10} DESCRIPTION")
            print(f"  {'─' * 30} {'─' * 10} {'─' * 50}")
            for name, desc, ver in skills:
                print(f"  {name:<30} {ver or '-':<10} {desc}")
            print()

    # 3. SkillSafe registry skills (~/.skillsafe/skills/)
    if SKILLS_DIR.is_dir():
        registry_skills: List[Tuple[str, str, str]] = []
        for ns_dir in sorted(SKILLS_DIR.iterdir()):
            if not ns_dir.is_dir():
                continue
            ns = ns_dir.name
            for skill_dir in sorted(ns_dir.iterdir()):
                if not skill_dir.is_dir():
                    continue
                current = skill_dir / "current"
                version = "?"
                if current.is_symlink():
                    version = current.resolve().name
                elif current.exists():
                    version = current.name
                else:
                    versions = [d.name for d in skill_dir.iterdir() if d.is_dir() and d.name != "current"]
                    def _semver_key(v: str) -> tuple:
                        """Parse version string into a tuple for proper numeric sorting."""
                        parts = v.split("-", 1)[0].split(".")
                        try:
                            return tuple(int(p) for p in parts)
                        except ValueError:
                            return (0,)
                    version = sorted(versions, key=_semver_key)[-1] if versions else "?"
                registry_skills.append((f"{ns}/{skill_dir.name}", version, str(skill_dir)))

        if registry_skills:
            found_any = True
            print(f"{bold('SkillSafe registry skills')} ({SKILLS_DIR}):\n")
            print(f"  {'SKILL':<35} {'VERSION':<12} PATH")
            print(f"  {'─' * 35} {'─' * 12} {'─' * 40}")
            for ref, ver, path in registry_skills:
                print(f"  {ref:<35} {ver:<12} {path}")
            print()

    # 4. Project-level skills (per-tool subdir in cwd)
    for tool_key, subdir in TOOL_PROJECT_SKILLS_SUBDIRS.items():
        project_skills_dir = Path.cwd() / subdir
        if project_skills_dir.is_dir():
            proj_skills = _list_skills_in_dir(project_skills_dir)
            if proj_skills:
                found_any = True
                label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
                print(f"{bold(f'Project skills ({label})')} ({project_skills_dir}):\n")
                print(f"  {'SKILL':<30} {'VERSION':<10} DESCRIPTION")
                print(f"  {'─' * 30} {'─' * 10} {'─' * 50}")
                for name, desc, ver in proj_skills:
                    print(f"  {name:<30} {ver or '-':<10} {desc}")
                print()

    if not found_any:
        print("No skills installed.")
        print()
        for tool_key, agent_dir in TOOL_SKILLS_DIRS.items():
            label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
            print(f"  {label + ' skills dir:':<25} {agent_dir}")
        print(f"  {'SkillSafe skills dir:':<25} {SKILLS_DIR}")
        for tool_key, subdir in TOOL_PROJECT_SKILLS_SUBDIRS.items():
            label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
            print(f"  {label + ' project skills:':<25} ./{subdir}/")



def cmd_eval(args: argparse.Namespace) -> None:
    """Upload eval results for a skill version to SkillSafe."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version

    payload: Dict[str, Any] = {}

    # Parse from eval JSON file (skill-creator format)
    if getattr(args, "eval_json", None):
        eval_path = Path(args.eval_json).expanduser().resolve()
        if not eval_path.exists():
            print(f"Error: Eval JSON file not found: {eval_path}", file=sys.stderr)
            sys.exit(1)
        with open(eval_path, "r", encoding="utf-8") as f:
            eval_data = json.load(f)
        # Support skill-creator summary format: { summary: { pass_rate, total, passed } }
        summary = eval_data.get("summary", eval_data)
        pass_rate = summary.get("pass_rate") or summary.get("passRate")
        test_cases = summary.get("total") or summary.get("test_cases") or summary.get("testCases")
        pass_count = summary.get("passed") or summary.get("pass_count")
        model = summary.get("model") or eval_data.get("model")
        payload["eval_json"] = json.dumps(eval_data)
        if pass_rate is not None:
            pr = float(pass_rate)
            # Auto-convert 0-1 range to 0-100 (API expects 0-100)
            if 0 < pr <= 1:
                pr = pr * 100
            payload["pass_rate"] = pr
        if test_cases is not None:
            payload["test_cases"] = len(test_cases) if isinstance(test_cases, list) else int(test_cases)
        if pass_count is not None:
            payload["pass_count"] = int(pass_count)
        if model:
            payload["model"] = str(model)
    else:
        # Manual stats
        if getattr(args, "pass_rate", None) is not None:
            payload["pass_rate"] = float(args.pass_rate)
        if getattr(args, "test_cases", None) is not None:
            payload["test_cases"] = int(args.test_cases)
        if getattr(args, "pass_count", None) is not None:
            payload["pass_count"] = int(args.pass_count)
        if getattr(args, "model", None):
            payload["model"] = args.model

    if not payload:
        print("Error: Provide --eval-json or at least --pass-rate.", file=sys.stderr)
        sys.exit(1)

    print(f"Uploading eval results for {bold(f'@{namespace}/{name}')} v{version}...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])
    try:
        result = client._request(
            "POST",
            f"/v1/skills/@{namespace}/{name}/versions/{version}/eval",
            body=json.dumps(payload).encode(),
            content_type="application/json",
        )
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    data = result.get("data", {}) if isinstance(result, dict) else {}
    pass_rate_out = data.get("pass_rate")
    test_cases_out = data.get("test_cases")

    if pass_rate_out is not None:
        rate_str = f"{pass_rate_out:.1f}%"
        tier_note = f" {green('✅ Tested tier achieved!')} (≥80% pass rate, ≥5 test cases)" if pass_rate_out >= 80 and (test_cases_out or 0) >= 5 else ""
        print(f"  {green('✓')} Eval uploaded — pass rate: {bold(rate_str)}{tier_note}")
    else:
        print(f"  {green('✓')} Eval uploaded")

    # Show regression warning if applicable
    regression = data.get("regression", {})
    if regression.get("is_regression"):
        prev_ver = regression.get("previous_version", "?")
        prev_rate = regression.get("previous_pass_rate")
        curr_rate = regression.get("current_pass_rate")
        delta = regression.get("delta")
        delta_str = f"{abs(delta):.1f}%" if delta is not None else "?"
        print()
        print(f"  {yellow('⚠ Regression detected:')} pass rate dropped {delta_str} from v{prev_ver}")
        if prev_rate is not None and curr_rate is not None:
            print(f"    {prev_ver}: {prev_rate:.1f}% → {version}: {curr_rate:.1f}%")
        print(f"    Run `skillsafe eval @{namespace}/{name} --version {prev_ver}` to compare")


def cmd_benchmark(args: argparse.Namespace) -> None:
    """Upload benchmark results for a skill version to SkillSafe."""
    cfg = require_config()
    namespace, name = parse_skill_ref(args.skill)
    version: str = args.version

    payload: Dict[str, Any] = {
        "benchmark_runs": int(args.runs),
    }
    if getattr(args, "avg_time", None) is not None:
        payload["avg_time_s"] = float(args.avg_time)
    if getattr(args, "avg_tokens", None) is not None:
        payload["avg_tokens"] = int(args.avg_tokens)
    if getattr(args, "variance", None) is not None:
        payload["variance"] = float(args.variance)

    print(f"Uploading benchmark for {bold(f'@{namespace}/{name}')} v{version} ({args.runs} runs)...\n")

    client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])
    try:
        result = client._request(
            "POST",
            f"/v1/skills/@{namespace}/{name}/versions/{version}/eval",
            body=json.dumps(payload).encode(),
            content_type="application/json",
        )
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)
    except (urllib.error.URLError, OSError) as e:
        print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
        sys.exit(1)

    data = result.get("data", {}) if isinstance(result, dict) else {}
    avg_t = data.get("avg_time_s")
    avg_tok = data.get("avg_tokens")
    runs = data.get("benchmark_runs") or args.runs

    parts = [f"{runs} runs"]
    if avg_t is not None:
        parts.append(f"avg {avg_t:.1f}s")
    if avg_tok is not None:
        parts.append(f"{avg_tok:,} tokens/run")
    print(f"  {green('✓')} Benchmark uploaded — {', '.join(parts)}")


def cmd_claim(args: argparse.Namespace) -> None:
    """Claim a skill from another registry (ClawHub, GitHub) on SkillSafe."""
    cfg = require_config()

    source: str = args.source.strip()

    # GitHub claim via import-github
    if source.startswith("github.com/") or source.startswith("https://github.com/"):
        raw_url = source if source.startswith("https://") else f"https://{source}"
        print(f"Claiming GitHub skill {bold(raw_url)} on SkillSafe...\n")
        client = SkillSafeClient(api_base=getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE), api_key=cfg["api_key"])
        try:
            result = client._request(
                "POST",
                "/v1/skills/import-github",
                body=json.dumps({"github_url": raw_url}).encode(),
                content_type="application/json",
            )
        except SkillSafeError as e:
            print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)
        except (urllib.error.URLError, OSError) as e:
            print(f"  Error: Could not connect to the API. {e}", file=sys.stderr)
            sys.exit(1)

        data = result.get("data", {}) if isinstance(result, dict) else {}
        ns = data.get("namespace", "").lstrip("@")
        nm = data.get("name", "")
        created = data.get("created", False)

        if created:
            print(f"  {green('✓')} Imported as {bold(f'@{ns}/{nm}')}")
        else:
            print(f"  {bold(f'@{ns}/{nm}')} already exists — refreshed metadata from GitHub")
        if ns and nm:
            print(f"\n  View at: https://skillsafe.ai/skill/@{ns}/{nm}")
            print(f"\n  {bold('Note:')} Importing does not prove ownership. To claim this")
            print(f"  namespace as a verified publisher, visit your account settings.")
            print(f"\n  {bold('Next steps:')}")
            print(f"    skillsafe scan <local-path>           — scan skill files")
            print(f"    skillsafe save <local-path>           — save a version")
            print(f"    skillsafe eval @{ns}/{nm} --version 1.0.0 --eval-json eval.json")

    # ClawHub migration instructions
    elif source.startswith("clawhub:") or source.startswith("clawhub.ai/") or source.startswith("clawhub.dev/"):
        ref = source.replace("clawhub:", "").replace("clawhub.ai/", "").replace("clawhub.dev/", "")
        print(f"Claiming ClawHub skill {bold(ref)} on SkillSafe...\n")
        print(f"  {yellow('ClawHub migration steps:')}")
        print(f"  1. Clone or download the skill from ClawHub: {bold(f'clawhub.ai/{ref}')}")
        print(f"  2. Run `skillsafe scan <local-path>` to verify it is safe")
        print(f"  3. Run `skillsafe save <local-path>` to save it to your account")
        print(f"  4. Run `skillsafe share @<ns>/<name>` to publish")
        print(f"\n  {bold('Tip:')} Add a GitHub repo URL to auto-sync releases:")
        print(f"    skillsafe claim github.com/owner/repo")

    else:
        print(f"Error: Unsupported source '{source}'.", file=sys.stderr)
        print("  Supported: github.com/owner/repo, clawhub.ai/owner/skill, clawhub:owner/skill", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Agent subcommand
# ---------------------------------------------------------------------------

_AGENT_SNAPSHOT_SKIP_EXTENSIONS = {".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe", ".bin"}
_AGENT_SNAPSHOT_MAX_FILE_SIZE = 512 * 1024  # 512 KB per file
_AGENT_SNAPSHOT_MAX_TOTAL_SIZE = 5 * 1024 * 1024  # 5 MB total for config snapshots
_AGENT_IDENTITY_FILE = ".skillsafe-agent.json"
_VALID_AGENT_PLATFORMS = ["claude", "cursor", "windsurf", "openclaw", "cline"]

# Config files captured at the root of a tool config directory (e.g. ~/.claude)
_AGENT_CONFIG_ROOT_FILES = {
    "CLAUDE.md", "GEMINI.md", "AGENTS.md",                  # project instructions
    "settings.json", "settings.local.json",                  # Claude Code settings
    "keybindings.json",                                      # keybindings
}
# Subdirectories to recurse into for config+memory snapshot (everything else skipped)
_AGENT_CONFIG_SUBDIRS = {"memory"}

# Skills subdirectory names used by each platform
_PLATFORM_SKILLS_SUBDIRS: Dict[str, str] = {
    "claude":    "skills",
    "cursor":    "skills",
    "windsurf":  "skills",
    "openclaw":  "skills",
    "cline":     "skills",
}


def _collect_config_files(root: Path) -> List[Tuple[str, bytes]]:
    """Collect config and memory files from a tool config directory.

    Captures:
    - Root-level config files (CLAUDE.md, settings.json, keybindings.json, etc.)
    - memory/ subdirectory (recursive)

    Intentionally excludes skills/, projects/, plugins/, history.jsonl, and
    any other runtime data — those are large and not meaningful as config.
    """
    collected: List[Tuple[str, bytes]] = []
    total_size = 0

    def _add_file(full: Path, rel: str) -> bool:
        nonlocal total_size
        try:
            size = full.stat().st_size
        except OSError:
            return True  # continue
        if size > _AGENT_SNAPSHOT_MAX_FILE_SIZE:
            print(f"  {dim(f'Skipping {rel} (too large: {size // 1024} KB)')}")
            return True
        try:
            content = full.read_bytes()
            content.decode("utf-8")  # reject binaries
        except (OSError, UnicodeDecodeError):
            return True
        total_size += size
        if total_size > _AGENT_SNAPSHOT_MAX_TOTAL_SIZE:
            print(f"  {yellow('Warning: config snapshot exceeds 5 MB limit — stopping.')}")
            return False  # stop
        collected.append((rel, content))
        return True

    # Root-level config files
    for fname in sorted(os.listdir(root)):
        if fname not in _AGENT_CONFIG_ROOT_FILES:
            continue
        full = root / fname
        if full.is_file():
            if not _add_file(full, fname):
                return collected

    # Allowed subdirectories (memory/, etc.)
    for subdir_name in sorted(_AGENT_CONFIG_SUBDIRS):
        subdir = root / subdir_name
        if not subdir.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(subdir):
            dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
            for fname in sorted(filenames):
                if fname.startswith(".") or any(fname.endswith(e) for e in _AGENT_SNAPSHOT_SKIP_EXTENSIONS):
                    continue
                full = Path(dirpath) / fname
                rel = str(full.relative_to(root))
                if not _add_file(full, rel):
                    return collected

    return collected


def _build_skills_manifest(root: Path, platform: str) -> Optional[bytes]:
    """Scan the skills directory and build a skills-manifest.json.

    Each entry captures the registry coordinates from the central install index
    or from the SKILL.md frontmatter registry field.  Skills without registry info
    are listed as 'local' source so the user knows they need to publish them.

    Returns JSON bytes, or None if no skills directory found.
    """
    skills_subdir = _PLATFORM_SKILLS_SUBDIRS.get(platform, "skills")
    skills_dir = root / skills_subdir
    if not skills_dir.is_dir():
        return None

    entries: List[Dict[str, Any]] = []
    index = _read_install_index()

    for item in sorted(skills_dir.iterdir()):
        if not item.is_dir():
            continue
        skill_name = item.name

        # Read from central install index
        registry_ref: Optional[str] = None
        version: Optional[str] = None
        tree_hash: Optional[str] = None
        share_link: Optional[str] = None

        meta = index.get(str(item))
        if meta:
            namespace = (meta.get("namespace") or "").lstrip("@")
            name = meta.get("name") or skill_name
            version = meta.get("version")
            tree_hash = meta.get("tree_hash")
            if namespace and name:
                registry_ref = f"@{namespace}/{name}"

        # Fallback: read registry field from SKILL.md frontmatter
        if not registry_ref:
            skill_md = item / "SKILL.md"
            if skill_md.exists():
                try:
                    text = skill_md.read_text(errors="replace")
                    m = re.search(r'^registry:\s*["\']?(@[\w/-]+)["\']?\s*$', text, re.MULTILINE)
                    if m:
                        registry_ref = m.group(1)
                    if not version:
                        mv = re.search(r'^version:\s*["\']?([0-9]+\.[0-9]+\.[0-9][^\s"\']*)["\']?\s*$', text, re.MULTILINE)
                        if mv:
                            version = mv.group(1)
                except OSError:
                    pass

        entry: Dict[str, Any] = {"name": skill_name, "source": "registry" if registry_ref else "local"}
        if registry_ref:
            entry["registry"] = registry_ref
        if version:
            entry["version"] = version
        if tree_hash:
            entry["tree_hash"] = tree_hash
        if share_link:
            entry["share_link"] = share_link
        entries.append(entry)

    if not entries:
        return None

    manifest = {
        "generated_at": __import__("datetime").datetime.utcnow().isoformat() + "Z",
        "skills": entries,
    }
    return json.dumps(manifest, indent=2).encode("utf-8")


def cmd_agent(args: argparse.Namespace) -> None:
    """Dispatch agent subcommands: save, list, snapshots."""
    action = getattr(args, "agent_action", None)

    if action == "save":
        _cmd_agent_save(args)
    elif action == "list":
        _cmd_agent_list(args)
    elif action == "snapshots":
        _cmd_agent_snapshots(args)
    else:
        # Print agent help
        print("Usage: skillsafe agent <subcommand> [options]\n")
        print("Subcommands:")
        print("  save [path]            Save config + memory snapshot (skills referenced by registry link)")
        print("  list                   List your agent identities")
        print("  snapshots <agent-id>   List snapshots for an agent")
        print("\nExamples:")
        print("  skillsafe agent save ~/.claude --name my-agent --platform claude")
        print("  skillsafe agent save ~/.claude --agent-id agt_abc123 --tag v1.2")
        print("  skillsafe agent save ~/.claude                    # re-snapshot (reads .skillsafe-agent.json)")
        print("  skillsafe agent list")
        print("  skillsafe agent snapshots agt_abc123")
        sys.exit(0)


def _cmd_agent_save(args: argparse.Namespace) -> None:
    """Save a snapshot of agent files to the registry."""
    cfg = require_config()
    path = Path(getattr(args, "path", ".")).resolve()

    if not path.is_dir():
        print(f"Error: {path} is not a directory.", file=sys.stderr)
        sys.exit(1)

    api_base = getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE)
    client = SkillSafeClient(api_base=api_base, api_key=cfg["api_key"])

    # Resolve agent ID: CLI flag > identity file > create new
    agent_id: Optional[str] = getattr(args, "agent_id", None)
    identity_file = path / _AGENT_IDENTITY_FILE

    if not agent_id and identity_file.exists():
        try:
            identity = json.loads(identity_file.read_text())
            agent_id = identity.get("agent_id")
            if agent_id:
                print(f"  Using agent {bold(agent_id)} (from {_AGENT_IDENTITY_FILE})")
        except (json.JSONDecodeError, OSError):
            pass

    if not agent_id:
        # Need to create a new agent
        name = getattr(args, "name", None)
        platform = getattr(args, "platform", None)

        if not name or not platform:
            print(f"Error: No agent identity found. Provide --name and --platform to create one.", file=sys.stderr)
            print(f"  Valid platforms: {', '.join(_VALID_AGENT_PLATFORMS)}", file=sys.stderr)
            print(f"  Example: skillsafe agent save . --name my-agent --platform claude", file=sys.stderr)
            sys.exit(1)

        if platform not in _VALID_AGENT_PLATFORMS:
            print(f"Error: Invalid platform '{platform}'. Valid: {', '.join(_VALID_AGENT_PLATFORMS)}", file=sys.stderr)
            sys.exit(1)

        print(f"Creating agent {bold(name)} ({platform})...")
        try:
            description = getattr(args, "description", None)
            agent = client.create_agent(name, platform, description)
            agent_id = agent.get("id") or agent.get("agent_id")
            if not agent_id:
                print("Error: Server did not return an agent ID.", file=sys.stderr)
                sys.exit(1)
            print(f"  {green('✓')} Created agent {bold(agent_id)}")

            # Persist agent ID to identity file
            try:
                identity_data = {"agent_id": agent_id, "name": name, "platform": platform}
                identity_file.write_text(json.dumps(identity_data, indent=2) + "\n")
                print(f"  Saved identity to {_AGENT_IDENTITY_FILE}")
            except OSError as e:
                print(f"  {yellow(f'Warning: could not write {_AGENT_IDENTITY_FILE}: {e}')}")

        except SkillSafeError as e:
            print(f"  Error: {e.message}", file=sys.stderr)
            sys.exit(1)

    # Collect config + memory files
    platform = getattr(args, "platform", None) or "claude"
    # If agent was loaded from identity file, recover platform from it
    if identity_file.exists() and not getattr(args, "platform", None):
        try:
            identity = json.loads(identity_file.read_text())
            platform = identity.get("platform", "claude")
        except (json.JSONDecodeError, OSError):
            pass

    print(f"\nCollecting config and memory files from {dim(str(path))}...")
    files = _collect_config_files(path)

    # Build skills manifest and append as a virtual file
    skills_manifest_bytes = _build_skills_manifest(path, platform)
    if skills_manifest_bytes:
        files.append(("skills-manifest.json", skills_manifest_bytes))
        skill_count = len(json.loads(skills_manifest_bytes).get("skills", []))
        print(f"  Skills manifest: {skill_count} skill(s) referenced by registry link")

    if not files:
        print("Error: No config files found. Is this a tool config directory (e.g. ~/.claude)?", file=sys.stderr)
        sys.exit(1)

    total_kb = sum(len(c) for _, c in files) / 1024
    print(f"  Files: {len(files)}, total size: {total_kb:.1f} KB")

    # Upload snapshot
    version_tag = getattr(args, "tag", None)
    description = getattr(args, "description", None)
    tag_label = f" [{version_tag}]" if version_tag else ""
    print(f"\nSaving snapshot{tag_label} to agent {bold(agent_id)}...")

    try:
        snapshot = client.save_agent_snapshot(agent_id, files, version_tag=version_tag, description=description)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    snap_id = snapshot.get("id") or snapshot.get("snapshot_id", "")
    snap_at = snapshot.get("snapshot_at", "")
    file_count = snapshot.get("file_count", len(files))
    total_size = snapshot.get("total_size", 0)

    print(f"\n  {green('✓')} Snapshot saved")
    if snap_id:
        print(f"  ID:        {bold(snap_id)}")
    if version_tag:
        print(f"  Tag:       {version_tag}")
    if snap_at:
        print(f"  Saved at:  {snap_at}")
    print(f"  Files:     {file_count}  ({int(total_size) / 1024:.1f} KB)")


def _cmd_agent_list(args: argparse.Namespace) -> None:
    """List all agent identities."""
    cfg = require_config()
    api_base = getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE)
    client = SkillSafeClient(api_base=api_base, api_key=cfg["api_key"])

    print("Fetching agents...")
    try:
        agents = client.list_agents()
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    if not agents:
        print("  No agents found.")
        print(f"\n  Create one: skillsafe agent save . --name my-agent --platform claude")
        return

    print(f"\n  {'ID':<20}  {'Name':<24}  {'Platform':<12}  Created")
    print(f"  {'─' * 20}  {'─' * 24}  {'─' * 12}  {'─' * 20}")
    for a in agents:
        aid = (a.get("id") or a.get("agent_id") or "")[:20]
        name = (a.get("name") or "")[:24]
        platform = (a.get("platform") or "")[:12]
        created = (a.get("created_at") or "")[:20]
        print(f"  {aid:<20}  {name:<24}  {platform:<12}  {created}")


def _cmd_agent_snapshots(args: argparse.Namespace) -> None:
    """List snapshots for an agent."""
    cfg = require_config()
    agent_id: str = args.agent_id
    api_base = getattr(args, "api_base", None) or cfg.get("api_base", DEFAULT_API_BASE)
    client = SkillSafeClient(api_base=api_base, api_key=cfg["api_key"])

    limit = getattr(args, "limit", 20)
    print(f"Fetching snapshots for {bold(agent_id)}...")
    try:
        snapshots = client.list_agent_snapshots(agent_id, limit=limit)
    except SkillSafeError as e:
        print(f"  Error: {e.message}", file=sys.stderr)
        sys.exit(1)

    if not snapshots:
        print("  No snapshots found.")
        print(f"\n  Save one: skillsafe agent save . --agent-id {agent_id}")
        return

    print(f"\n  {'Snapshot ID':<26}  {'Tag':<16}  {'Files':>5}  {'Size':>8}  Saved at")
    print(f"  {'─' * 26}  {'─' * 16}  {'─' * 5}  {'─' * 8}  {'─' * 20}")
    for s in snapshots:
        sid = (s.get("id") or s.get("snapshot_id") or "")[:26]
        tag = (s.get("version_tag") or "")[:16]
        fcount = int(s.get("file_count") or 0)
        size_kb = int(s.get("total_size") or 0) / 1024
        saved = (s.get("snapshot_at") or "")[:20]
        print(f"  {sid:<26}  {tag:<16}  {fcount:>5}  {size_kb:>7.1f}K  {saved}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_skills_base_from_script() -> Optional[Path]:
    """Auto-detect the skills base directory from the script's own location.

    If skillsafe.py is installed as a skill (e.g. at
    ``<project>/.agents/skills/skillsafe/scripts/skillsafe.py`` or
    ``<project>/.claude/skills/skillsafe/scripts/skillsafe.py``), return the
    parent ``skills/`` directory so sibling skills are installed alongside it.

    Returns None if the script isn't inside a recognizable skills directory.
    """
    try:
        script_path = Path(__file__).resolve()
        # Expected: <base>/skills/<skillname>/scripts/skillsafe.py
        #   parts[-1] = skillsafe.py
        #   parts[-2] = scripts
        #   parts[-3] = skillsafe (or any skill name)
        #   parts[-4] = skills (the directory we want to return as parent)
        parts = script_path.parts
        if len(parts) >= 5 and parts[-2] == "scripts" and parts[-4] == "skills":
            candidate = script_path.parent.parent.parent  # -> skills/
            if candidate.is_dir():
                return candidate
    except (ValueError, IndexError, OSError):
        pass
    return None


def _should_use_canonical_mode(args: argparse.Namespace) -> bool:
    """Return True when install should use the canonical .agents/skills/ directory with symlinks."""
    if getattr(args, "skills_dir", None):
        return False
    if getattr(args, "tool", None):
        return False
    location = getattr(args, "location", None) or "project"
    return location == "project"


# Agent config directories to detect (relative to project root).
# Maps tool_key → (config_dir_to_detect, project_skills_subdir).
# "codex" is excluded because .agents/skills IS the canonical dir.
_AGENT_DETECT_MAP: Dict[str, Tuple[str, str]] = {
    "claude":      (".claude",                  ".claude/skills"),
    "cursor":      (".cursor",                  ".cursor/skills"),
    "windsurf":    (".windsurf",                ".windsurf/skills"),
    "gemini":      (".gemini",                  ".gemini/skills"),
    "cline":       (".cline",                   ".cline/skills"),
    "roo":         (".roo",                     ".roo/skills"),
    "goose":       (".goose",                   ".goose/skills"),
    "copilot":     (".github/copilot",          ".github/copilot/skills"),
    "kiro":        (".kiro",                    ".kiro/skills"),
    "trae":        (".trae",                    ".trae/skills"),
    "amp":         (".amp",                     ".amp/skills"),
    "aider":       (".aider",                   ".aider/skills"),
    "antigravity": (".gemini/antigravity",      ".agent/skills"),
    "droid":       (".factory",                 ".factory/skills"),
    "kilo":        (".kilocode",                ".kilocode/skills"),
}


def _detect_agent_dirs(root: Path) -> List[Tuple[str, Path]]:
    """Scan root for known agent config directories.

    Returns list of (tool_name, project_skills_path) for agents whose config dir exists.
    """
    found: List[Tuple[str, Path]] = []
    for tool_key, (config_dir, skills_subdir) in _AGENT_DETECT_MAP.items():
        config_path = root / config_dir
        if config_path.is_dir():
            found.append((tool_key, root / skills_subdir))
    return found


def _create_agent_symlinks(
    canonical_dir: Path,
    skill_name: str,
    root: Path,
) -> List[Tuple[str, Path]]:
    """Create relative symlinks from each detected agent's skills dir to the canonical dir.

    Returns list of (tool_name, symlink_path) for successfully created symlinks.
    """
    agents = _detect_agent_dirs(root)
    created: List[Tuple[str, Path]] = []
    for tool_key, skills_path in agents:
        link_path = skills_path / skill_name
        target = canonical_dir / skill_name

        # Real directory exists — skip, don't modify other agents' directories
        if link_path.exists() and not link_path.is_symlink():
            label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
            print(f"    {label}: skipped (existing install at {link_path})")
            print(f"      To update: skillsafe install @<ns>/<name> --tool {tool_key}")
            continue

        try:
            skills_path.mkdir(parents=True, exist_ok=True)
            # Compute relative path for portability
            rel_target = os.path.relpath(target, link_path.parent)

            # Remove existing symlink to update it
            if link_path.is_symlink():
                link_path.unlink()

            link_path.symlink_to(rel_target)
            created.append((tool_key, link_path))
        except OSError as e:
            label = TOOL_DISPLAY_NAMES.get(tool_key, tool_key)
            if sys.platform == "win32":
                # Copy instead of symlink on Windows (symlinks require Developer Mode)
                try:
                    shutil.copytree(target, link_path, symlinks=False)
                    created.append((tool_key, link_path))
                except OSError as copy_err:
                    print(f"    {label}: copy failed ({copy_err})")
            else:
                print(f"    {label}: symlink failed ({e})")

    return created


def _resolve_skills_dir(args: argparse.Namespace) -> Optional[Path]:
    """
    Resolve the target skills directory from CLI flags.

    --skills-dir <path>                        → use that path directly (overrides everything)
    --tool <name> --location global            → tool's global skills dir (e.g. ~/.claude/skills/)
    --tool <name> --location project (default) → tool's project subdir in cwd (e.g. .claude/skills/)
    (no --tool)   --location project (default) → Path.cwd()
    """
    skills_dir = getattr(args, "skills_dir", None)
    if skills_dir:
        return Path(skills_dir).expanduser().resolve()
    location = getattr(args, "location", None) or "project"
    tool = getattr(args, "tool", None)
    if tool and tool not in TOOL_SKILLS_DIRS:
        print(f"Error: Unknown tool '{tool}'. Supported tools: {', '.join(TOOL_SKILLS_DIRS.keys())}", file=sys.stderr)
        sys.exit(1)
    if location == "global":
        if not tool:
            print("Error: --location global requires --tool <name>", file=sys.stderr)
            sys.exit(1)
        return TOOL_SKILLS_DIRS[tool]
    # project (default)
    if tool:
        subdir = TOOL_PROJECT_SKILLS_SUBDIRS.get(tool, f".{tool}/skills")
        return Path.cwd() / subdir
    return Path.cwd()


def _grade_color(grade: str) -> str:
    """Return a colored grade string."""
    if grade in ("A+", "A"):
        return green(grade)
    if grade == "B":
        return cyan(grade)
    if grade == "C":
        return yellow(grade)
    return red(grade)


def _print_scan_results(report: Dict[str, Any], indent: int = 0, publisher_verified: bool = False, skill_ref: str = "") -> None:
    """Pretty-print scan results.

    When *publisher_verified* is True, output is compact: a Verified Publisher
    tag (with optional skill_ref handle) and only critical threats listed.
    When False (default), the full verbose output is shown with an unverified
    warning when threats are present.
    """
    prefix = " " * indent
    findings = report.get("findings_summary", [])
    score = report.get("score")
    grade = report.get("grade")
    threat_count = report.get("findings_count", len(findings))
    advisory_count = report.get("advisory_count", 0)

    # --- Verified publisher: compact output ---
    if publisher_verified:
        label = green('Verified Publisher')
        if skill_ref:
            label = f"{bold(skill_ref)} — {label}"
        print(f"{prefix}{label}")
        if report.get("clean", True) and not findings:
            return
        # Only list critical threats for verified publishers
        critical_threats = [f for f in findings if f.get("classification", "threat") == "threat" and f.get("severity") == "critical"]
        if critical_threats:
            print(f"{prefix}{yellow(f'{len(critical_threats)} critical finding(s)')}")
            for f in critical_threats:
                loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
                print(f"{prefix}  {format_severity('critical')} {loc:<35} {f.get('message', '')}")
        elif threat_count > 0:
            print(f"{prefix}{dim(f'{threat_count} non-critical finding(s)')}")
        return

    # --- Unverified publisher: full verbose output ---
    if score is not None and grade is not None:
        grade_str = _grade_color(grade)
        score_label = green(str(score)) if score >= 80 else (yellow(str(score)) if score >= 60 else red(str(score)))
        print(f"{prefix}Score: {score_label}/100  Grade: {grade_str}\n")

    if report.get("clean", True) and not findings:
        print(f"{prefix}{green('No security issues found.')}")
        return

    total = threat_count + advisory_count
    summary = f"Found {total} issue(s) ({threat_count} threat(s), {advisory_count} advisory(ies))"
    print(f"{prefix}{yellow(summary)}\n")

    for f in findings:
        classification = f.get("classification", "threat")
        loc = f"{f.get('file', '?')}:{f.get('line', '?')}"
        msg = f.get("message", "")
        if classification == "advisory":
            sev_label = dim("ADVISORY".ljust(8))
            print(f"{prefix}  {sev_label} {loc:<35} {dim(msg)}")
        else:
            sev = format_severity(f.get("severity", "info"))
            print(f"{prefix}  {sev} {loc:<35} {msg}")
        ctx = f.get("context", "")
        if ctx:
            print(f"{prefix}           {dim(ctx[:100])}")

    if threat_count > 0:
        print(f"\n{prefix}{yellow('Review findings carefully — this skill is from an unverified publisher.')}")




# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="skillsafe",
        description="SkillSafe — secured skill registry client for AI coding tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              skillsafe auth                              # browser login
              skillsafe scan ./my-skill
              skillsafe save ./my-skill --version 1.0.0
              skillsafe share @alice/my-skill --version 1.0.0
              skillsafe share @alice/my-skill --version 1.0.0 --public
              skillsafe install @alice/my-skill                                    # .agents/skills/ + symlinks (default)
              skillsafe install @alice/my-skill --no-symlink                     # .agents/skills/ only, no symlinks
              skillsafe install @alice/my-skill --tool claude                     # .claude/skills/ in current project
              skillsafe install @alice/my-skill --tool claude --location global   # global ~/.claude/skills/
              skillsafe install @alice/my-skill --tool cursor --location global   # global ~/.cursor/skills/
              skillsafe install @alice/my-skill --tool windsurf --location global # global ~/.windsurf/skills/
              skillsafe install @alice/my-skill --tool codex --location global    # global ~/.agents/skills/
              skillsafe install @alice/my-skill --tool gemini --location global   # global ~/.gemini/skills/
              skillsafe install @alice/my-skill --tool opencode --location global # global ~/.config/opencode/skills/
              skillsafe install @alice/my-skill --skills-dir ~/custom/skills
              skillsafe search "salesforce automation"
              skillsafe info @alice/my-skill
              skillsafe list
              skillsafe update                             # update CLI to latest version
              skillsafe whoami                             # check auth status
              skillsafe demo-from-session ~/.claude/projects/.../session.jsonl @alice/my-skill --version 1.0.0 --title "Installing a skill"
              skillsafe demo-from-session session.jsonl --title "Preview" --no-upload
              skillsafe demo-from-session session.jsonl @alice/my-skill --version 1.0.0 --title "Skill demo" --filter-keyword skillsafe
              skillsafe agent save ~/.claude --name my-agent --platform claude  # create agent + snapshot config
              skillsafe agent save ~/.claude                       # re-snapshot (reads .skillsafe-agent.json)
              skillsafe agent list                                 # list all agent identities
              skillsafe agent snapshots agt_abc123                 # list snapshots for an agent
        """),
    )
    parser.add_argument("--api-base", default=None, help="API base URL (default: %(default)s)")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # -- auth ---------------------------------------------------------------
    p_auth = subparsers.add_parser("auth", help="Authenticate via browser login")

    # -- scan ---------------------------------------------------------------
    p_scan = subparsers.add_parser("scan", help="Scan a skill directory for security issues")
    p_scan.add_argument("path", help="Path to the skill directory")
    p_scan.add_argument("-o", "--output", help="Write JSON report to file")
    p_scan.add_argument("--check", action="store_true", help="Exit with code 1 if any HIGH or CRITICAL findings exist (CI mode)")
    p_scan.add_argument("--ignore", metavar="RULES", help="Comma-separated rule IDs to suppress (e.g. git_hook_persist,unpinned_npm)")

    # -- bom ----------------------------------------------------------------
    p_bom = subparsers.add_parser("bom", help="Generate Bill of Materials for a skill directory")
    p_bom.add_argument("path", help="Path to the skill directory")
    p_bom.add_argument("-o", "--output", help="Write BOM JSON to file")

    # -- save ---------------------------------------------------------------
    p_save = subparsers.add_parser("save", help="Save a skill to the registry (private by default)")
    p_save.add_argument("path", help="Path to the skill directory")
    p_save.add_argument("--version", help="Semantic version (e.g. 1.0.0). Omit to auto-increment patch.")
    p_save.add_argument("--description", help="Skill description")
    p_save.add_argument("--category", help="Skill category")
    p_save.add_argument("--tags", help="Comma-separated tags")
    p_save.add_argument("--changelog", help="What changed in this version")

    # -- share --------------------------------------------------------------
    p_share = subparsers.add_parser("share", help="Create a share link for a saved skill")
    p_share.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_share.add_argument("--version", required=True, help="Version to share (e.g. 1.0.0)")
    p_share.add_argument("--public", action="store_true", help="Make skill discoverable via search")
    p_share.add_argument("--expires", choices=["1d", "7d", "30d", "never"], help="Link expiration (default: never)")

    # -- install ------------------------------------------------------------
    p_install = subparsers.add_parser("install", help="Install or upgrade a skill from the registry")
    p_install.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_install.add_argument("--version", help="Specific version (default: latest)")
    p_install.add_argument("--upgrade", action="store_true", help="Upgrade to latest if already installed")
    p_install.add_argument("--tool", choices=list(TOOL_SKILLS_DIRS.keys()),
        help="Tool name — determines the skills subdirectory (claude, cursor, windsurf, codex, gemini, opencode, openclaw, cline, roo, goose, copilot, kiro, trae, amp, aider, vscode)")
    p_install.add_argument("--location", choices=["project", "global"], default="project",
        help="Install location: project = tool's subdir in current folder (default), global = tool's global skills dir")
    p_install.add_argument("--skills-dir", help="Override install path directly (ignores --tool and --location)")
    p_install.add_argument("--no-symlink", action="store_true", help="Install to .agents/skills/ without creating agent symlinks")

    # -- search -------------------------------------------------------------
    p_search = subparsers.add_parser("search", help="Search for skills")
    p_search.add_argument("query", nargs="?", help="Search query")
    p_search.add_argument("--category", help="Filter by category")
    p_search.add_argument("--sort", default="popular", choices=["popular", "recent", "verified", "trending", "hot", "relevance", "installs", "newest", "updated", "stars", "eval_score"], help="Sort order")
    p_search.add_argument("--limit", type=int, default=20, help="Max results per page (default: 20, max: 100)")
    p_search.add_argument("--page", type=int, default=None, help="Page number for pagination (default: 1)")
    p_search.add_argument("--all", action="store_true", help="Fetch all results across all pages")

    # -- info ---------------------------------------------------------------
    p_info = subparsers.add_parser("info", help="Get skill details")
    p_info.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")

    # -- list ---------------------------------------------------------------
    p_list = subparsers.add_parser("list", help="List locally installed skills")
    p_list.add_argument("--skills-dir", action="append", help="Additional skills directory to scan (can be repeated)")

    # -- yank ---------------------------------------------------------------
    p_yank = subparsers.add_parser("yank", help="Yank a version (blocks future downloads)")
    p_yank.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_yank.add_argument("--version", required=True, help="Version to yank (e.g. 1.0.0)")
    p_yank.add_argument("--reason", help="Reason for yanking (shown in version listings)")

    # -- demo ---------------------------------------------------------------
    p_demo = subparsers.add_parser("demo", help="Upload a demo JSON recording for a skill version",
        epilog='Demo JSON must have {"schema": "skillsafe-demo/1", "messages": [...]}. Each message: {"role": "user"|"assistant", "content": "..."}')
    p_demo.add_argument("json_file", help="Path to demo JSON file (requires schema: skillsafe-demo/1 and messages array)")
    p_demo.add_argument("skill", help="Skill reference (e.g. @alice/my-skill)")
    p_demo.add_argument("--version", required=True, help="Skill version (e.g. 1.0.0)")
    p_demo.add_argument("--title", help="Override title from JSON (max 200 chars)")

    # -- demo-from-session --------------------------------------------------
    p_dfs = subparsers.add_parser(
        "demo-from-session",
        help="Convert a Claude Code session JSONL to a SkillSafe demo and upload it",
    )
    p_dfs.add_argument("session", help="Path to Claude Code session JSONL file (~/.claude/projects/.../session.jsonl)")
    p_dfs.add_argument("skill", nargs="?", help="Skill reference (e.g. @alice/my-skill). Omit with --no-upload.")
    p_dfs.add_argument("--version", help="Skill version (e.g. 1.0.0). Required when uploading.")
    p_dfs.add_argument("--title", required=True, help="Demo title shown on skillsafe.ai (max 200 chars)")
    p_dfs.add_argument("--out", metavar="FILE", help="Save converted JSON to FILE instead of uploading")
    p_dfs.add_argument("--filter-keyword", metavar="WORD",
        help="Keep only messages that contain WORD (e.g. 'skillsafe' to focus the demo on skill usage)")
    p_dfs.add_argument("--max-output-lines", type=int, default=120, metavar="N",
        help="Truncate tool outputs longer than N lines (default: 120)")
    p_dfs.add_argument("--no-upload", action="store_true",
        help="Convert and save to a temp file without uploading")

    # -- whoami -------------------------------------------------------------
    p_whoami = subparsers.add_parser("whoami", help="Show current authentication status and account info")

    # -- upgrade ------------------------------------------------------------
    # -- update (self-update CLI or upgrade skills) --------------------------
    p_update = subparsers.add_parser(
        "update", aliases=["upgrade", "self-update"],
        help="Update skillsafe CLI or upgrade installed skills. "
             "'update' or 'update skillsafe' updates the CLI from skillsafe.ai; "
             "'update @ns/skill' upgrades a specific skill; "
             "'update --all' upgrades all installed skills."
    )
    p_update.add_argument("skill", nargs="?", default=None,
                          help="Skill to upgrade (e.g. @alice/my-skill), or 'skillsafe' to update the CLI (default)")
    p_update.add_argument("--all", action="store_true", help="Upgrade all installed skills")
    p_update.add_argument("--tool", choices=list(TOOL_SKILLS_DIRS.keys()), help="Limit --all to skills for a specific tool")
    p_update.add_argument("--dry-run", action="store_true", help="Show what would be upgraded without applying changes")

    p_import = subparsers.add_parser("import", help="Import a skill from a GitHub or ClawHub URL")
    p_import.add_argument("url", help="Skill URL (e.g. github.com/owner/repo or https://clawhub.ai/owner/skill)")

    p_lint = subparsers.add_parser("lint", help="Validate a skillsafe.yaml manifest")
    p_lint.add_argument("path", nargs="?", default=".", help="Path to skill directory (default: current directory)")

    p_eval = subparsers.add_parser("eval", help="Upload eval results for a skill version")
    p_eval.add_argument("skill", help="Skill reference (@namespace/name)")
    p_eval.add_argument("--version", required=True, help="Version to attach eval results to (e.g. 1.0.0)")
    p_eval.add_argument("--eval-json", metavar="FILE", help="Path to skill-creator eval JSON file")
    p_eval.add_argument("--pass-rate", type=float, metavar="RATE", help="Pass rate (0–100)")
    p_eval.add_argument("--test-cases", type=int, metavar="N", help="Total number of test cases")
    p_eval.add_argument("--pass-count", type=int, metavar="N", help="Number of passing test cases")
    p_eval.add_argument("--model", metavar="MODEL", help="Model used for evals (e.g. claude-opus-4-6)")

    p_benchmark = subparsers.add_parser("benchmark", help="Upload benchmark results for a skill version")
    p_benchmark.add_argument("skill", help="Skill reference (@namespace/name)")
    p_benchmark.add_argument("--version", required=True, help="Version to attach benchmark results to")
    p_benchmark.add_argument("--runs", type=int, required=True, help="Number of benchmark runs")
    p_benchmark.add_argument("--avg-time", type=float, metavar="SECONDS", help="Average execution time in seconds")
    p_benchmark.add_argument("--avg-tokens", type=int, metavar="N", help="Average tokens per run")
    p_benchmark.add_argument("--variance", type=float, help="Variance in execution time")

    p_claim = subparsers.add_parser("claim", help="Claim a skill from another registry (ClawHub, GitHub)")
    p_claim.add_argument("source", help="Source ref: github.com/owner/repo or clawhub:owner/skill")

    # -- agent --------------------------------------------------------------
    p_agent = subparsers.add_parser("agent", help="Manage AI agent identities and configuration snapshots")
    agent_subs = p_agent.add_subparsers(dest="agent_action")

    p_agent_save = agent_subs.add_parser("save", help="Save a snapshot of agent files to the registry")
    p_agent_save.add_argument("path", nargs="?", default=".", help="Directory to snapshot (default: current directory)")
    p_agent_save.add_argument("--agent-id", dest="agent_id", help="Agent ID (reads from .skillsafe-agent.json if omitted)")
    p_agent_save.add_argument("--name", help="Agent name — required when creating a new agent")
    p_agent_save.add_argument("--platform", choices=_VALID_AGENT_PLATFORMS, help="Agent platform — required when creating a new agent")
    p_agent_save.add_argument("--tag", metavar="VERSION_TAG", help="Optional version tag for this snapshot (e.g. v1.2)")
    p_agent_save.add_argument("--description", help="Optional description for this snapshot")

    p_agent_list = agent_subs.add_parser("list", help="List your agent identities")

    p_agent_snaps = agent_subs.add_parser("snapshots", help="List snapshots for an agent")
    p_agent_snaps.add_argument("agent_id", help="Agent ID (e.g. agt_abc123)")
    p_agent_snaps.add_argument("--limit", type=int, default=20, help="Max snapshots to show (default: 20)")

    args = parser.parse_args(argv)

    # Ensure api_base is set in the namespace (subcommand may not define it)
    if not getattr(args, "api_base", None):
        args.api_base = DEFAULT_API_BASE

    # Validate --api-base scheme early (allow http only for localhost/127.0.0.1)
    api_base_val = getattr(args, "api_base", DEFAULT_API_BASE) or DEFAULT_API_BASE
    if api_base_val and not api_base_val.startswith("https://"):
        parsed_base = urllib.parse.urlparse(api_base_val)
        if parsed_base.hostname not in ("localhost", "127.0.0.1"):
            print(f"Error: Refusing to use insecure HTTP API base: {api_base_val}. Use HTTPS.", file=sys.stderr)
            sys.exit(1)

    if args.command == "auth":
        cmd_auth(args)
    elif args.command == "scan":
        cmd_scan(args)
    elif args.command == "bom":
        cmd_bom(args)
    elif args.command == "save":
        cmd_save(args)
    elif args.command == "share":
        cmd_share(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "search":
        cmd_search(args)
    elif args.command == "info":
        cmd_info(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "yank":
        cmd_yank(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "demo-from-session":
        cmd_demo_from_session(args)
    elif args.command == "whoami":
        cmd_whoami(args)
    elif args.command in ("update", "self-update", "upgrade"):
        cmd_update(args)
    elif args.command == "import":
        cmd_import(args)
    elif args.command == "lint":
        cmd_lint(args)
    elif args.command == "eval":
        cmd_eval(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "claim":
        cmd_claim(args)
    elif args.command == "agent":
        cmd_agent(args)
    else:
        parser.print_help()
        sys.exit(1)

    # After any command that contacted the server, show update notice if available
    _print_update_notice()


if __name__ == "__main__":
    main()
