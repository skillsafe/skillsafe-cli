# SkillSafe CLI

The open-source Python CLI for [SkillSafe](https://skillsafe.ai) — the secured skill registry for AI coding tools. Scan, save, share, install, and verify AI skills with security scanning and dual-side cryptographic verification.

Works with **Claude Code**, **Cursor**, **Windsurf**, **Codex**, **Gemini CLI**, **OpenCode**, **Cline**, **Roo**, **Goose**, **Copilot**, **Kiro**, **Trae**, **AMP**, **Aider**, and more.

## Quick Start

No dependencies — uses only Python stdlib. Requires Python 3.8+.

```bash
# Install a public skill (no account required)
curl -fsSL https://skillsafe.ai/scripts/skillsafe.py | python3 - install @anthropics/pdf

# Or if you already have the CLI:
skillsafe install @anthropics/pdf

# Sign in to save and share your own skills
skillsafe auth
skillsafe scan ./my-skill
skillsafe save ./my-skill --version 1.0.0
skillsafe share @myname/my-skill --version 1.0.0
```

## Install

Tell your AI coding tool:

> Install skillsafe from https://skillsafe.ai/skill.md

Or manually:

```bash
mkdir -p <skill-dir>/scripts
curl -fsSL https://skillsafe.ai/scripts/skillsafe.py -o <skill-dir>/scripts/skillsafe.py
python3 <skill-dir>/scripts/skillsafe.py update
```

## Commands

### Authentication

| Command | Description |
|---------|-------------|
| `auth` | Sign in via browser. Saves API key to `~/.skillsafe/config.json` |
| `whoami` | Show current auth status, namespace, and masked API key |

### Scanning & Security

| Command | Description |
|---------|-------------|
| `scan <path>` | Run a 12-pass security scan (AST analysis, secrets, injection, structural mimicry, composite patterns, surplus functionality) |
| `scan <path> -o report.json` | Save scan report as JSON |
| `bom <path>` | Generate a Bill of Materials — inventory of files, APIs, capabilities |
| `bom <path> -o bom.json` | Save BOM as JSON |

### Publishing

| Command | Description |
|---------|-------------|
| `init [path]` | Initialize a `skillsafe.yaml` manifest in a skill directory |
| `lint [path]` | Validate a `skillsafe.yaml` manifest |
| `save <path> --version <ver>` | Save a skill privately to the registry |
| `share @ns/name --version <ver>` | Create a share link (requires email verification + scan report) |
| `share @ns/name --version <ver> --public` | Share with public visibility (discoverable via search) |
| `share @ns/name --version <ver> --expires 7d` | Share with expiration (`1d`, `7d`, `30d`, `never`) |
| `yank @ns/name --version <ver>` | Yank a version — blocks future downloads |

### Installing

| Command | Description |
|---------|-------------|
| `install @ns/name` | Install to `.agents/skills/` and auto-symlink to detected agents |
| `install @ns/name --version <ver>` | Install a specific version |
| `install @ns/name --tool claude` | Install directly into `.claude/skills/` |
| `install @ns/name --tool cursor --location global` | Install to a tool's global skills directory |
| `install @ns/name --skills-dir ./custom` | Install to a custom directory |
| `install @ns/name --no-symlink` | Install to `.agents/skills/` without creating symlinks |
| `install <share-link>` | Install via a `shr_` share link or URL |

No account required for public skills. Authenticated installs enable dual-side verification.

### Discovery

| Command | Description |
|---------|-------------|
| `search <query>` | Search public skills |
| `search <query> --sort trending` | Sort by `popular`, `recent`, `verified`, `trending`, `hot` |
| `search --category "code review"` | Filter by category |
| `info @ns/name` | Show skill details, versions, and verification status |
| `list` | List all locally installed skills across all agent directories |

### Updating

| Command | Description |
|---------|-------------|
| `update` | Self-update the CLI from skillsafe.ai |
| `update @ns/name` | Upgrade a specific installed skill to the latest version |
| `update --all` | Upgrade all installed skills |
| `update --all --tool claude` | Upgrade all skills for a specific tool |
| `update --all --dry-run` | Preview upgrades without applying |

### Demos

| Command | Description |
|---------|-------------|
| `demo <json> @ns/name --version <ver> --title "My demo"` | Upload a demo recording |
| `demo-from-session <session.jsonl> @ns/name --version <ver> --title "Title"` | Convert a Claude Code session to a demo and upload |
| `demo-from-session <session.jsonl> --title "Title" --no-upload` | Convert without uploading |

### Evals & Benchmarks

| Command | Description |
|---------|-------------|
| `eval @ns/name --version <ver> --eval-json results.json` | Upload eval results |
| `eval @ns/name --version <ver> --pass-rate 95 --test-cases 20` | Upload eval metrics directly |
| `benchmark @ns/name --version <ver> --runs 10 --avg-time 2.5` | Upload benchmark results |

### Vault (Backup & Restore)

| Command | Description |
|---------|-------------|
| `backup <path>` | Back up a skill directory to the encrypted vault |
| `restore @ns/name` | Restore a skill from the vault |
| `restore @ns/name --tool claude --location global` | Restore to a specific tool directory |

### Import & Claim

| Command | Description |
|---------|-------------|
| `import <url>` | Import a skill from a GitHub or ClawHub URL |
| `claim github.com/owner/repo` | Claim a GitHub repo as your skill on SkillSafe |

## Security Model

SkillSafe uses **dual-side verification**:

1. Publisher scans before sharing
2. Consumer re-scans after download
3. Server compares both reports

Tree hashes (SHA-256 of archive content) detect tampering. Verdicts: `verified`, `divergent`, `critical`.

The scanner runs 12 analysis passes including AST parsing, regex pattern matching, credential detection, prompt injection analysis, and composite behavioral patterns.

## File Structure

```
SKILL.md                   # Skill definition (source of truth)
scripts/skillsafe.py       # CLI client (stdlib only, single file)
submit-skill-demo.md       # Instructions for AI-assisted demo recording
submit-demo-comment.md     # Instructions for AI-assisted demo commenting
tests/test_skillsafe.py    # Test suite
LICENSE                    # MIT
```

## Testing

```bash
python3 -m pytest tests/ -v
```

## License

MIT
