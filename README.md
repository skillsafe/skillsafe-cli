# SkillSafe Skill Manager

A single-file Python CLI for the [SkillSafe](https://skillsafe.ai) secured skill registry. Scan, save, share, install, and verify AI coding skills with security scanning and dual-side cryptographic verification.

Works with **Claude Code**, **Cursor**, and **Windsurf**.

## Quick Start

No dependencies to install — uses only Python stdlib. Requires Python 3.8+.

```bash
# Sign in via browser
python3 scripts/skillsafe.py auth

# Scan a skill for security issues
python3 scripts/skillsafe.py scan <path>

# Save a skill to the registry (private by default)
python3 scripts/skillsafe.py save <path> --version 1.0.0

# Share a saved skill via link
python3 scripts/skillsafe.py share @ns/name --version 1.0.0

# Install a skill
python3 scripts/skillsafe.py install @ns/name --tool claude

# Search the registry
python3 scripts/skillsafe.py search "code review"
```

## Install as a Skill

Tell your AI coding tool:

> Install skillsafe from https://skillsafe.ai/skill.md

Or manually:

```bash
mkdir -p <skill-dir>/scripts
curl -fsSL https://skillsafe.ai/scripts/skillsafe.py -o <skill-dir>/scripts/skillsafe.py
```

## Commands

| Command | Description |
|---------|-------------|
| `auth` | Sign in via browser, saves API key to `~/.skillsafe/config.json` |
| `scan <path>` | Run 4-pass security scan (Python AST, JS/TS regex, secrets, prompt injection) |
| `save <path>` | Save a skill privately to the registry |
| `share @ns/name` | Create a share link for a saved skill |
| `install @ns/name` | Download, verify, scan, and install a skill |
| `search <query>` | Search publicly shared skills |
| `info @ns/name` | Get skill details |
| `list` | Show all installed skills across tools |
| `backup <path>` | Back up a skill to the vault |
| `restore <name>` | Restore a skill from the vault |

## Security Model

SkillSafe uses **dual-side verification**:

1. Sharer scans before sharing
2. Consumer re-scans after download
3. Server compares both reports

Tree hashes (SHA-256 of the archive) detect tampering. Verdicts: `verified`, `divergent`, `critical`.

## Testing

```bash
python3 -m pytest tests/ -v
# or
python3 -m unittest discover -s tests -v
```

## File Structure

```
SKILL.md              # Skill definition (source of truth)
scripts/skillsafe.py  # CLI client (stdlib only, ~1800 lines)
tests/test_skillsafe.py  # Test suite
LICENSE               # MIT
```

## License

MIT
