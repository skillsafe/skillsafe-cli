---
name: skillsafe
version: 0.1.5
description: Scan, save, share, install, and verify skills from the SkillSafe secured skill registry. Use this skill whenever the user mentions scanning a skill for security issues, saving or publishing a skill to a registry, sharing a skill via a link, installing someone else's skill, searching for skills, uploading a demo recording, checking skill verification status, or anything involving skill versioning, the SkillSafe CLI, or managing AI coding tool skills — even if they don't say "SkillSafe" explicitly. Also use it when the user asks to record a conversation as a demo or wants to showcase how a skill works.
allowed-tools: Bash, Read, Write
---

# SkillSafe — Secured Skill Registry Client

You have access to `skillsafe.py`, a Python client for the SkillSafe skill registry. It scans skills for security issues (dangerous functions, hardcoded secrets, prompt injection), saves them to the registry, shares them via links, installs them with cryptographic verification, and searches the registry.

## Setup

### Installation

Requires Python 3. Download the CLI script and run `update` to pull all remaining files:

```bash
SKILL_DIR="~/.claude/skills/skillsafe"
mkdir -p "$SKILL_DIR/scripts"
curl -fsSL https://skillsafe.ai/scripts/skillsafe.py -o "$SKILL_DIR/scripts/skillsafe.py"
python3 "$SKILL_DIR/scripts/skillsafe.py" update
```

This installs `SKILL.md`, `submit-skill-demo.md`, and `submit-demo-comment.md` alongside the script.

> The example above installs globally for Claude Code (`~/.claude/skills/`). Replace `SKILL_DIR` with the appropriate path for your tool.

### Updating

To update all skill files to the latest version:

```bash
python3 <skill-dir>/scripts/skillsafe.py update
```

**Upgrade a registry-installed skill** to the latest registry version:

```bash
python3 <skill-dir>/scripts/skillsafe.py update @ns/name
# or upgrade all installed skills at once:
python3 <skill-dir>/scripts/skillsafe.py update --all
```

**Installing into the current project:** By default (no flags), `install` places the skill in `.agents/skills/` inside the current working directory and auto-symlinks into detected agent directories (`.claude/skills/`, `.cursor/skills/`, etc.) so it is immediately available. Use `--location project` to make this explicit. Use `--tool <name>` (`claude`, `cursor`, `windsurf`, `codex`, `gemini`, `opencode`, `openclaw`, `cline`, `roo`, `goose`, `copilot`, `kiro`, `trae`, `amp`, `aider`, `vscode`, `antigravity`, `clawdbot`, `droid`, `kilo`) with `--location global` to install globally instead. For any other tool, use `--skills-dir <path>` with that tool's skills directory path.

## Available Commands

Run all commands using `python3` and the script at `scripts/skillsafe.py` inside this skill's directory.

### Auth — Sign in via browser
```bash
python3 <skill-dir>/scripts/skillsafe.py auth
```
First checks if a saved API key in `~/.skillsafe/config.json` is still valid. If valid, prints account info and exits. If the key is missing, expired, or revoked, opens your browser to sign in (via Google or API key) and saves a new API key. The CLI waits for browser authorization automatically.

### Scan — Security scan a skill directory
```bash
python3 <skill-dir>/scripts/skillsafe.py scan <path>
```
Runs 12 scan passes:
1. **Python AST analysis** — detects `eval()`, `exec()`, `os.system()`, `subprocess.*`, etc.
2. **JS/TS regex analysis** — detects `eval()`, `new Function()`, `child_process`, etc.
3. **Secret detection** — AWS keys, GitHub tokens, private keys, generic API keys
4. **Prompt injection + inducement language** — explicit override patterns and softer social-engineering phrases in `.md`/`.txt`/`.yaml` files (e.g. "run the included setup script", "for the tool to function")
5. **Shell threat patterns** — exfiltration, persistence, reverse shells, recon, ClickFix
6. **Binary file detection** — bundled executables/libraries
7. **base64 deep-scan** — decodes blobs and re-scans for hidden payloads
8. **Unicode obfuscation** — zero-width chars, Cyrillic/Latin homographs
9. **Structural mimicry** — fake `## Prerequisites` / `## Environment Setup` section headers followed by bundled-script execution references within 10 lines; urgency markers (`**IMPORTANT**`, `> WARNING`) adjacent to script execution (SkillJect SS-SM)
10. **Composite capability co-occurrence** — escalates when a single file combines process execution + network calls (critical), env reads + network (high), or accumulates 3+ medium findings (high)
11. **Surplus functionality** — cross-references script capabilities (network, env reads, subprocess, file writes) against `SKILL.md` documentation; flags capabilities present in code but absent from docs
12. **BOM (Bill of Materials)** — neutral capability inventory cataloging all detected capabilities, permissions, and dependencies

### Save — Save a skill to the registry (private by default)
```bash
python3 <skill-dir>/scripts/skillsafe.py save <path> [--version <semver>] [--description <d>] [--category <c>] [--tags <t>] [--changelog <msg>]
```
Scans the skill, computes a SHA-256 tree hash, and uploads to the registry. Skills are saved privately by default — only you can access them. No email verification required. Use `--changelog` to describe what changed in this version (shown in `info`). If `--version` is omitted, the CLI auto-increments the patch version from the latest (e.g., 1.0.2 → 1.0.3). If the skill's content is unchanged from the latest version, the save is skipped.

Saving is intentionally low-friction and private — the goal is to let you checkpoint work in progress without committing to distribution. Think of it like a private git commit: you're preserving the version and its tree hash before you decide whether to share it with anyone.

### Share — Create a share link for a saved skill
```bash
python3 <skill-dir>/scripts/skillsafe.py share @<namespace>/<skill-name> --version <ver> [--public] [--expires <1d|7d|30d|never>]
```
Creates a share link for a specific version. By default the link is private (only people with the link can access it). Use `--public` to make the skill discoverable via search. Requires email verification and a scan report on the version.

Sharing requires a scan report because SkillSafe's dual-side verification model depends on it: when a consumer installs via the link, their local scan is compared against the sharer's report. Without the sharer's report on record, there's nothing to verify against. This is what makes the supply chain trustworthy — both sides must independently produce a consistent scan result.

### Install — Install a skill from the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<skill-name> [--version <ver>] [--skills-dir <dir>] [--tool <name>]
```
Downloads the archive, verifies the tree hash matches, scans the downloaded files, submits a verification report, and installs. By default (no flags), installs into the **current project's `.agents/skills/`** directory and auto-symlinks into detected agent directories (`.claude/skills/`, `.cursor/skills/`, etc.). Use `--location project` to make this explicit. Use `--tool <name> --location global` to install into a known tool's **global** skills directory (`--tool claude` → `~/.claude/skills/`, `--tool cursor`, `--tool windsurf`, `--tool openclaw`). Use `--skills-dir <path>` for any other tool — pass the parent directory and the skill will be placed in a subdirectory named after the skill.

The install command does more than download — it independently re-scans the files and submits that report to the server, which compares it against the sharer's original scan. This is the consumer side of dual-side verification: if someone tampered with the archive between publishing and download, the tree hash will mismatch and the install will be blocked. Running the scan locally (rather than trusting the server's copy) is what makes this meaningful — it's the consumer's independent check, not just a server-side assertion.

After install, a `.skillsafe.json` metadata file is written into the skill directory with the namespace, name, version, and tree hash. The installer also injects `improvable: true` and `registry` fields into the skill's SKILL.md frontmatter if not already present.

### Search — Search the registry
```bash
python3 <skill-dir>/scripts/skillsafe.py search "<query>" [--category <c>] [--sort popular|recent|verified|trending|hot|relevance|installs|newest|updated|stars|eval_score] [--limit N] [--page N] [--all]
```
Searches publicly shared skills only. Use `--page N` to fetch a specific page, or `--all` to auto-paginate through the entire registry (fetches 100 per batch). Default limit is 20 per page, max is 100.

### Lint — Validate a skillsafe.yaml manifest
```bash
python3 <skill-dir>/scripts/skillsafe.py lint [path]
```
Validates the `skillsafe.yaml` manifest in the given directory (defaults to current directory). Checks: required fields (`name`, `version`, `entrypoint`), valid semver version, entrypoint file exists, description quality, valid category, lowercase tags, and eval pass rate threshold (≥80% required for "Tested" tier). Reports errors (must fix before saving) and warnings (recommendations). Exits with code 1 if any errors are found.

### Import — Import a GitHub repository as a skill
```bash
python3 <skill-dir>/scripts/skillsafe.py import <github-url>
```
Imports a GitHub repository as a public placeholder skill on SkillSafe. Accepts bare `github.com/owner/repo` or full `https://github.com/owner/repo` URLs. Creates a public skill entry with metadata fetched from GitHub (name, description, stars, language, license). If the skill already exists, refreshes its GitHub metadata. Use this to quickly register an existing GitHub-hosted skill on SkillSafe, then follow up with `save` to upload your local version and `share` to distribute it.

### Eval — Upload eval results for a skill version
```bash
python3 <skill-dir>/scripts/skillsafe.py eval @<ns>/<name> --version <ver> [--eval-json <file>]
python3 <skill-dir>/scripts/skillsafe.py eval @<ns>/<name> --version <ver> --pass-rate 91.7 --test-cases 12 --pass-count 11 [--model claude-opus-4-6]
```
Uploads skill-creator eval results to SkillSafe, attaching them to a specific saved version. Use `--eval-json` to pass a skill-creator eval JSON file (parses `summary.pass_rate`, `summary.total`, `summary.passed`, `model`). Alternatively, pass stats directly with `--pass-rate`, `--test-cases`, `--pass-count`. Skills with ≥5 test cases and ≥80% pass rate earn the **✅ Tested** tier, which improves search visibility. If the pass rate dropped from the previous version, a regression warning is shown. Skill-creator eval JSON format: `{ "summary": { "pass_rate": 91.7, "total": 12, "passed": 11 }, "model": "claude-opus-4-6" }`.

### Benchmark — Upload benchmark results for a skill version
```bash
python3 <skill-dir>/scripts/skillsafe.py benchmark @<ns>/<name> --version <ver> --runs 10 [--avg-time 1.4] [--avg-tokens 850] [--variance 0.2]
```
Uploads benchmark performance data (execution time, token usage, variance) to SkillSafe. Stored alongside eval results on the skill's Evals tab.

### Claim — Claim a skill from another registry
```bash
python3 <skill-dir>/scripts/skillsafe.py claim github.com/owner/repo
python3 <skill-dir>/scripts/skillsafe.py claim clawhub:owner/skill-name
```
Claims an externally-hosted skill on SkillSafe. For GitHub sources, creates a SkillSafe listing with GitHub metadata (same as `import`). For ClawHub sources, prints migration instructions. After claiming, run `scan` + `save` + `eval` to earn the Tested tier.

### Yank — Block downloads of a broken version
```bash
python3 <skill-dir>/scripts/skillsafe.py yank @<namespace>/<skill-name> --version <ver> [--reason <msg>]
```
Marks a version as yanked — it remains visible in `info` but cannot be downloaded. Use when a published version has a bug or security issue. Other versions are unaffected.

### Demo — Upload a chat recording

> To **design and produce a polished showcase demo from scratch** (rather than recording an existing session), read `submit-skill-demo.md` in this skill's directory, or fetch it from `https://skillsafe.ai/submit-skill-demo.md`.
```bash
python3 <skill-dir>/scripts/skillsafe.py demo <demo-json-file> @<ns>/<name> --version <ver> [--title "Title"]
```
Upload a recorded chat session showing the skill in action. The demo JSON must follow the `skillsafe-demo/1` schema:
```json
{
  "schema": "skillsafe-demo/1",
  "title": "Example: reviewing a pull request",
  "messages": [
    {"role": "user", "content": "Review PR #42"},
    {
      "role": "assistant",
      "content": "I'll review it now.",
      "tool_uses": [
        {"tool": "Bash", "input": "gh pr view 42", "output": "Title: Add auth..."}
      ]
    }
  ]
}
```
Fields: `schema` (required), `title` (required, max 200 chars), `messages` array with `role`/`content`/`tool_uses`. Limits: max 5 MB, max 1000 messages. The `--title` flag overrides the title in the JSON.

### Demo from Session — Convert a Claude Code session into a demo and upload it

Use this when the user wants to record the current or a recent conversation as a demo for a skill.

**Step 1 — Find the session file**

Claude Code saves sessions as JSONL files under `~/.claude/projects/<project-dir>/`. The project directory name is the absolute project path with every `/` and `.` replaced by `-`:

```bash
# Compute the sessions directory for the current project
python3 -c "import os, re; print(re.sub(r'[/.]', '-', os.getcwd()))"
# → e.g.  -Users-alice-myproject

# List the most recent sessions for this project
ls -lt ~/.claude/projects/<project-dir>/*.jsonl 2>/dev/null | head -5
```

To get the path in one shot:
```bash
ls -t ~/.claude/projects/$(python3 -c "import os,re; print(re.sub(r'[/.]','-',os.getcwd()))")/*.jsonl 2>/dev/null | head -3
```

Pick the most recently modified `.jsonl` file that represents the session you want to record. Avoid the file currently being written (the most recent one if you are mid-conversation); prefer the second most recent for a complete past session.

**Step 2 — Convert, clean, and upload**

```bash
python3 <skill-dir>/scripts/skillsafe.py demo-from-session \
  <session.jsonl> \
  @<ns>/<name> --version <ver> \
  --title "<what this demo shows>" \
  --filter-keyword <skill-name>
```

`--filter-keyword` keeps only messages that mention the skill name (in content or tool inputs/outputs), which removes off-topic turns and keeps the demo focused. Use the skill's short name (e.g. `skillsafe`, `code-review`).

**Step 3 — Preview before uploading (optional)**

```bash
# Save to file first, inspect, then upload
python3 <skill-dir>/scripts/skillsafe.py demo-from-session <session.jsonl> \
  --title "<title>" --filter-keyword <keyword> --out demo.json

# Review demo.json, then upload
python3 <skill-dir>/scripts/skillsafe.py demo demo.json @<ns>/<name> --version <ver>
```

**What the command does automatically:**
- Pairs every `tool_use` block with its `tool_result`, merges into `tool_uses` array
- Skips system-injected tags (`<local-command-caveat>`, `<system-reminder>`, etc.)
- Masks sensitive values: API keys, GitHub tokens, AWS keys, Bearer tokens, email addresses, home directory paths
- Truncates tool outputs longer than 120 lines (configurable with `--max-output-lines N`)
- Reports how many sensitive values were replaced before uploading

### Info — Get skill details
```bash
python3 <skill-dir>/scripts/skillsafe.py info @<namespace>/<skill-name>
```

### List — Show all installed skills
```bash
python3 <skill-dir>/scripts/skillsafe.py list
```
Shows skills from multiple locations: all known tool directories (Claude Code, Cursor, Windsurf, Codex, Gemini, OpenCode, OpenClaw, Cline, Roo, Goose, Copilot, Kiro, Trae, AMP, Aider, VS Code, Antigravity, ClawdBot, Droid, Kilo Code), SkillSafe registry skills (`~/.skillsafe/skills/`), and project-level skills. Use `--skills-dir <path>` to include additional directories.

## Improving & Iterating on Skills

Use this workflow when the user wants to edit an existing skill, publish a new version, or roll back to an older one.

### Step 1 — Install locally for editing

```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<name>
```

This installs into `.agents/skills/` in the current project by default (with symlinks to detected agent directories). After install, a `.skillsafe.json` metadata file is written into the skill directory with the namespace, name, version, and tree hash.

### Step 2 — Edit the skill

Read and modify `SKILL.md` (instructions) and any supporting files in the installed directory. Base improvements on user feedback about what worked or didn't. If unsure where the skill was installed, run `list` to find the path.

### Step 3 — Save the improved version

```bash
python3 <skill-dir>/scripts/skillsafe.py save <path-to-skill-dir> --changelog "[type] what changed"
```

No `--version` needed — the CLI auto-increments the patch version. If the content is unchanged, the save is skipped. Use changelog prefixes to categorize: `[example]`, `[patch]`, `[instruction]`, `[bugfix]`.

### Step 4 — Optionally share

```bash
python3 <skill-dir>/scripts/skillsafe.py share @<namespace>/<name> --version <new-version> [--public]
```

### Step 5 — Revert to a previous version if needed

```bash
python3 <skill-dir>/scripts/skillsafe.py install @<namespace>/<name> --version <old-version> --tool claude
```

## Self-Improving Skills

Skills can self-improve based on usage feedback. When a skill has `improvable: true` in its frontmatter, the main agent orchestrates an observe-improve-save loop after each execution. Self-improvement is disabled by default — pass `--auto-improve` during install to opt in.

### Frontmatter Fields

Add these optional fields to opt into self-improvement:

```yaml
---
name: my-skill
description: What this skill does
context: fork
improvable: true
registry: "@namespace/skill-name"
allowed-tools: Bash, Read, Write
---
```

- **`improvable: true`** — Signals that this skill opts into the self-improvement loop. When present, the main agent observes execution and user feedback, then edits and saves a new version when warranted. Not injected by default — pass `--auto-improve` during install to enable.
- **`registry: "@ns/name"`** — The skill's registry coordinates. Used by the auto-save flow so the agent doesn't need to derive namespace and name separately. Read from `.skillsafe.json` if not in frontmatter.
- **`context: fork`** — Skills should run in a sub-agent (separate context) so the main agent can observe the full execution and user reaction without being inside the skill's execution flow.

### How It Works

1. **Sub-agent execution**: The main agent reads the skill's SKILL.md and spawns a sub-agent with `context: fork`. The sub-agent executes the skill instructions and returns the result.

2. **Feedback detection**: After the sub-agent completes, the main agent observes the user's next 1-3 messages for feedback signals:
   - **Positive**: user says "thanks", "good job", "perfect", or proceeds without corrections
   - **Negative**: user says "wrong", "no", "try again", manually corrects output, or asks for a different approach
   - **Error recovery**: the sub-agent hit a tool error (e.g., command not found) and used a workaround

3. **Improvement**: When feedback warrants it, the main agent edits the skill files directly:
   - **Add examples** — append successful (input, output) pairs to a `## Examples` section in SKILL.md
   - **Patch scripts** — fix commands that failed (e.g., replace `jq` with `python3 -m json.tool` when jq is missing)
   - **Fix instructions** — clarify SKILL.md text based on user corrections

4. **Save new version**: The main agent saves the improved skill:
   ```bash
   python3 <skillsafe-cli>/scripts/skillsafe.py save <skill-dir> --changelog "[patch] replaced jq with python3 fallback"
   ```
   The version auto-increments. The changelog describes what was improved and why.

5. **Confirm to user**: The main agent tells the user what was improved and the new version number.

### Changelog Convention

Use a bracketed prefix to categorize improvement type:
- `[example]` — Added a concrete example of correct behavior
- `[patch]` — Fixed a script or command (tool fallback, error handling, platform compatibility)
- `[instruction]` — Clarified or corrected SKILL.md instructions
- `[bugfix]` — Fixed a bug in the skill's logic

### Skill Template Sections

Skills that opt into self-improvement should include these optional sections:

#### Feedback Signals

Define what counts as positive/negative feedback specific to this skill:

```markdown
## Feedback Signals

### Positive
- User accepts the generated output without edits
- Tests pass after the skill's changes

### Negative
- User reverts the skill's changes
- Tests fail after the skill's changes
- User says the output format is wrong
```

#### Improvement Guide

Define what types of improvements the main agent should make:

```markdown
## Improvement Guide

### When a command fails
Add platform detection and fallback commands. Prefer widely-available tools.

### When output format is wrong
Add a concrete example to the Examples section showing the correct format.

### When instructions are misunderstood
Add DO and DO NOT lists to clarify edge cases.
```

### Rate Limiting

To avoid rapid-fire saves:
- Only improve after explicit user feedback, not on every sub-agent error
- Maximum one improvement save per skill per conversation
- If the same skill fails after an improvement, ask the user before making another edit

## How to Use

When the user asks to scan, save, share, install, list, or search for skills:

1. Determine which command to run based on the user's request
2. Run the appropriate command using `Bash`
3. Show the user the output

Common user requests and which command to use:
- "sign in" / "log in" / "authenticate" -> `auth`
- "list my skills" / "what skills do I have" -> `list`
- "scan this for security issues" -> `scan <path>`
- "save my skill" / "upload my skill" -> `save <path>` (auto-versions) or `save <path> --version <ver>`
- "share my skill" / "publish my skill" -> `share @ns/name --version <ver>` (add `--public` for search visibility)
- "install a skill" -> `install @ns/name` (project default) or `install @ns/name --tool <name>` for global install
- "improve this skill" / "make this skill better" / "update the skill instructions" -> edit + save workflow (see "Improving & Iterating on Skills")
- "push a new version" / "publish my changes" -> `save <path> --changelog "what changed"`
- "revert to previous version" / "go back to the old skill" / "undo skill changes" -> `install @ns/name --version <old>` (project) or `install @ns/name --version <old> --tool claude` (global)
- "yank this version" / "block this version" / "this version is broken" -> `yank @ns/name --version <ver> --reason "..."`
- "record this session as a demo" / "upload a demo of this skill" / "create a demo from our conversation" -> `demo-from-session` workflow: find the session JSONL, convert with `--filter-keyword <skill-name>`, upload
- "comment on a demo" / "reply to a comment" / "post a comment on demo dmo_..." -> read `submit-demo-comment.md` in this skill's directory, or fetch `https://skillsafe.ai/submit-demo-comment.md`

## Configuration

Credentials are stored in `~/.skillsafe/config.json`. By default, `install` places skills in `.agents/skills/` in the current project directory and auto-symlinks into detected agent directories. Use `--tool <name>` for global install to the tool's standard location, or `--skills-dir <path>` for a custom location. Supported tools: `claude` → `~/.claude/skills/`, `cursor` → `~/.cursor/skills/`, `windsurf` → `~/.windsurf/skills/`, `codex` → `~/.agents/skills/`, `gemini` → `~/.gemini/skills/`, `opencode` → `~/.config/opencode/skills/`, `openclaw` → `~/.openclaw/workspace/skills/`, `cline` → `~/.cline/skills/`, `roo` → `~/.roo/skills/`, `goose` → `~/.config/goose/skills/`, `copilot` → `~/.config/github-copilot/skills/`, `kiro` → `~/.kiro/skills/`, `trae` → `~/.trae/skills/`, `amp` → `~/.amp/skills/`, `aider` → `~/.aider/skills/`, `vscode` → `~/.vscode/skills/`.

## Security Model

SkillSafe uses a **save-first** model: skills are saved privately by default, then shared via links when ready. Shared skills require **dual-side verification**: the sharer scans before sharing, the consumer independently re-scans after download, and the server compares both reports. Tree hashes (SHA-256 of the archive) detect tampering. Verdicts are:
- **verified** — scans match, safe to install
- **divergent** — scans disagree, user decides
- **critical** — tree hash mismatch, possible tampering, abort
