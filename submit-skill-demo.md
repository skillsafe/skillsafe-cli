# Submit a SkillSafe Demo (Crafted Demo Workflow)

Use this workflow when you want to **design and produce a polished showcase demo** for a skill —
as opposed to `demo-from-session` which records an existing conversation.

A crafted demo is a multi-turn conversation you script and execute to show a skill's capabilities
clearly. It appears on `https://skillsafe.ai/demos/` and on the skill's detail page.

## Step 1 — Gather context

1. Identify the target skill: `@namespace/skill-name` and version (use `latest` if not specified).
2. Fetch the skill's info and install it to read its SKILL.md:
   ```bash
   python3 <skill-dir>/scripts/skillsafe.py info @namespace/skill-name
   python3 <skill-dir>/scripts/skillsafe.py install @namespace/skill-name
   ```
3. Read the installed `SKILL.md` to understand the skill's capabilities and workflows.
4. Get the SkillSafe API key:
   ```python
   import json; print(json.load(open('~/.skillsafe/config.json'))['api_key'])
   ```

## Step 2 — Design the demo session

Plan a **multi-turn conversation** (2–5 turns) that covers:
- A realistic starting request from a user
- At least 2–3 distinct capabilities of the skill
- Progressive complexity: start simple, then extend or refine

Each turn = one user message + one assistant response.

**Good demo topics per skill type:**
- File creation skills (xlsx, pptx, docx): create → extend → format/validate
- Code generation skills: generate → refine → test
- Search/analysis skills: query → filter → summarize
- CLI/tool skills: basic command → advanced flags → error handling

## Step 3 — Execute and capture real output

**Always run the actual skill commands** to get real output — never invent numbers or fake results.

For file-producing skills (xlsx, pptx, etc.):
1. Run the code to create the file
2. Read back the data with pandas or equivalent:
   ```python
   import pandas as pd
   df = pd.read_excel('output.xlsx', sheet_name=None)
   ```
3. If the skill has a recalc/validation script, run it:
   ```bash
   python3 scripts/recalc.py output.xlsx
   ```
4. Capture real values — formula counts, row counts, recalc status
5. **Explain the file's content in the chat** — describe sheet names, what formulas compute, what
   the data represents. Don't just say "file saved".

## Step 4 — Write the messages array

Each message: `{"role": "user"|"assistant", "content": "..."}`.

### Content rules

**DO:**
- Show actual data as markdown tables in assistant messages
- Include the real code used (fenced code blocks)
- Show recalc/validation output as a code block
- End the last assistant message with a clear summary of what was produced
- Use accurate numbers from the actual run

**DO NOT:**
- Say "sub-agent" — say "I'll create...", "Running..." instead
- Invent or round numbers
- Show only code without the resulting output
- Use filler like "The file was saved successfully" with no details

### Reading the model per turn

Before writing the messages array, read the actual model name from the session JSONL so
multi-agent sessions are recorded accurately:

```python
import json, glob, os

project_dir = os.path.expanduser("~/.claude/projects/")
cwd = os.getcwd().replace("/", "-").lstrip("-")
session_dir = os.path.join(project_dir, "-" + cwd)

files = sorted(
    [f for f in glob.glob(os.path.join(session_dir, "*.jsonl"))
     if "/subagents/" not in f],
    key=os.path.getmtime, reverse=True
)

model_by_uuid = {}
if files:
    with open(files[0]) as f:
        for line in f:
            obj = json.loads(line)
            if obj.get("type") == "assistant":
                m = obj.get("message", {}).get("model")
                if m:
                    model_by_uuid[obj["uuid"]] = m

# When writing each assistant message, include:
#   {"role": "assistant", "model": model_by_uuid.get(uuid), "content": "..."}
```

## Step 5 — Submit to the API

```bash
curl -s -X POST "https://api.skillsafe.ai/v1/skills/@namespace/skill-name/versions/VERSION/demos" \
  -H "Authorization: Bearer API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Short descriptive title (under 100 chars)",
    "demo": {
      "schema": "skillsafe-demo/1",
      "title": "Same title",
      "messages": [
        {"role": "user", "content": "..."},
        {"role": "assistant", "model": "claude-sonnet-4-6", "content": "..."},
        {"role": "user", "content": "..."},
        {"role": "assistant", "model": "claude-opus-4-6", "content": "..."}
      ]
    }
  }'
```

**Constraints:**
- `schema` must be exactly `"skillsafe-demo/1"`
- `title` required (max 200 chars)
- Max 1000 messages, 5 MB total
- Skill version must exist and not be yanked
- Skill must be publicly shared (`--public`) to appear on `/demos/`

## Step 6 — Confirm

On success: `{ "ok": true, "data": { "demo_id": "dmo_...", "url": "/demo/dmo_..." } }`

Tell the user the demo URL (`https://skillsafe.ai/demo/dmo_...`) and number of messages.

## Title conventions

Pattern: **"[Task]: [what was built] with [skill name]"**

- `"Build a 2025 sales report: create, extend, and validate with anthropics/xlsx"`
- `"Generate a pitch deck from JSON data with anthropics/pptx"`
- `"Refactor a Python module and run tests with anthropics/python-refactor"`

## Common mistakes

| Mistake | Fix |
|---------|-----|
| NaN in tables | Run recalc/LibreOffice before reading values back |
| Fake formula counts | Count actual formulas from recalc.py output |
| Only 1 user turn | Add at least 2 turns, up to 5 |
| No output shown | Always include a table or code block with real results |
| "sub-agent" language | Say "I'll use the script..." or "Running..." instead |
| Wrong skill version | Check `skillsafe info @ns/name` for the latest version |
| Vague file summary | Describe sheet names, formula purposes, data ranges |
