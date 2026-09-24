"""
Optional PR-level enrichment for the summary comment: a changed-files table
with touched symbol names, an LLM-generated narrative ("What this PR does" /
"Impact Analysis"), and an honest findings-by-file diagram.

All of this is presentation on top of the real findings, never load-bearing:
every function here degrades to None/"" (not a crash) when git or an LLM key
isn't available, and render_extra_sections() is safe to call with any mix of
missing pieces.

No fabricated call-graph analysis: the "flow" diagram shows PR -> changed
file -> its findings, which is what this codebase can actually derive - not
a cross-function call chain, which would need real AST/call-graph analysis
this repo doesn't have. A wrong diagram in a security review is worse than
no diagram.
"""
import json
import re

import requests

from aspm_cli.utils.git_info import GitInfo
from aspm_cli.utils.logger import Logger
from .remediation import DEFAULT_BASE_URL, DEFAULT_MODEL
from .render import SEVERITY_ICON, SEVERITY_ORDER

_MAX_FILES_IN_TABLE = 10
_MAX_FILES_IN_DIAGRAM = 12
_MAX_SYMBOLS_SHOWN = 5
_TIMEOUT = 30

# Added-line patterns for common languages/IaC, first match per line wins.
# Best-effort symbol extraction, not a parser - a line that doesn't match
# any of these just doesn't contribute a symbol name, nothing crashes.
_SYMBOL_PATTERNS = (
    re.compile(r"^\+\s*(?:async\s+)?def\s+(\w+)\s*\("),                      # Python
    re.compile(r"^\+\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+(\w+)\s*\("),  # JS/TS
    re.compile(r"^\+\s*(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\("),  # JS/TS arrow fn
    re.compile(r"^\+\s*func\s+(?:\([^)]*\)\s*)?(\w+)\s*\("),                 # Go
    re.compile(r"^\+\s*resource\s+\"[\w-]+\"\s+\"([\w-]+)\""),               # Terraform
    re.compile(r"^\+\s*class\s+(\w+)"),                                     # Python/Java/JS class
)


def _extract_symbols(diff_text):
    seen = []
    for line in (diff_text or "").splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for pat in _SYMBOL_PATTERNS:
            m = pat.match(line)
            if m:
                name = m.group(1)
                if name not in seen:
                    seen.append(name)
                break
    return seen


def build_file_changes(base_sha, head_sha):
    """[{"path", "added", "deleted", "symbols": [...]}, ...] or None if the
    diff couldn't be computed (e.g. base_sha not fetched)."""
    rows = GitInfo.get_diff_numstat(base_sha, head_sha)
    if not rows:
        return None
    out = []
    for path, added, deleted in rows:
        diff_text = GitInfo.get_unified_diff_for_file(base_sha, head_sha, path)
        out.append({"path": path, "added": added, "deleted": deleted,
                     "symbols": _extract_symbols(diff_text)})
    return out


def render_file_changes_table(file_changes):
    if not file_changes:
        return ""
    lines = ["### \U0001F511 Key Changes at a Glance", "",
             "| File | Changes | Key Updates |", "|---|---|---|"]
    shown = file_changes[:_MAX_FILES_IN_TABLE]
    for r in shown:
        symbols = r["symbols"]
        if symbols:
            updates = ", ".join(symbols[:_MAX_SYMBOLS_SHOWN])
            if len(symbols) > _MAX_SYMBOLS_SHOWN:
                updates += "..."
        else:
            updates = "*code changes*"
        added = f"+{r['added']}" if r["added"] != "-" else "binary"
        deleted = f"-{r['deleted']}" if r["deleted"] != "-" else ""
        lines.append(f"| `{r['path']}` | {added} {deleted} | {updates} |")
    remaining = len(file_changes) - len(shown)
    if remaining > 0:
        lines.append(f"| ... | ... | *and {remaining} more file(s)* |")
    lines.append("")
    return "\n".join(lines)


def _build_narrative_prompt(file_changes, findings):
    file_lines = "\n".join(
        f"- {r['path']} (+{r['added']} -{r['deleted']}): {', '.join(r['symbols']) or 'no named symbols detected'}"
        for r in file_changes[:20]
    )
    finding_lines = "\n".join(
        f"- {f['severity']} {f['rule_id']} in {f['path']}:{f['start_line']}" for f in findings[:20]
    ) or "none"
    return (
        "You are summarizing a pull request for a security review comment.\n\n"
        f"Changed files:\n{file_lines}\n\n"
        f"Security findings in this PR:\n{finding_lines}\n\n"
        "Reply with ONLY a JSON object, no markdown fences, no explanation, matching exactly:\n"
        '{"what_it_does": ["bullet", "..."], "impact": ["bullet", "..."]}\n\n'
        "3-6 short bullets each. what_it_does describes the functional changes only. "
        "impact covers functional AND security impact, referencing specific findings by "
        "file/rule where relevant - call out anything CRITICAL/HIGH explicitly."
    )


def generate_pr_narrative(file_changes, findings, api_key, model=None, base_url=None):
    """{"what_it_does": [...], "impact": [...]} or None - skipped (no key/no
    diff) or failed (bad response, network error). Never raises."""
    logger = Logger.get_logger()
    if not api_key or not file_changes:
        return None
    model = model or DEFAULT_MODEL
    base_url = base_url or DEFAULT_BASE_URL
    try:
        resp = requests.post(
            base_url,
            json={"model": model,
                  "messages": [{"role": "user", "content": _build_narrative_prompt(file_changes, findings)}],
                  "max_tokens": 700},
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json",
                     "HTTP-Referer": "https://github.com/accuknox/aspm-scanner-cli",
                     "X-Title": "AccuKnox PR Decorator"},
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"].strip()
        content = re.sub(r"^```(?:json)?\s*|\s*```$", "", content).strip()
        data = json.loads(content)
        if not isinstance(data.get("what_it_does"), list) or not isinstance(data.get("impact"), list):
            raise ValueError(f"unexpected narrative shape: {data!r}")
        return data
    except Exception as e:
        logger.warning(f"PR narrative generation failed: {e}")
        return None


def render_narrative(narrative):
    if not narrative:
        return ""
    lines = []
    if narrative.get("what_it_does"):
        lines += ["### \U0001F4DD What This PR Does", ""]
        lines += [f"- {b}" for b in narrative["what_it_does"]]
        lines.append("")
    if narrative.get("impact"):
        lines += ["### \U0001F3AF Impact Analysis", ""]
        lines += [f"- {b}" for b in narrative["impact"]]
        lines.append("")
    return "\n".join(lines)


def _mermaid_node_id(prefix, s):
    return prefix + re.sub(r"[^a-zA-Z0-9]", "_", s)[:40]


def render_flow_diagram(findings):
    """PR -> changed file -> its findings (grouped, worst severity shown) -
    what this codebase actually knows. Not a call graph - see module
    docstring for why that's deliberate, not a missing feature."""
    if not findings:
        return ""
    by_file = {}
    for f in findings:
        by_file.setdefault(f["path"], []).append(f)
    if not by_file:
        return ""

    lines = ["## \U0001F5FA️ Findings by File", "",
              "<details open>", "<summary><b>\U0001F4CC Overview</b></summary>", "",
              "```mermaid", "graph LR", '  PR["Pull Request"]']
    for path, items in list(by_file.items())[:_MAX_FILES_IN_DIAGRAM]:
        fid = _mermaid_node_id("F", path)
        worst = min(items, key=lambda x: SEVERITY_ORDER.index(x["severity"]))
        icon = SEVERITY_ICON[worst["severity"]]
        lines.append(f'  PR --> {fid}["{path}"]')
        lines.append(f'  {fid} --> {fid}_c["{icon} {len(items)} finding(s)"]')
    remaining = len(by_file) - _MAX_FILES_IN_DIAGRAM
    if remaining > 0:
        lines.append(f'  PR --> MORE["... and {remaining} more file(s)"]')
    lines += ["```", "", "</details>", ""]
    return "\n".join(lines)


def render_extra_sections(file_changes, narrative, findings):
    """Everything above Security Findings, in order. Each piece is already
    individually degrade-safe (empty string when its data is missing) - this
    just concatenates whatever came back."""
    parts = [render_file_changes_table(file_changes), render_narrative(narrative),
             render_flow_diagram(findings)]
    return "\n".join(p for p in parts if p)
