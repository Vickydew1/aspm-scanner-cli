"""
PR Decorator - comment renderer.

Turns normalized findings (see adapters.py) into GitHub-ready markdown: a PR
summary comment (severity table + quality gate) and per-finding inline
comment bodies. Provider-agnostic - started as a port of the standalone
PR-Decorator action (accuknox/PR-Decorator), since corrected against this
CLI's own real scan output and the CSPM backend's parsers (source of truth
for which raw fields matter) where they diverged from the original port.
"""
import json
import re
from collections import Counter

SEVERITY_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1", "LOW": "⚪", "UNKNOWN": "❔"}
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

# Gate thresholds: max findings allowed per severity before the gate fails.
# None = unlimited. UNKNOWN defaults to unlimited - nothing to gate on
# without a real severity (see adapters.load_findings_checkov).
DEFAULT_THRESHOLDS = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": None, "LOW": None, "UNKNOWN": None}

FINDING_MARKER_RE = re.compile(r"accuknox-pr-decorator:finding:(\S+?) -->")

FOOTER = ("\n---\n"
          "\U0001F537 **[AccuKnox ASPM](https://accuknox.com)** — AI-powered, security-first PR review "
          "· [Docs](https://help.accuknox.com) · [Report an issue](https://github.com/accuknox)")


def load_findings(path, changed_files=None):
    """OpenGrep/SAST result loader - the default shape adapters.py falls
    back to for any file it can't otherwise identify."""
    with open(path) as f:
        data = json.load(f)

    findings = []
    for r in data["results"]:
        if changed_files is not None and r["path"] not in changed_files:
            continue  # diff-scope filter
        extra = r["extra"]
        metadata = extra.get("metadata", {})
        native_sev = extra.get("severity", "INFO")
        # Severity tier comes from extra.metadata.impact (LOW/MEDIUM/HIGH/
        # CRITICAL) - the same signal scan/sast.py's own quality gate uses
        # ("OpenGrep already rates each finding on the standard scale via
        # extra.metadata.impact... The rule-level extra.severity (ERROR/
        # WARNING/INFO) is a different axis"), and what the CSPM backend's
        # own Semgrep parser reads for risk_factor. Confirmed against a real
        # scan sample: impact is absent on ~85% of default-ruleset findings
        # (most rules don't carry one) - those fall to UNKNOWN, same policy
        # as Checkov's null severity, rather than invented from extra.severity.
        impact = (metadata.get("impact") or "").upper()
        severity = impact if impact in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "UNKNOWN"
        cwe = metadata.get("cwe", [])
        if isinstance(cwe, str):  # some rules report a single CWE as a bare string
            cwe = [cwe]
        findings.append({
            "rule_id": r["check_id"],
            "path": r["path"],
            "start_line": r["start"]["line"],
            "end_line": r["end"]["line"],
            "message": extra.get("message", ""),
            "severity": severity,
            "native_severity": native_sev,
            "cwe": cwe,
            "owasp": metadata.get("owasp"),
            "confidence": metadata.get("confidence"),
            "category": metadata.get("category"),
            "code": extra.get("lines", ""),
            "fingerprint": extra.get("fingerprint", ""),
            "fix": r.get("fix") or extra.get("fix") or extra.get("remediation"),
            "source": metadata.get("source", "AccuKnox SAST"),
        })
    meta = {
        "repo": data.get("repo"),
        "sha": data.get("sha"),
        "ref": data.get("ref"),
        "repo_url": data.get("repo_url"),
        "ai_analysis": data.get("ai_analysis", False),
    }
    return findings, meta


def gate_status(counts, thresholds):
    """Which severities exceeded their configured threshold. Empty = passed."""
    failed = []
    for sev in SEVERITY_ORDER:
        limit = thresholds.get(sev)
        found = counts.get(sev, 0)
        if limit is not None and found > limit:
            failed.append((sev, found, limit))
    return failed


def compute_event(findings, mode):
    """GitHub review event: REQUEST_CHANGES only in blocking mode with a
    CRITICAL/HIGH finding present, COMMENT otherwise."""
    blocking_severities = ("CRITICAL", "HIGH")
    has_blocker = any(f["severity"] in blocking_severities for f in findings)
    return "REQUEST_CHANGES" if (mode == "blocking" and has_blocker) else "COMMENT"


def render_severity_section(findings, severity):
    """One numbered list per severity tier - full detail lives on the
    matching inline comment, this stays a compact index."""
    items = [f for f in findings if f["severity"] == severity]
    if not items:
        return ""
    lines = [f"### {SEVERITY_ICON[severity]} {severity} Issues ({len(items)} found)", ""]
    for i, f in enumerate(sorted(items, key=lambda x: (x["path"], x["start_line"])), 1):
        cwe = f" — _{'; '.join(f['cwe'])}_" if f["cwe"] else ""
        lines.append(f"{i}. `{f['path']}:{f['start_line']}` — `{f['rule_id'].split('.')[-1]}`{cwe}")
    lines.append("")
    return "\n".join(lines)


def render_summary_comment(findings, meta, thresholds=None):
    thresholds = thresholds if thresholds is not None else DEFAULT_THRESHOLDS
    counts = Counter(f["severity"] for f in findings)
    total = len(findings)
    failed = gate_status(counts, thresholds)
    mode = meta.get("mode", "advisory")
    blocking = bool(failed) and mode == "blocking"

    lines = ["<!-- accuknox-pr-decorator:summary -->", "# \U0001F6E1️ AccuKnox Security Review", ""]

    lines.append("## \U0001F4CA Pull Request Summary")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| **Repository** | `{meta.get('repo') or 'unknown'}` |")
    if meta.get("pr_number"):
        lines.append(f"| **PR** | #{meta['pr_number']} |")
    if blocking:
        status = "\U0001F6A8 CRITICAL - Immediate Action Required"
    elif failed:
        status = "⚠️ Needs Review"
    else:
        status = "✅ Passed"
    lines.append(f"| **Security Status** | {status} |")
    lines.append("")
    lines.append(f"_Scanned `{meta.get('ref') or 'unknown ref'}` @ `{(meta.get('sha') or 'unknown sha')[:10]}` "
                  f"| AI analysis: {'on' if meta.get('ai_analysis') else 'off'}_")
    lines.append("")

    if total == 0:
        lines.append("## ✅ No issues found")
        lines.append("")
        lines.append("AccuKnox reviewed your code and found no material issues that require review.")
        return "\n".join(lines) + FOOTER

    lines.append("## \U0001F6E1️ Security Findings")
    lines.append("")
    lines.append(f"Found **{total} finding(s)** in changed code:")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in SEVERITY_ORDER:
        if counts.get(sev):
            lines.append(f"| {SEVERITY_ICON[sev]} {sev} | {counts[sev]} |")
    lines.append("")
    for sev in SEVERITY_ORDER:
        section = render_severity_section(findings, sev)
        if section:
            lines.append(section)

    lines.append("## \U0001F6A6 Quality Gate")
    lines.append("")
    if not failed:
        lines.append("✅ **Passed** — within configured thresholds.")
    else:
        lines.append("❌ **Failed**")
        lines.append("")
        lines.append("**Failed conditions**")
        for sev, found, limit in failed:
            lines.append(f"- {SEVERITY_ICON[sev]} {sev}: found {found}, threshold {limit}")
    lines.append("")

    lines.append("## ✅ Review Status")
    lines.append("")
    if blocking:
        lines.append("**Recommendation:** \U0001F6A8 **Changes requested** — thresholds exceeded.")
    elif failed:
        lines.append("**Recommendation:** ⚠️ Review recommended — thresholds exceeded "
                      "(advisory mode, not blocking).")
    else:
        lines.append("**Recommendation:** ✅ No blocking issues found.")
    return "\n".join(lines) + FOOTER


def render_inline_comment(f):
    lines = []
    lines.append(f"<!-- accuknox-pr-decorator:finding:{f['fingerprint']} -->")
    lines.append(f"{SEVERITY_ICON[f['severity']]} **{f['severity']}** "
                  f"— {f['rule_id'].split('.')[-1].replace('-', ' ')}")
    lines.append(f"_Detected by {f['source']}_")
    lines.append("")
    lines.append(f["message"])
    if f["cwe"]:
        lines.append("")
        lines.append("**CWE:** " + "; ".join(f["cwe"]))
    if f["code"]:
        lines.append("")
        lines.append("```")
        lines.append(f["code"].strip())
        lines.append("```")
    lines.append("")
    if f.get("fix"):
        lines.append("**Suggested fix:**")
        lines.append("```suggestion")
        lines.append(f["fix"])
        lines.append("```")
    else:
        lines.append("_No automatic fix available for this rule — remediation needs to be "
                      "reviewed manually._")
    return "\n".join(lines)
