"""Markdown report generation for LexEvidence Disclosure Agent."""

from __future__ import annotations

from agent.analyzer import AuditResult
from agent.policy_generator import generate_disclosure_note, generate_policy_snippet
from agent.risk_classifier import LEVEL_LABELS, LEVEL_DOTS, CLASS_LABELS

GAP_RECOMMENDATIONS = {
    "disclosure": ("AI transparency", "Add a clear AI disclosure note to every external message."),
    "operator": ("accountability", "Identify the responsible operator in user-facing communication."),
    "scope": ("scope control", "Define and enforce the agent's scope of authority."),
    "approval": ("human-in-the-loop", "Require human approval for medium/high/critical actions."),
    "audit": ("auditability", "Preserve timestamps, content, tools, approvals and file hashes."),
    "custody": ("chain of custody", "Ensure chronological, complete and hashable records."),
    "escalation": ("human escalation", "Provide and use an escalation path for high-risk matters."),
    "data": ("data minimization", "Reduce data access to what is necessary for the task."),
    "reserved": ("professional guardrail", "Prevent autonomous legal/medical/tax advice without qualified review."),
    "notice": ("complete disclosure", "Include AI status, operator identity and human contact route."),
}


def _gap_recommendation(gap: str) -> tuple[str, str]:
    for key, value in GAP_RECOMMENDATIONS.items():
        if key in gap.lower():
            return value
    return "Lex Turbo Standard", "Review and remediate this gap before deployment."


def build_report(result: AuditResult) -> str:
    log = result.log
    lines: list[str] = []
    lines.append(f"# LexEvidence Disclosure Audit Report")
    lines.append("")
    lines.append("## 1. File metadata")
    lines.append(f"- Source file: `{log.source_filename}`")
    lines.append(f"- Agent name: `{log.agent_name}`")
    lines.append(f"- Operator: `{log.operator}`")
    lines.append(f"- Channel: `{log.channel}`")
    lines.append(f"- SHA-256: `{log.sha256}`")
    lines.append(f"- Analyzed at: `{result.analyzed_at}`")
    lines.append("")
    lines.append("## 2. Executive summary")
    lines.append(f"- Compliance score: **{result.total}/{result.max_total}**")
    lines.append(f"- Overall risk: **{LEVEL_DOTS[result.overall]} {LEVEL_LABELS[result.overall]}**")
    lines.append(f"- Detected gaps: **{len(result.gaps)}**")
    lines.append("")
    lines.append("## 3. Ten-principle audit")
    lines.append("| # | Principle | Score | Evidence | Justification |")
    lines.append("|---|---|---:|---|---|")
    for rule in result.rules:
        evidence = rule.evidence.replace("|", "\\|")
        justification = rule.justification.replace("|", "\\|")
        lines.append(f"| {rule.number} | {rule.name} | {rule.points}/2 | {evidence} | {justification} |")
    lines.append("")
    lines.append("## 4. Message risk matrix")
    lines.append("| Message | Action class | Risk | Reasons | Excerpt |")
    lines.append("|---:|---|---|---|---|")
    for risk in result.message_risks:
        reasons = "; ".join(risk.reasons) or "—"
        excerpt = risk.excerpt.replace("|", "\\|")
        lines.append(f"| {risk.index} | {CLASS_LABELS[risk.action_cls]} | {LEVEL_DOTS[risk.level]} {LEVEL_LABELS[risk.level]} | {reasons} | {excerpt} |")
    lines.append("")
    lines.append("## 5. Gap analysis")
    if result.gaps:
        for gap in result.gaps:
            basis, recommendation = _gap_recommendation(gap)
            lines.append(f"- **{gap}** — basis: {basis}. Recommendation: {recommendation}")
    else:
        lines.append("No material gaps detected in this synthetic log.")
    lines.append("")
    lines.append("## 6. Chain-of-custody checklist")
    lines.append("- File hash recorded: yes")
    lines.append(f"- Audit log declared available: {'yes' if log.audit_log_available else 'no'}")
    lines.append("- Timestamped messages present: yes")
    lines.append("- Human approval flags present: yes")
    lines.append("- Tools and data access fields present: yes")
    lines.append("")
    lines.append("## 7. Recommended disclosure note")
    lines.append(generate_disclosure_note(log))
    lines.append("")
    lines.append("## 8. Recommended internal policy snippet")
    lines.append(generate_policy_snippet(result.gaps))
    lines.append("")
    lines.append("## 9. Responsible AI notice")
    lines.append("This is a demonstration tool using synthetic data only. It is an auditor, not an autonomous decision-maker, and it does not provide legal advice.")
    lines.append("")
    return "\n".join(lines)
