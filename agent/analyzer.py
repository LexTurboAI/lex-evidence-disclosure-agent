"""Deterministic audit engine: 10 Lex Turbo AI-agent disclosure principles."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from agent.parser import AgentLog, Message, parse_log_file
from agent.risk_classifier import (
    BASIC_DATA,
    LEVEL_ORDER,
    SENSITIVE_DATA,
    MessageRisk,
    action_class,
    classify_messages,
    escalation_present,
    is_disclosed,
    mentions_contact_channel,
    overall_risk,
    reserved_hits,
)

@dataclass
class RuleResult:
    number: int
    name: str
    points: int
    evidence: str
    justification: str
    gap_label: str | None = None
    max_points: int = 2

@dataclass
class AuditResult:
    log: AgentLog
    rules: list[RuleResult]
    total: int
    max_total: int
    gaps: list[str]
    message_risks: list[MessageRisk]
    overall: str
    analyzed_at: str = field(default_factory=lambda: datetime.now().strftime("%Y-%m-%d %H:%M"))


def _msg_ids(indices: list[int]) -> str:
    return ", ".join(f"#{i}" for i in indices) if indices else "—"


def _parse_ts(value: str):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except Exception:
        return None


def rule_1(log: AgentLog) -> RuleResult:
    ok = [i for i, m in enumerate(log.messages, 1) if is_disclosed(m)]
    missing = [i for i, m in enumerate(log.messages, 1) if not is_disclosed(m)]
    if not missing:
        return RuleResult(1, "AI status disclosure", 2, f"Disclosed messages: {_msg_ids(ok)}", "Every message clearly identifies AI involvement.")
    if ok:
        return RuleResult(1, "AI status disclosure", 1, f"Disclosed: {_msg_ids(ok)}; missing: {_msg_ids(missing)}", "AI disclosure is inconsistent.", "missing AI disclosure in some messages")
    return RuleResult(1, "AI status disclosure", 0, "No message contains a clear AI disclosure.", "The recipient may not know they interact with an AI system.", "missing AI disclosure")


def rule_2(log: AgentLog) -> RuleResult:
    if not log.operator:
        return RuleResult(2, "Operator identity", 0, "Operator field is empty.", "No accountable organization is identified.", "missing operator")
    mentioned = [i for i, m in enumerate(log.messages, 1) if log.operator.lower() in f"{m.message} {m.disclosure_note or ''}".lower()]
    if mentioned:
        return RuleResult(2, "Operator identity", 2, f"Operator '{log.operator}' appears in messages {_msg_ids(mentioned)}.", "Operator is defined and communicated.")
    return RuleResult(2, "Operator identity", 1, f"Operator exists in metadata: {log.operator}", "Operator exists in the log, but not in user-facing text.", "operator not disclosed to recipient")


def rule_3(log: AgentLog) -> RuleResult:
    critical = [i for i, m in enumerate(log.messages, 1) if action_class(m) == "critical"]
    if log.scope and not critical:
        return RuleResult(3, "Scope of authority", 2, f"Scope: {log.scope}", "Agent activity stays within a defined scope.")
    if log.scope:
        return RuleResult(3, "Scope of authority", 1, f"Scope exists; critical actions: {_msg_ids(critical)}", "Defined scope exists, but some actions are too sensitive.", "scope overrun risk")
    return RuleResult(3, "Scope of authority", 0, "Scope field is empty.", "No boundary of authority is documented.", "missing scope")


def rule_4(log: AgentLog) -> RuleResult:
    relevant = [(i, m) for i, m in enumerate(log.messages, 1) if LEVEL_ORDER[action_class(m)] >= LEVEL_ORDER["medium"]]
    if not relevant:
        return RuleResult(4, "Human approval", 2, "No medium/high/critical actions detected.", "Human approval was not required.")
    approved = [i for i, m in relevant if m.human_approved]
    missing = [i for i, m in relevant if not m.human_approved]
    if not missing:
        return RuleResult(4, "Human approval", 2, f"Approved: {_msg_ids(approved)}", "All sensitive actions were human-approved.")
    if approved:
        return RuleResult(4, "Human approval", 1, f"Approved: {_msg_ids(approved)}; missing: {_msg_ids(missing)}", "Some sensitive actions lack approval.", "missing human approval in some actions")
    return RuleResult(4, "Human approval", 0, f"Missing approval: {_msg_ids(missing)}", "No sensitive action was approved by a human.", "missing human approval")


def rule_5(log: AgentLog) -> RuleResult:
    complete = all(m.timestamp and m.message for m in log.messages)
    points = int(log.audit_log_available) + int(complete)
    if points == 2:
        return RuleResult(5, "Audit trail", 2, "audit_log_available=true and message entries are complete.", "A basic audit trail exists.")
    if points == 1:
        return RuleResult(5, "Audit trail", 1, f"audit_log_available={log.audit_log_available}; complete={complete}", "Audit trail is partial.", "incomplete audit trail")
    return RuleResult(5, "Audit trail", 0, "No audit log flag and incomplete entries.", "Actions cannot be reliably reconstructed.", "missing audit trail")


def rule_6(log: AgentLog) -> RuleResult:
    parsed = [_parse_ts(m.timestamp) for m in log.messages]
    bad = [i for i, ts in enumerate(parsed, 1) if ts is None]
    if bad:
        return RuleResult(6, "Chain of custody", 0, f"Invalid timestamps: {_msg_ids(bad)}", "Timeline cannot be reconstructed.", "broken chain of custody")
    ordered = all(parsed[i] <= parsed[i + 1] for i in range(len(parsed) - 1))
    if ordered:
        return RuleResult(6, "Chain of custody", 2, f"SHA-256: {log.sha256[:16]}…; timestamps are chronological.", "The file hash and timeline support basic reconstruction.")
    return RuleResult(6, "Chain of custody", 1, f"SHA-256: {log.sha256[:16]}…; timestamps are not ordered.", "Timeline exists but is inconsistent.", "timeline inconsistency")


def rule_7(log: AgentLog) -> RuleResult:
    relevant = [i for i, m in enumerate(log.messages, 1) if LEVEL_ORDER[action_class(m)] >= LEVEL_ORDER["high"]]
    if not relevant:
        return RuleResult(7, "Human escalation", 2, "No high/critical action detected.", "Escalation was not required.")
    if escalation_present(log):
        return RuleResult(7, "Human escalation", 2, f"High/critical actions: {_msg_ids(relevant)}; escalation present.", "Escalation path was available or used.")
    if any(mentions_contact_channel(m) for m in log.messages):
        return RuleResult(7, "Human escalation", 1, f"High/critical actions: {_msg_ids(relevant)}; contact channel mentioned.", "Contact exists but escalation is not explicit.", "weak escalation path")
    return RuleResult(7, "Human escalation", 0, f"High/critical actions: {_msg_ids(relevant)}", "No escalation path exists for sensitive actions.", "missing escalation")


def rule_8(log: AgentLog) -> RuleResult:
    major, minor = [], []
    for i, m in enumerate(log.messages, 1):
        sensitive = [d for d in m.data_accessed if d.lower() in SENSITIVE_DATA]
        if sensitive:
            major.append(i)
        elif len(m.data_accessed) > 3:
            minor.append(i)
    if not major and not minor:
        return RuleResult(8, "Data minimization", 2, "No excessive data access detected.", "Accessed data appears proportionate to the action.")
    if not major:
        return RuleResult(8, "Data minimization", 1, f"Broad data access in messages: {_msg_ids(minor)}", "Some access may be broader than necessary.", "possible data minimization issue")
    return RuleResult(8, "Data minimization", 0, f"Sensitive data accessed in messages: {_msg_ids(major)}", "Sensitive data access requires stronger justification.", "data minimization failure")


def rule_9(log: AgentLog) -> RuleResult:
    hits = [(i, reserved_hits(m)) for i, m in enumerate(log.messages, 1) if reserved_hits(m)]
    if not hits:
        return RuleResult(9, "Reserved activity guardrail", 2, "No legal/medical/tax advice markers detected.", "Agent does not appear to perform reserved professional activities.")
    approved = [i for i, m in enumerate(log.messages, 1) if reserved_hits(m) and m.human_approved]
    if approved:
        return RuleResult(9, "Reserved activity guardrail", 1, f"Reserved-risk messages: {_msg_ids([i for i, _ in hits])}; approved: {_msg_ids(approved)}", "Reserved-risk activity exists and needs strict human review.", "reserved activity risk")
    return RuleResult(9, "Reserved activity guardrail", 0, f"Reserved-risk messages: {_msg_ids([i for i, _ in hits])}", "Agent may be giving professional advice or making legal representations autonomously.", "reserved activity without approval")


def rule_10(log: AgentLog) -> RuleResult:
    good = [i for i, m in enumerate(log.messages, 1) if is_disclosed(m) and log.operator and mentions_contact_channel(m)]
    if len(good) == len(log.messages):
        return RuleResult(10, "Complete disclosure notice", 2, f"Complete notices: {_msg_ids(good)}", "Every message includes AI status, operator, and human contact route.")
    if good:
        return RuleResult(10, "Complete disclosure notice", 1, f"Complete notices: {_msg_ids(good)}", "Only some messages contain a full disclosure notice.", "incomplete disclosure notice")
    return RuleResult(10, "Complete disclosure notice", 0, "No message contains a full disclosure notice.", "The disclosure notice lacks required elements.", "missing complete disclosure notice")

RULES: list[Callable[[AgentLog], RuleResult]] = [rule_1, rule_2, rule_3, rule_4, rule_5, rule_6, rule_7, rule_8, rule_9, rule_10]


def analyze(log: AgentLog) -> AuditResult:
    rules = [rule(log) for rule in RULES]
    total = sum(rule.points for rule in rules)
    gaps = [rule.gap_label for rule in rules if rule.gap_label]
    message_risks = classify_messages(log, total)
    return AuditResult(log=log, rules=rules, total=total, max_total=20, gaps=gaps, message_risks=message_risks, overall=overall_risk(message_risks))


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python -m agent.analyzer path/to/log.json")
        raise SystemExit(2)
    result = analyze(parse_log_file(sys.argv[1]))
    print(f"Score: {result.total}/{result.max_total} | overall risk: {result.overall.upper()}")
    for rule in result.rules:
        print(f"{rule.number}. {rule.name}: {rule.points}/2 — {rule.justification}")
