"""Risk classification helpers for LexEvidence Disclosure Agent."""

from __future__ import annotations

from dataclasses import dataclass

from agent.parser import AgentLog, Message

LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
LEVEL_LABELS = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
LEVEL_DOTS = {"low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}
CLASS_LABELS = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}

AI_MARKERS = ["ai", "artificial intelligence", "automated", "bot", "virtual assistant", "system ai", "agent ai"]
CONTACT_MARKERS = ["human", "człowiek", "contact", "kontakt", "operator", "support", "supervisor", "person"]
ESCALATION_MARKERS = ["escalated", "escalation", "przekazano", "człowiek", "human review", "supervisor"]
RESERVED_MARKERS = [
    "legal advice", "porada prawna", "lawsuit", "pozew", "court", "sąd", "binding decision",
    "medical advice", "diagnosis", "diagnoza", "tax advice", "oświadczenie woli",
]
SENSITIVE_DATA = ["health", "medical", "diagnosis", "pesel", "id_number", "legal_case", "case_file", "salary"]
BASIC_DATA = ["email", "name", "order_history", "order_id", "calendar", "customer_email", "ticket_id"]

ACTION_CLASS = {
    "schedule_meeting": "low",
    "status_update": "low",
    "customer_support": "medium",
    "complaint_handling": "medium",
    "discount_negotiation": "high",
    "price_negotiation": "high",
    "legal_advice": "critical",
    "medical_advice": "critical",
    "binding_commitment": "critical",
}

@dataclass
class MessageRisk:
    index: int
    excerpt: str
    action_cls: str
    level: str
    reasons: list[str]


def normalize(text: str | None) -> str:
    return (text or "").lower().strip()


def normalize_token(text: str | None) -> str:
    return normalize(text).replace(" ", "_").replace("-", "_")


def _haystack(message: Message) -> str:
    return f"{message.message} {message.disclosure_note or ''} {message.action_type} {message.risk_context}".lower()


def is_disclosed(message: Message) -> bool:
    haystack = _haystack(message)
    return bool(message.disclosure_note) and any(marker in haystack for marker in AI_MARKERS)


def has_disclaimer(message: Message) -> bool:
    haystack = _haystack(message)
    return any(marker in haystack for marker in ["not legal advice", "nie jest poradą", "requires human review"])


def mentions_contact_channel(message: Message) -> bool:
    haystack = _haystack(message)
    return any(marker in haystack for marker in CONTACT_MARKERS)


def escalation_present(log: AgentLog) -> bool:
    return any(any(marker in _haystack(msg) for marker in ESCALATION_MARKERS) for msg in log.messages)


def reserved_hits(message: Message) -> list[str]:
    haystack = _haystack(message)
    return [marker for marker in RESERVED_MARKERS if marker in haystack]


def action_class(message: Message) -> str:
    token = normalize_token(message.action_type)
    if token in ACTION_CLASS:
        return ACTION_CLASS[token]
    if reserved_hits(message):
        return "critical"
    if "negoti" in token or "discount" in token or "price" in token or "rabat" in token:
        return "high"
    if "complaint" in token or "support" in token or "reklamac" in token:
        return "medium"
    return "low"


def classify_message(message: Message, index: int, compliance_score: int) -> MessageRisk:
    cls = action_class(message)
    reasons: list[str] = []
    level = cls

    if not is_disclosed(message):
        reasons.append("missing AI disclosure")
    if LEVEL_ORDER[cls] >= LEVEL_ORDER["medium"] and not message.human_approved:
        reasons.append("missing human approval")
        level = max(level, "high", key=lambda x: LEVEL_ORDER[x])
    if reserved_hits(message):
        reasons.append("reserved/professional advice risk")
        level = "critical"
    elif compliance_score < 8 and LEVEL_ORDER[level] < LEVEL_ORDER["high"]:
        level = "high"
    elif compliance_score < 14 and LEVEL_ORDER[level] < LEVEL_ORDER["medium"]:
        level = "medium"

    excerpt = message.message[:110] + ("…" if len(message.message) > 110 else "")
    return MessageRisk(index=index, excerpt=excerpt, action_cls=cls, level=level, reasons=reasons)


def classify_messages(log: AgentLog, compliance_score: int) -> list[MessageRisk]:
    return [classify_message(msg, index, compliance_score) for index, msg in enumerate(log.messages, start=1)]


def overall_risk(message_risks: list[MessageRisk]) -> str:
    if not message_risks:
        return "low"
    return max((risk.level for risk in message_risks), key=lambda x: LEVEL_ORDER[x])
