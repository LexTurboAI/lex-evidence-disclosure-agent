"""Parser and validation for synthetic AI-agent activity logs."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


class LogValidationError(Exception):
    """Raised when an uploaded log cannot be safely parsed."""


@dataclass
class Message:
    timestamp: str
    message: str
    action_type: str = "other"
    risk_context: str = ""
    human_approved: bool = False
    disclosure_note: str | None = None
    tools_used: list[str] = field(default_factory=list)
    data_accessed: list[str] = field(default_factory=list)


@dataclass
class AgentLog:
    agent_name: str
    operator: str
    channel: str
    scope: str
    audit_log_available: bool
    messages: list[Message]
    source_filename: str = "log.json"
    sha256: str = ""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise LogValidationError(message)


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value == 1
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "tak", "1"}
    return False


def _as_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    _require(isinstance(value, list), f"Field '{field_name}' must be a list.")
    return [str(item) for item in value]


def parse_log(raw_bytes: bytes, filename: str = "log.json") -> AgentLog:
    _require(bool(raw_bytes), "The uploaded file is empty.")
    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError:
        raise LogValidationError("The file must be UTF-8 text.")
    except json.JSONDecodeError as exc:
        raise LogValidationError(f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.")

    _require(isinstance(payload, dict), "The JSON root must be an object.")
    for required in ["agent_name", "operator", "channel", "messages"]:
        _require(required in payload, f"Missing required top-level field: '{required}'.")

    raw_messages = payload["messages"]
    _require(isinstance(raw_messages, list) and raw_messages, "Field 'messages' must be a non-empty list.")

    messages: list[Message] = []
    for index, raw in enumerate(raw_messages, start=1):
        _require(isinstance(raw, dict), f"Message #{index} must be an object.")
        for required in ["timestamp", "message"]:
            _require(required in raw and str(raw[required]).strip(), f"Message #{index}: missing '{required}'.")

        note = raw.get("disclosure_note")
        messages.append(
            Message(
                timestamp=str(raw["timestamp"]).strip(),
                message=str(raw["message"]).strip(),
                action_type=str(raw.get("action_type", "other")).strip() or "other",
                risk_context=str(raw.get("risk_context", "")).strip(),
                human_approved=_as_bool(raw.get("human_approved", False)),
                disclosure_note=(str(note).strip() if note else None),
                tools_used=_as_list(raw.get("tools_used"), "tools_used"),
                data_accessed=_as_list(raw.get("data_accessed"), "data_accessed"),
            )
        )

    return AgentLog(
        agent_name=str(payload["agent_name"]).strip(),
        operator=str(payload["operator"]).strip(),
        channel=str(payload["channel"]).strip(),
        scope=str(payload.get("scope", "")).strip(),
        audit_log_available=_as_bool(payload.get("audit_log_available", False)),
        messages=messages,
        source_filename=filename,
        sha256=sha256,
    )


def parse_log_file(path: str) -> AgentLog:
    with open(path, "rb") as handle:
        return parse_log(handle.read(), filename=path.split("/")[-1])
