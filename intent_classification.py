from __future__ import annotations

from typing import Literal

IntentClass = Literal[
    "DATA_ACCESS",
    "DATA_EXPORT",
    "COMMUNICATION",
    "PAYMENT",
    "TRADE",
    "SYSTEM_MODIFICATION",
    "AUTHORIZATION",
    "UNKNOWN",
]


def classify_intent(tool_name: str, intent: str) -> IntentClass:
    text = f"{tool_name} {intent}".lower()
    if any(k in text for k in ["query", "read", "lookup", "fetch"]):
        return "DATA_ACCESS"
    if any(k in text for k in ["export", "download", "dump"]):
        return "DATA_EXPORT"
    if any(k in text for k in ["email", "message", "post", "notify"]):
        return "COMMUNICATION"
    if any(k in text for k in ["payment", "invoice", "charge", "transfer"]):
        return "PAYMENT"
    if any(k in text for k in ["trade", "order", "buy", "sell"]):
        return "TRADE"
    if any(k in text for k in ["deploy", "config", "modify", "delete", "restart"]):
        return "SYSTEM_MODIFICATION"
    if any(k in text for k in ["authorize", "approval", "token", "grant"]):
        return "AUTHORIZATION"
    return "UNKNOWN"
