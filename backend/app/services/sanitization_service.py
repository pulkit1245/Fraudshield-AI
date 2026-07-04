"""Adversarial sanitization layer — the "AI Evasion Defense" differentiator.

Every string extracted by static/dynamic analysis passes through here BEFORE it
can reach the primary reasoning LLM. Two tiers:

  Tier 1 — fast regex/heuristic pass for obvious prompt-injection markers.
  Tier 2 — (optional) a cheap Claude classification call for ambiguous strings.

Flagged strings are replaced with a redaction placeholder and recorded as
`sanitization_flags` (persisted onto `llm_reports`), never passed through
verbatim. Tier 1 alone is deterministic and offline, so the pipeline is safe even
with no API key / network.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.core.logging import get_logger
from app.llm.prompts.sanitization_prompt import REDACTION_PLACEHOLDER

log = get_logger(__name__)

# (compiled pattern, category). Case-insensitive. Ordered by specificity.
_RAW_PATTERNS: list[tuple[str, str]] = [
    (r"ignore\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|preceding|earlier)\s+"
     r"(?:instruction|prompt|message|context|rule)", "instruction_override"),
    (r"disregard\s+(?:all\s+|the\s+)?(?:previous|above|prior|earlier|foregoing|following)",
     "instruction_override"),
    (r"forget\s+(?:all\s+|everything\s+)?(?:that\s+|you\s+|your\s+|the\s+)?"
     r"(?:previous\s+)?(?:instruction|rule|context|prompt|above)", "instruction_override"),
    (r"(?:new|updated|revised|real)\s+instructions?\s*:", "instruction_override"),
    (r"override\s+(?:the\s+)?(?:previous|system|your|all)\b", "instruction_override"),
    (r"do\s+not\s+(?:follow|obey|adhere\s+to|comply)\b", "instruction_override"),
    # Fake conversation roles / control tokens.
    (r"(?m)^\s*(?:system|assistant|developer)\s*:", "role_injection"),
    (r"\[/?(?:INST|SYS|SYSTEM|system)\]", "role_injection"),
    (r"<\|(?:im_start|im_end|system|assistant|user)\|>", "role_injection"),
    (r"###\s*(?:system|instruction|role)", "role_injection"),
    # Persona / jailbreak.
    (r"you\s+are\s+now\s+(?:a|an|the|in)\b", "persona_hijack"),
    (r"\bact\s+as\s+(?:a|an|the|if)\b", "persona_hijack"),
    (r"\bpretend\s+to\s+be\b", "persona_hijack"),
    (r"\b(?:jailbreak|developer\s+mode|DAN\s+mode|do\s+anything\s+now)\b", "jailbreak"),
    (r"bypass\s+(?:the\s+)?(?:filter|safety|guard|rule|restriction|content)", "jailbreak"),
    # Prompt / secret exfiltration.
    (r"(?:reveal|print|repeat|show|leak|expose|reprint|output)\s+(?:your\s+|the\s+)?"
     r"(?:system\s+)?(?:prompt|instructions?)", "exfiltration"),
    (r"what\s+(?:were|are)\s+your\s+(?:original\s+)?instructions", "exfiltration"),
    (r"repeat\s+(?:the\s+)?(?:words|text)\s+above", "exfiltration"),
    (r"\bprompt\s+injection\b", "meta"),
]

_COMPILED: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), cat) for p, cat in _RAW_PATTERNS
]

_MAX_SNIPPET = 160


@dataclass
class SanitizationResult:
    clean_values: list[str] = field(default_factory=list)
    flags: list[dict[str, Any]] = field(default_factory=list)

    @property
    def had_injection(self) -> bool:
        return bool(self.flags)


class SanitizationService:
    def __init__(self, enable_llm_tier: bool = False) -> None:
        # Tier 2 is opt-in; tier 1 is always on and fully offline.
        self.enable_llm_tier = enable_llm_tier

    # ── tier 1 ──────────────────────────────────────────────────────────
    def _regex_match(self, text: str) -> str | None:
        for pattern, category in _COMPILED:
            if pattern.search(text):
                return category
        return None

    # ── tier 2 (optional) ───────────────────────────────────────────────
    def _llm_match(self, text: str) -> str | None:
        try:
            from app.llm.claude_client import ClaudeClient
            from app.llm.prompts.sanitization_prompt import (
                SANITIZATION_SYSTEM_PROMPT,
                build_classification_messages,
            )

            client = ClaudeClient()
            if not client.is_available:
                return None
            data = client.classify_json(
                system=SANITIZATION_SYSTEM_PROMPT,
                messages=build_classification_messages(text),
            )
            if data and data.get("is_injection"):
                return str(data.get("category") or "llm_flagged")
        except Exception as exc:  # noqa: BLE001
            log.debug("sanitization.llm_tier_skipped", error=str(exc))
        return None

    # ── public API ──────────────────────────────────────────────────────
    def is_injection(self, text: str) -> tuple[bool, str | None, str | None]:
        """Return (flagged, category, tier)."""
        if not text or not text.strip():
            return False, None, None
        category = self._regex_match(text)
        if category:
            return True, category, "regex"
        if self.enable_llm_tier and self._is_ambiguous(text):
            category = self._llm_match(text)
            if category:
                return True, category, "llm"
        return False, None, None

    def _is_ambiguous(self, text: str) -> bool:
        """Only spend a tier-2 call on strings that smell instruction-like."""
        lowered = text.lower()
        soft_markers = ("instruction", "prompt", "system", "assistant",
                        "you should", "you must", "please ignore", "respond with")
        return len(text) > 20 and any(m in lowered for m in soft_markers)

    def sanitize_value(self, text: str) -> tuple[str, dict | None]:
        flagged, category, tier = self.is_injection(text)
        if not flagged:
            return text, None
        flag = {
            "category": category,
            "tier": tier,
            "snippet": text[:_MAX_SNIPPET],
            "length": len(text),
        }
        return REDACTION_PLACEHOLDER, flag

    def sanitize_strings(self, values: list[str]) -> SanitizationResult:
        result = SanitizationResult()
        for value in values:
            clean, flag = self.sanitize_value(str(value))
            result.clean_values.append(clean)
            if flag:
                result.flags.append(flag)
        if result.flags:
            log.info("sanitization.flagged", count=len(result.flags))
        return result

    def sanitize_findings(self, findings: dict[str, Any]) -> tuple[dict[str, Any], list[dict]]:
        """Recursively sanitize every string in a findings dict.

        Returns (sanitized_copy, flags). Keys are never treated as untrusted;
        only string *values* are screened.
        """
        flags: list[dict] = []

        def _walk(node: Any) -> Any:
            if isinstance(node, str):
                clean, flag = self.sanitize_value(node)
                if flag:
                    flags.append(flag)
                return clean
            if isinstance(node, list):
                return [_walk(v) for v in node]
            if isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            return node

        sanitized = _walk(findings)
        return sanitized, flags


# Module-level default instance (tier 1 only).
default_sanitizer = SanitizationService(enable_llm_tier=False)
