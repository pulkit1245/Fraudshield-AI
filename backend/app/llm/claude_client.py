"""Claude API client — agentic tool-use loop + tiered model selection.

Wraps the Anthropic Messages API. Exposes:
  - `is_available`      : True only if the SDK is importable and a key is set.
  - `choose_model()`    : fast model for triage, stronger model above a risk cut.
  - `run_agentic_loop()`: multi-turn tool-use loop (tools query findings + TTP KB).
  - `classify_json()`   : one-shot call parsed into a JSON object (tier-2 sanitizer).

The SDK import is lazy so the module loads with anthropic uninstalled; callers
check `is_available` and fall back to deterministic templates when it's False
(keeps the demo alive if the API is unset or rate-limited, per §10 fallbacks).

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Tiered models (§2: fast triage, escalate on high risk).
FAST_MODEL = "claude-haiku-4-5-20251001"
STRONG_MODEL = "claude-sonnet-5"
ESCALATE_RISK_THRESHOLD = 0.6


def get_analysis_tools() -> list[dict]:
    """Anthropic tool schemas the agent can call during report generation."""
    return [
        {
            "name": "get_static_findings",
            "description": "Return sanitized static-analysis findings (permissions, "
                           "certificate, sensitive API calls, obfuscation score).",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "get_dynamic_findings",
            "description": "Return sanitized dynamic-sandbox findings (SMS access, "
                           "accessibility abuse, overlay detection, network calls).",
            "input_schema": {"type": "object", "properties": {}},
        },
        {
            "name": "search_ttp_knowledge_base",
            "description": "Semantic search over the banking-fraud TTP taxonomy.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "What to look up."},
                    "k": {"type": "integer", "description": "Number of entries (1-5)."},
                },
                "required": ["query"],
            },
        },
    ]


class ClaudeClient:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.CLAUDE_API_KEY
        self._client = None
        self._init_error: str | None = None
        if self.api_key:
            try:
                import anthropic

                self._client = anthropic.Anthropic(api_key=self.api_key)
            except Exception as exc:  # noqa: BLE001
                self._init_error = str(exc)
                log.debug("claude.init_failed", error=str(exc))

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def choose_model(self, risk_score: float | None) -> str:
        if risk_score is not None and risk_score >= ESCALATE_RISK_THRESHOLD:
            return STRONG_MODEL
        return FAST_MODEL

    # ── one-shot JSON classification (sanitizer tier 2) ─────────────────
    def classify_json(self, *, system: str, messages: list[dict],
                      model: str | None = None, max_tokens: int = 256) -> dict | None:
        if not self.is_available:
            return None
        try:
            resp = self._client.messages.create(
                model=model or FAST_MODEL,
                system=system,
                messages=messages,
                max_tokens=max_tokens,
            )
            return _extract_json(_text_of(resp))
        except Exception as exc:  # noqa: BLE001
            log.warning("claude.classify_failed", error=str(exc))
            return None

    # ── agentic tool-use loop ───────────────────────────────────────────
    def run_agentic_loop(self, *, system: str, user_prompt: str, tools: list[dict],
                         tool_dispatch: Callable[[str, dict], Any],
                         model: str | None = None, max_tokens: int = 2000,
                         max_iters: int = 5) -> dict[str, Any]:
        """Run a bounded tool-use loop and return {text, tokens, model, iterations}."""
        if not self.is_available:
            raise RuntimeError("Claude client unavailable (no SDK or API key)")

        model = model or FAST_MODEL
        messages: list[dict] = [{"role": "user", "content": user_prompt}]
        total_tokens = 0

        for iteration in range(max_iters):
            resp = self._client.messages.create(
                model=model, system=system, tools=tools,
                messages=messages, max_tokens=max_tokens,
            )
            total_tokens += _tokens_of(resp)

            if resp.stop_reason != "tool_use":
                return {
                    "text": _text_of(resp),
                    "tokens": total_tokens,
                    "model": model,
                    "iterations": iteration + 1,
                }

            # Execute each requested tool and feed results back.
            messages.append({"role": "assistant", "content": resp.content})
            tool_results = []
            for block in resp.content:
                if getattr(block, "type", None) == "tool_use":
                    try:
                        output = tool_dispatch(block.name, block.input or {})
                    except Exception as exc:  # noqa: BLE001
                        output = {"error": str(exc)}
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(output, default=str),
                    })
            messages.append({"role": "user", "content": tool_results})

        return {"text": _text_of(resp), "tokens": total_tokens,
                "model": model, "iterations": max_iters}


# ── response helpers (SDK-shape tolerant) ───────────────────────────────
def _text_of(resp: Any) -> str:
    parts = []
    for block in getattr(resp, "content", []) or []:
        if getattr(block, "type", None) == "text":
            parts.append(block.text)
    return "\n".join(parts).strip()


def _tokens_of(resp: Any) -> int:
    usage = getattr(resp, "usage", None)
    if not usage:
        return 0
    return int(getattr(usage, "input_tokens", 0)) + int(getattr(usage, "output_tokens", 0))


def _extract_json(text: str) -> dict | None:
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                return json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return None
    return None
