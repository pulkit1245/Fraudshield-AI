"""Groq API client — drop-in replacement for GeminiClient.

Exposes the same interface as gemini_client.py so LLMOrchestrationService
can swap providers by changing one import:
  - `is_available`      : True when SDK is installed and key is set.
  - `choose_model()`    : llama-3.3-70b for triage, llama-3.3-70b for high-risk.
  - `classify_json()`   : one-shot JSON call (sanitizer tier-2).
  - `run_agentic_loop()`: multi-turn function-calling loop.

Owner: Member B — AI/ML Engineer.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

# Groq models — fast and capable
FAST_MODEL   = "llama-3.3-70b-versatile"
STRONG_MODEL = "llama-3.3-70b-versatile"
ESCALATE_RISK_THRESHOLD = 0.6


class GroqClient:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.GROQ_API_KEY
        self._client = None
        self._init_error: str | None = None
        if self.api_key:
            try:
                from groq import Groq  # noqa: WPS433
                self._client = Groq(api_key=self.api_key)
                log.info("groq.init_ok", model=FAST_MODEL)
            except Exception as exc:  # noqa: BLE001
                self._init_error = str(exc)
                log.warning("groq.init_failed", error=str(exc))

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def choose_model(self, risk_score: float | None) -> str:
        if risk_score is not None and risk_score >= ESCALATE_RISK_THRESHOLD:
            return STRONG_MODEL
        return FAST_MODEL

    # ── one-shot JSON classification ────────────────────────────────────
    def classify_json(self, *, system: str, messages: list[dict],
                      model: str | None = None, max_tokens: int = 1024) -> dict | None:
        if not self.is_available:
            log.warning("groq.classify_json.unavailable", init_error=self._init_error)
            return None
        try:
            groq_messages = [{"role": "system", "content": system}]
            for msg in messages:
                content = msg.get("content", "")
                if not isinstance(content, str):
                    content = json.dumps(content)
                groq_messages.append({"role": msg.get("role", "user"), "content": content})

            resp = self._client.chat.completions.create(
                model=model or FAST_MODEL,
                messages=groq_messages,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
            text = resp.choices[0].message.content or ""
            return _extract_json(text)
        except Exception as exc:  # noqa: BLE001
            log.warning("groq.classify_json.failed", error=str(exc))
            return None

    # ── agentic function-calling loop ───────────────────────────────────
    def run_agentic_loop(self, *, system: str, user_prompt: str,
                         tools: list[dict],
                         tool_dispatch: Callable[[str, dict], Any],
                         model: str | None = None, max_tokens: int = 2000,
                         max_iters: int = 5) -> dict[str, Any]:
        """Run a bounded tool-calling loop; return {text, tokens, model, iterations}."""
        if not self.is_available:
            raise RuntimeError(
                f"Groq client unavailable — SDK not installed or API key missing. "
                f"Init error: {self._init_error}"
            )

        model_name = model or FAST_MODEL
        groq_tools = _tools_to_groq(tools)

        messages: list[dict] = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_prompt},
        ]
        total_tokens = 0

        for iteration in range(max_iters):
            # Only pass tools/tool_choice when tools are actually provided.
            # Groq rejects tool_choice=None — it must be absent, not null.
            extra: dict = {}
            if groq_tools:
                extra["tools"] = groq_tools
                extra["tool_choice"] = "auto"

            resp = self._client.chat.completions.create(
                model=model_name,
                messages=messages,
                max_tokens=max_tokens,
                **extra,
            )
            choice = resp.choices[0]
            total_tokens += (resp.usage.total_tokens if resp.usage else 0)

            # Append assistant message to history
            messages.append({"role": "assistant", "content": choice.message.content or "",
                              **({"tool_calls": [
                                  {
                                      "id": tc.id,
                                      "type": "function",
                                      "function": {"name": tc.function.name,
                                                   "arguments": tc.function.arguments},
                                  }
                                  for tc in (choice.message.tool_calls or [])
                              ]} if choice.message.tool_calls else {})})

            tool_calls = choice.message.tool_calls or []
            if not tool_calls:
                # No tool calls — final answer
                return {
                    "text": choice.message.content or "",
                    "tokens": total_tokens,
                    "model": model_name,
                    "iterations": iteration + 1,
                }

            # Execute tools and feed results back
            for tc in tool_calls:
                fn_name = tc.function.name
                try:
                    fn_args = json.loads(tc.function.arguments or "{}")
                    output = tool_dispatch(fn_name, fn_args)
                except Exception as exc:  # noqa: BLE001
                    output = {"error": str(exc)}
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(output, default=str),
                })

        return {
            "text": choice.message.content or "",
            "tokens": total_tokens,
            "model": model_name,
            "iterations": max_iters,
        }


# ── helpers ──────────────────────────────────────────────────────────────

def _tools_to_groq(tools: list[dict]) -> list[dict]:
    """Convert Anthropic-style tool schemas → Groq/OpenAI tool format."""
    result = []
    for t in tools:
        result.append({
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        })
    return result


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
