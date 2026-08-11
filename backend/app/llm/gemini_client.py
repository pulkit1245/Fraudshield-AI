"""Gemini API client — drop-in replacement for ClaudeClient.

Exposes the same interface as claude_client.py so LLMOrchestrationService
can swap providers by changing one line:
  - `is_available`      : True when SDK is installed and key is set.
  - `choose_model()`    : flash for triage, pro for high-risk.
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

# Tiered Gemini models — flash for speed, pro for accuracy on high risk.
FAST_MODEL  = "gemini-3.5-flash"
STRONG_MODEL = "gemini-3.5-flash"  # Using flash for both to avoid free-tier Pro limits
ESCALATE_RISK_THRESHOLD = 0.6


class GeminiClient:
    def __init__(self, api_key: str | None = None) -> None:
        self.api_key = api_key or settings.GEMINI_API_KEY
        self._client = None
        self._init_error: str | None = None
        if self.api_key:
            try:
                import google.generativeai as genai  # noqa: WPS433
                genai.configure(api_key=self.api_key)
                self._genai = genai
                # Smoke-test that the SDK works.
                self._client = genai
            except Exception as exc:  # noqa: BLE001
                self._init_error = str(exc)
                log.debug("gemini.init_failed", error=str(exc))

    @property
    def is_available(self) -> bool:
        return self._client is not None

    def choose_model(self, risk_score: float | None) -> str:
        if risk_score is not None and risk_score >= ESCALATE_RISK_THRESHOLD:
            return STRONG_MODEL
        return FAST_MODEL

    # ── one-shot JSON classification ────────────────────────────────────
    def classify_json(self, *, system: str, messages: list[dict],
                      model: str | None = None, max_tokens: int = 256) -> dict | None:
        if not self.is_available:
            return None
        try:
            import google.generativeai as genai
            m = genai.GenerativeModel(
                model_name=model or FAST_MODEL,
                system_instruction=system,
            )
            # Flatten messages into a single prompt for one-shot calls.
            prompt = "\n".join(
                msg.get("content", "") if isinstance(msg.get("content"), str)
                else json.dumps(msg.get("content", ""))
                for msg in messages
            )
            resp = m.generate_content(
                prompt,
                generation_config={"max_output_tokens": max_tokens},
            )
            return _extract_json(resp.text)
        except Exception as exc:  # noqa: BLE001
            log.warning("gemini.classify_failed", error=str(exc))
            return None

    # ── agentic function-calling loop ───────────────────────────────────
    def run_agentic_loop(self, *, system: str, user_prompt: str,
                         tools: list[dict],
                         tool_dispatch: Callable[[str, dict], Any],
                         model: str | None = None, max_tokens: int = 2000,
                         max_iters: int = 5) -> dict[str, Any]:
        """Run a bounded function-calling loop and return {text, tokens, model, iterations}."""
        if not self.is_available:
            raise RuntimeError("Gemini client unavailable (no SDK or API key)")

        import google.generativeai as genai
        from google.generativeai.types import content_types

        model_name = model or FAST_MODEL
        # Convert Anthropic-style tool schemas → Gemini FunctionDeclaration list.
        gemini_tools = _tools_to_gemini(tools)

        m = genai.GenerativeModel(
            model_name=model_name,
            system_instruction=system,
            tools=gemini_tools,
        )
        chat = m.start_chat()
        total_tokens = 0

        for iteration in range(max_iters):
            resp = chat.send_message(
                user_prompt if iteration == 0 else "",
                generation_config={"max_output_tokens": max_tokens},
            )
            total_tokens += _tokens_of(resp)

            # Check if the model wants to call a function.
            fn_calls = _extract_function_calls(resp)
            if not fn_calls:
                return {
                    "text": resp.text if hasattr(resp, "text") else "",
                    "tokens": total_tokens,
                    "model": model_name,
                    "iterations": iteration + 1,
                }

            # Execute each function and feed the results back.
            function_responses = []
            for fn_name, fn_args in fn_calls:
                try:
                    output = tool_dispatch(fn_name, fn_args)
                except Exception as exc:  # noqa: BLE001
                    output = {"error": str(exc)}
                function_responses.append(
                    content_types.protos.Part(
                        function_response=content_types.protos.FunctionResponse(
                            name=fn_name,
                            response={"result": json.dumps(output, default=str)},
                        )
                    )
                )
            chat.send_message(function_responses)

        return {
            "text": resp.text if hasattr(resp, "text") else "",
            "tokens": total_tokens,
            "model": model_name,
            "iterations": max_iters,
        }


# ── helpers ──────────────────────────────────────────────────────────────

def _tools_to_gemini(tools: list[dict]) -> list:
    """Convert Anthropic-style tool schemas to Gemini FunctionDeclaration objects."""
    try:
        import google.generativeai as genai
        declarations = []
        for t in tools:
            schema = t.get("input_schema", {})
            declarations.append(
                genai.protos.FunctionDeclaration(
                    name=t["name"],
                    description=t.get("description", ""),
                    parameters=genai.protos.Schema(
                        type=genai.protos.Type.OBJECT,
                        properties={
                            k: genai.protos.Schema(type=genai.protos.Type.STRING)
                            for k in schema.get("properties", {})
                        },
                        required=schema.get("required", []),
                    ),
                )
            )
        return [genai.protos.Tool(function_declarations=declarations)]
    except Exception:  # noqa: BLE001
        return []


def _extract_function_calls(resp: Any) -> list[tuple[str, dict]]:
    """Pull function call name+args out of a Gemini response."""
    calls = []
    try:
        for part in resp.parts:
            fc = getattr(part, "function_call", None)
            if fc and fc.name:
                calls.append((fc.name, dict(fc.args) if fc.args else {}))
    except Exception:  # noqa: BLE001
        pass
    return calls


def _tokens_of(resp: Any) -> int:
    try:
        return getattr(resp.usage_metadata, "total_token_count", 0)
    except Exception:  # noqa: BLE001
        return 0


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
