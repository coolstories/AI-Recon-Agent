import os
import json
import time
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

_client = None


class LLMStreamError(Exception):
    """Base error for LLM stream failures."""


class LLMStreamTimeoutError(LLMStreamError):
    """Raised when a streamed LLM response times out."""


class LLMStreamRetriesExhaustedError(LLMStreamTimeoutError):
    """Raised when timeout retries are exhausted."""


def get_client():
    global _client
    if _client is not None:
        return _client
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError("OPENROUTER_API_KEY not set in .env file")
    _client = OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    return _client


def get_model():
    return os.getenv("OPENROUTER_MODEL", "anthropic/claude-sonnet-4.6")


def _env_int(name, default_value, min_value, max_value):
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return default_value
    try:
        parsed = int(raw)
    except Exception:
        return default_value
    if parsed < min_value:
        return min_value
    if parsed > max_value:
        return max_value
    return parsed


def get_llm_stream_timeout_sec():
    return _env_int("LLM_STREAM_TIMEOUT_SEC", 90, 10, 600)


def get_llm_stream_max_retries():
    return _env_int("LLM_STREAM_MAX_RETRIES", 1, 0, 5)


def _is_timeout_exception(exc):
    text = f"{exc.__class__.__name__}: {exc}".lower()
    markers = (
        "timeout", "timed out", "readtimeout", "connecttimeout",
        "deadline exceeded", "stream timed out",
    )
    return any(marker in text for marker in markers)


def chat_completion_stream(messages, tools=None, model=None):
    """Stream a chat completion. Yields delta chunks as they arrive.
    Returns a dict with the fully assembled message once the stream ends.
    """
    client = get_client()
    model = model or get_model()
    timeout_sec = get_llm_stream_timeout_sec()
    max_retries = get_llm_stream_max_retries()
    attempts = max_retries + 1

    base_kwargs = {
        "model": model,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 16000,
        "stream": True,
        "timeout": timeout_sec,
    }
    if tools:
        base_kwargs["tools"] = tools
        base_kwargs["tool_choice"] = "auto"

    last_timeout_error = None
    for attempt in range(attempts):
        content_parts = []
        tool_calls_map = {}  # index -> {id, function_name, arguments_parts}
        emitted_any_delta = False
        try:
            stream = client.chat.completions.create(**base_kwargs)

            for chunk in stream:
                delta = chunk.choices[0].delta if chunk.choices else None
                if delta is None:
                    continue

                finish_reason = chunk.choices[0].finish_reason

                # Stream text content
                if delta.content:
                    emitted_any_delta = True
                    content_parts.append(delta.content)
                    yield {"type": "content_delta", "text": delta.content}

                # Stream tool call deltas
                if delta.tool_calls:
                    emitted_any_delta = True
                    for tc_delta in delta.tool_calls:
                        idx = tc_delta.index
                        if idx not in tool_calls_map:
                            tool_calls_map[idx] = {
                                "id": tc_delta.id or "",
                                "function_name": "",
                                "arguments_parts": [],
                            }
                        if tc_delta.id:
                            tool_calls_map[idx]["id"] = tc_delta.id
                        if tc_delta.function:
                            if tc_delta.function.name:
                                tool_calls_map[idx]["function_name"] = tc_delta.function.name
                                yield {"type": "tool_call_start", "index": idx, "name": tc_delta.function.name}
                            if tc_delta.function.arguments:
                                tool_calls_map[idx]["arguments_parts"].append(tc_delta.function.arguments)
                                yield {"type": "tool_call_args_delta", "index": idx, "text": tc_delta.function.arguments}

                if finish_reason:
                    break

            # Assemble final message
            full_content = "".join(content_parts)
            assembled_tool_calls = None
            if tool_calls_map:
                assembled_tool_calls = []
                for idx in sorted(tool_calls_map.keys()):
                    tc = tool_calls_map[idx]
                    assembled_tool_calls.append({
                        "id": tc["id"],
                        "type": "function",
                        "function": {
                            "name": tc["function_name"],
                            "arguments": "".join(tc["arguments_parts"]),
                        }
                    })

            yield {
                "type": "done",
                "content": full_content,
                "tool_calls": assembled_tool_calls,
            }
            return
        except Exception as exc:
            if not _is_timeout_exception(exc):
                raise

            last_timeout_error = exc
            retries_left = (attempts - 1) - attempt
            # If we've already streamed partial output in this attempt, avoid retrying and
            # fail fast to prevent duplicate deltas.
            if emitted_any_delta:
                raise LLMStreamTimeoutError(
                    f"LLM stream timed out after partial output (timeout={timeout_sec}s): {exc}"
                ) from exc

            if retries_left <= 0:
                break
            time.sleep(min(2.0, 0.5 * (attempt + 1)))

    if last_timeout_error is None:
        raise LLMStreamRetriesExhaustedError(
            "LLM stream failed with timeout-like behavior and no concrete exception was captured."
        )
    raise LLMStreamRetriesExhaustedError(
        f"LLM stream timed out after {attempts} attempt(s) (timeout={timeout_sec}s): {last_timeout_error}"
    ) from last_timeout_error
