from __future__ import annotations

import json
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .prompts import prompt_snapshot
from .util import canonical_json, text_size


class LMStudioError(RuntimeError):
    pass


def json_protocol_instructions(tools: list[dict[str, Any]]) -> str:
    catalog = [{"name": item["name"], "description": item.get("description", ""),
                "parameters": item.get("parameters", {})} for item in tools]
    return """
The controller uses a strict JSON tool protocol because the local runner's
multi-turn native function-call template is not reliable. On every turn return
exactly one JSON object and no markdown or surrounding text. To request a tool:
{"action":"tool","name":"TOOL_NAME","arguments":{}}
To finish:
{"action":"final","content":FINAL_VALUE}
FINAL_VALUE must be the exact requested final answer: an object for a JSON task
or a string containing source code for a reconstruction task. Request only a
tool in the catalog below. After a tool result, either request another catalog
tool or finish. Never emit XML/tool-call tags.
Tool catalog:
""" + canonical_json(catalog) + "\n"


class LMStudioAdapter:
    def __init__(self, config: dict[str, Any], timeout: float,
                 redactions: list[str] | None = None):
        self.config = config
        self.timeout = timeout
        self.redactions = sorted((item for item in (redactions or []) if item),
                                 key=len, reverse=True)
        self.base_url: str | None = None
        self.model_metadata: dict[str, Any] | None = None
        self.last_request_attempts = 0

    def _redact_text(self, text: str) -> str:
        for item in self.redactions:
            text = text.replace(item, "<REDACTED_PATH>")
            text = text.replace(item.replace("\\", "/"), "<REDACTED_PATH>")
        return text

    def _sanitize(self, value: Any) -> Any:
        if isinstance(value, str): return self._redact_text(value)
        if isinstance(value, list): return [self._sanitize(item) for item in value]
        if isinstance(value, dict):
            return {key: self._sanitize(item) for key, item in value.items()
                    if key.lower() not in {"authorization", "api_key"}}
        return value

    def _request(self, method: str, path: str, payload: Any | None = None,
                 timeout: float | None = None) -> tuple[Any, dict[str, str], float]:
        if self.base_url is None:
            raise LMStudioError("base URL has not been selected")
        data = None if payload is None else canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
            headers={"Content-Type": "application/json"})
        started = time.perf_counter()
        last_error: Exception | None = None
        request_budget = timeout or self.timeout
        for attempt in range(1, 3):
            self.last_request_attempts = attempt
            remaining_budget = request_budget - (time.perf_counter() - started)
            if remaining_budget <= 0:
                raise LMStudioError("LM Studio request timed out")
            try:
                with urllib.request.urlopen(request, timeout=remaining_budget) as response:
                    raw = response.read().decode("utf-8", "replace")
                    return json.loads(raw), dict(response.headers), \
                        round((time.perf_counter() - started) * 1000, 3)
            except urllib.error.HTTPError as error:
                body = error.read().decode("utf-8", "replace")
                if error.code not in {502, 503, 504} or attempt == 2:
                    raise LMStudioError(f"LM Studio HTTP {error.code}: {body[:4000]}") from error
                last_error = error
            except (OSError, ValueError) as error:
                if attempt == 2:
                    raise LMStudioError(f"LM Studio request failed: {error}") from error
                last_error = error
            time.sleep(0.25)
        raise LMStudioError(f"LM Studio request failed: {last_error}")

    def probe(self) -> dict[str, Any]:
        errors: list[str] = []
        required = self.config["id"]
        for candidate in self.config["base_urls"]:
            self.base_url = candidate.rstrip("/")
            try:
                models, _, _ = self._request("GET", "/v1/models", timeout=5)
                identifiers = [item.get("id") for item in models.get("data", [])]
                if required not in identifiers:
                    errors.append(f"{candidate}: required model absent")
                    continue
                native, headers, elapsed = self._request("GET", "/api/v1/models", timeout=5)
                match = next((item for item in native.get("models", [])
                              if item.get("key") == required), None)
                self.model_metadata = {"selected_base_url": self.base_url,
                    "required_model": required, "openai_model_ids": identifiers,
                    "native_model": match, "response_headers": self._sanitize(headers),
                    "probe_elapsed_ms": elapsed, "transport_attempts": self.last_request_attempts}
                return self.model_metadata
            except LMStudioError as error:
                errors.append(f"{candidate}: {error}")
        self.base_url = None
        raise LMStudioError("no configured LM Studio endpoint has the required model: " +
                            "; ".join(errors))

    def native_chat_smoke(self) -> dict[str, Any]:
        payload = {"model": self.config["id"], "system_prompt": "Reply with OK only.",
                   "input": "Connectivity check", "temperature": 0,
                   "max_output_tokens": 64}
        response, headers, elapsed = self._request(
            "POST", self.config["native_chat_path"], payload)
        return {"request": self._sanitize(payload), "response": self._sanitize(response),
                "headers": self._sanitize(headers), "elapsed_ms": elapsed}

    @staticmethod
    def _text(response: dict[str, Any]) -> str:
        parts: list[str] = []
        for item in response.get("output", []):
            if item.get("type") != "message": continue
            for content in item.get("content", []):
                if content.get("type") == "output_text":
                    parts.append(content.get("text", ""))
        return "".join(parts).strip()

    def run_tools(self, instructions: str, user_input: str,
                  tools: list[dict[str, Any]], executor: Callable[[str, dict[str, Any]], str],
                  max_tool_calls: int, max_input_bytes: int = 120000) -> dict[str, Any]:
        if self.base_url is None:
            self.probe()
        requests: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        tool_events: list[dict[str, Any]] = []
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                 "reasoning_tokens": 0, "cached_tokens": 0}
        payload: dict[str, Any] = {"model": self.config["id"],
            "instructions": instructions, "input": user_input, "tools": tools,
            "tool_choice": "auto", "temperature": self.config["temperature"],
            "seed": self.config["seed"],
            "max_output_tokens": self.config["max_output_tokens"],
            "max_tool_calls": max_tool_calls, "parallel_tool_calls": False,
            "store": True}
        if self.config.get("reasoning") is not None:
            payload["reasoning"] = self.config["reasoning"]
        started = time.perf_counter()
        total_model_ms = 0.0
        executed_calls = 0
        response_turns = 0
        while True:
            response_turns += 1
            if response_turns > max_tool_calls + 2:
                raise LMStudioError("response-turn budget exhausted")
            payload_bytes = len(canonical_json(payload).encode("utf-8"))
            if payload_bytes > max_input_bytes:
                raise LMStudioError(
                    f"request envelope exceeds input byte budget: {payload_bytes}>{max_input_bytes}")
            remaining = self.timeout - (time.perf_counter() - started)
            if remaining <= 0:
                raise LMStudioError("task wall-clock budget exhausted")
            requests.append(self._sanitize(payload))
            response, headers, elapsed = self._request(
                "POST", self.config["responses_path"], payload,
                timeout=max(1, remaining))
            requests[-1]["_transport_attempts"] = self.last_request_attempts
            requests[-1]["_utf8_bytes"] = payload_bytes
            total_model_ms += elapsed
            responses.append(self._sanitize(response))
            current = response.get("usage") or {}
            usage["input_tokens"] += int(current.get("input_tokens") or 0)
            usage["output_tokens"] += int(current.get("output_tokens") or 0)
            usage["total_tokens"] += int(current.get("total_tokens") or 0)
            usage["reasoning_tokens"] += int(
                (current.get("output_tokens_details") or {}).get("reasoning_tokens") or 0)
            usage["cached_tokens"] += int(
                (current.get("input_tokens_details") or {}).get("cached_tokens") or 0)
            if response.get("status") not in {"completed", "incomplete"}:
                raise LMStudioError(f"tool response failed: {response.get('error')}")
            calls = [item for item in response.get("output", [])
                     if item.get("type") == "function_call"]
            if not calls:
                final = self._text(response)
                return {"final_text": final, "usage": usage,
                        "requests": requests, "responses": responses,
                        "tool_events": tool_events, "model_elapsed_ms": total_model_ms,
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                        "final_size": text_size(final), "response_headers": self._sanitize(headers)}
            outputs: list[dict[str, Any]] = []
            for call in calls:
                arguments: dict[str, Any] = {}
                if executed_calls >= max_tool_calls:
                    result = canonical_json({"ok": False, "error": "tool-call budget exhausted"})
                    tool_events.append({"name": call.get("name"), "arguments": {},
                        "executed": False, "result": result, "result_size": text_size(result)})
                else:
                    try:
                        arguments = json.loads(call.get("arguments") or "{}")
                        if not isinstance(arguments, dict):
                            raise ValueError("arguments must be an object")
                        result = executor(str(call.get("name")), arguments)
                    except (ValueError, TypeError, json.JSONDecodeError) as error:
                        arguments = {}
                        result = canonical_json({"ok": False,
                            "error": f"malformed tool request: {error}"})
                    tool_events.append({"name": call.get("name"),
                        "arguments": self._sanitize(arguments), "executed": True,
                        "result": self._sanitize(result),
                        "result_size": text_size(result)})
                    executed_calls += 1
                outputs.append({"type": "function_call_output",
                                "call_id": call["call_id"], "output": result})
            exhausted = executed_calls >= max_tool_calls
            payload = {"model": self.config["id"],
                "previous_response_id": response["id"], "input": outputs,
                "temperature": self.config["temperature"], "seed": self.config["seed"],
                "max_output_tokens": self.config["max_output_tokens"],
                "store": True}
            # LM Studio persists the original tool definitions with the response.
            # Resending them on a stateful follow-up duplicates the tool-template
            # context and can exceed even an otherwise adequate context window.
            if exhausted:
                payload["tools"] = []
                payload["tool_choice"] = "none"
            if self.config.get("reasoning") is not None:
                payload["reasoning"] = self.config["reasoning"]

    @staticmethod
    def _protocol_object(text: str) -> dict[str, Any] | None:
        candidate = text.strip()
        if candidate.startswith("```"):
            candidate = candidate.split("\n", 1)[1] if "\n" in candidate else candidate
            if candidate.endswith("```"):
                candidate = candidate[:-3].rstrip()
        try:
            value = json.loads(candidate)
        except json.JSONDecodeError:
            start, end = candidate.find("{"), candidate.rfind("}")
            if start < 0 or end <= start:
                return None
            try:
                value = json.loads(candidate[start:end + 1])
            except json.JSONDecodeError:
                return None
        return value if isinstance(value, dict) else None

    def run_json_protocol(self, instructions: str, user_input: str,
                          tools: list[dict[str, Any]],
                          executor: Callable[[str, dict[str, Any]], str],
                          max_tool_calls: int,
                          max_input_bytes: int = 120000) -> dict[str, Any]:
        if self.base_url is None:
            self.probe()
        protocol = json_protocol_instructions(tools)
        full_instructions = instructions + "\n" + protocol
        requests: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        tool_events: list[dict[str, Any]] = []
        protocol_errors: list[str] = []
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                 "reasoning_tokens": 0, "cached_tokens": 0}
        payload: dict[str, Any] = {"model": self.config["id"],
            "instructions": full_instructions, "input": user_input,
            "temperature": self.config["temperature"], "seed": self.config["seed"],
            "max_output_tokens": self.config["max_output_tokens"], "store": True}
        if self.config.get("reasoning") is not None:
            payload["reasoning"] = self.config["reasoning"]
        started = time.perf_counter()
        total_model_ms = 0.0
        executed_calls = 0
        turns = 0
        while True:
            turns += 1
            if turns > max_tool_calls + 3:
                raise LMStudioError("JSON protocol turn budget exhausted")
            payload_bytes = len(canonical_json(payload).encode("utf-8"))
            if payload_bytes > max_input_bytes:
                raise LMStudioError(
                    f"request envelope exceeds input byte budget: {payload_bytes}>{max_input_bytes}")
            remaining = self.timeout - (time.perf_counter() - started)
            if remaining <= 0:
                raise LMStudioError("task wall-clock budget exhausted")
            requests.append(self._sanitize(payload))
            response, headers, elapsed = self._request(
                "POST", self.config["responses_path"], payload, timeout=max(1, remaining))
            requests[-1]["_transport_attempts"] = self.last_request_attempts
            requests[-1]["_utf8_bytes"] = payload_bytes
            total_model_ms += elapsed
            responses.append(self._sanitize(response))
            current = response.get("usage") or {}
            usage["input_tokens"] += int(current.get("input_tokens") or 0)
            usage["output_tokens"] += int(current.get("output_tokens") or 0)
            usage["total_tokens"] += int(current.get("total_tokens") or 0)
            usage["reasoning_tokens"] += int(
                (current.get("output_tokens_details") or {}).get("reasoning_tokens") or 0)
            usage["cached_tokens"] += int(
                (current.get("input_tokens_details") or {}).get("cached_tokens") or 0)
            if response.get("status") not in {"completed", "incomplete"}:
                raise LMStudioError(f"JSON protocol response failed: {response.get('error')}")
            raw = self._text(response)
            value = self._protocol_object(raw)
            if value is None or value.get("action") not in {"tool", "final"}:
                message = "malformed JSON protocol response"
                protocol_errors.append(message + ": " + raw[:1000])
                next_input: dict[str, Any] = {"protocol_error": message,
                    "required": {"action": "tool or final"},
                    "remaining_tool_calls": max_tool_calls - executed_calls}
            elif value["action"] == "final":
                content = value.get("content")
                final = content if isinstance(content, str) else canonical_json(content)
                return {"transport": "json-protocol", "final_text": final,
                    "usage": usage, "requests": requests, "responses": responses,
                    "tool_events": tool_events, "protocol_errors": protocol_errors,
                    "model_elapsed_ms": total_model_ms,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                    "final_size": text_size(final),
                    "response_headers": self._sanitize(headers),
                    "protocol_instructions": prompt_snapshot(protocol)}
            else:
                name = value.get("name")
                arguments = value.get("arguments")
                was_executed = False
                if not isinstance(name, str) or not isinstance(arguments, dict):
                    result = canonical_json({"ok": False,
                        "error": "malformed tool request: name string and arguments object required"})
                    normalized_arguments: dict[str, Any] = {}
                elif executed_calls >= max_tool_calls:
                    result = canonical_json({"ok": False, "error": "tool-call budget exhausted"})
                    normalized_arguments = arguments
                else:
                    normalized_arguments = arguments
                    result = executor(name, arguments)
                    executed_calls += 1
                    was_executed = True
                tool_events.append({"name": name, "arguments": self._sanitize(normalized_arguments),
                    "executed": was_executed,
                    "result": self._sanitize(result), "result_size": text_size(result)})
                next_input = {"tool_result": result,
                    "remaining_tool_calls": max(0, max_tool_calls - executed_calls),
                    "instruction": "Return the next strict JSON protocol object."}
                if executed_calls >= max_tool_calls:
                    next_input["instruction"] = "Tool budget is exhausted. Return action final now."
            payload = {"model": self.config["id"],
                "previous_response_id": response["id"], "input": canonical_json(next_input),
                "temperature": self.config["temperature"], "seed": self.config["seed"],
                "max_output_tokens": self.config["max_output_tokens"], "store": True}
            if self.config.get("reasoning") is not None:
                payload["reasoning"] = self.config["reasoning"]
