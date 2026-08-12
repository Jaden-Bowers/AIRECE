from __future__ import annotations

import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from typing import Any, Callable

from .prompts import prompt_snapshot
from .util import canonical_json, sha256_bytes, text_size


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
tool or finish. When `initial_context` is present, treat it as the first tool
result and do not request it again. Never repeat an exact tool request; a
duplicate closes tool selection. Never emit XML/tool-call tags.
Tool catalog:
""" + canonical_json(catalog) + "\n"


def _utf8_prefix(text: str, maximum: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= maximum:
        return text
    return encoded[:maximum].decode("utf-8", "ignore")


def compact_tool_evidence(tool_events: list[dict[str, Any]],
                          maximum: int = 8000) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep complete, unique, high-value records within a final-turn byte budget."""
    seen: set[str] = set()
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    omitted = 0
    has_baseline = any(bool(event.get("baseline")) for event in tool_events)
    for index, event in enumerate(tool_events):
        result = event.get("result")
        if not isinstance(result, str):
            omitted += 1
            continue
        try:
            parsed = json.loads(result)
            if isinstance(parsed, dict) and "same_result_as_call" in parsed:
                omitted += 1
                continue
        except json.JSONDecodeError:
            pass
        digest = sha256_bytes(result.encode("utf-8"))
        if digest in seen:
            omitted += 1
            continue
        seen.add(digest)
        name = str(event.get("name", ""))
        if has_baseline and name in {"inspect", "functions", "list_functions"}:
            omitted += 1
            continue
        priority = (0 if event.get("baseline") else
                    1 if name in {"evidence", "slice", "calls", "xrefs", "flow", "path"} else
                    2 if name in {"fn", "function_context"} else 3)
        record = {"call": index + 1, "tool": name,
                  "arguments": event.get("arguments", {}), "result": result}
        candidates.append((priority, index, record))
    selected: list[dict[str, Any]] = []
    for _, _, record in sorted(candidates):
        if len(canonical_json(selected + [record]).encode("utf-8")) <= maximum:
            selected.append(record)
        else:
            omitted += 1
    selected.sort(key=lambda item: int(item["call"]))
    return selected, {"included": len(selected), "omitted": omitted,
                      "utf8_bytes": len(canonical_json(selected).encode("utf-8"))}


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
        self.provider = str(config.get("provider", "lmstudio"))
        self.api_key: str | None = None
        key_name = config.get("api_key_env")
        if isinstance(key_name, str):
            self.api_key = os.environ.get(key_name)
            env_path = pathlib.Path(str(config.get("env_file", ".env")))
            if self.api_key is None and env_path.is_file():
                for line in env_path.read_text(encoding="utf-8").splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or "=" not in stripped:
                        continue
                    name, value = stripped.split("=", 1)
                    if name.strip() == key_name:
                        self.api_key = value.strip().strip('"').strip("'")
                        break
            if not self.api_key:
                raise LMStudioError(f"missing API key environment variable: {key_name}")
            self.redactions.insert(0, self.api_key)

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
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = "Bearer " + self.api_key
        if self.provider == "openrouter":
            headers["X-Title"] = str(self.config.get("app_name", "AIRECE Benchmark"))
        request = urllib.request.Request(self.base_url + path, data=data, method=method,
                                         headers=headers)
        started = time.perf_counter()
        last_error: Exception | None = None
        request_budget = timeout or self.timeout
        for attempt in range(1, 3):
            self.last_request_attempts = attempt
            remaining_budget = request_budget - (time.perf_counter() - started)
            if remaining_budget <= 0:
                raise LMStudioError(f"{self.provider} request timed out")
            try:
                with urllib.request.urlopen(request, timeout=remaining_budget) as response:
                    raw = response.read().decode("utf-8", "replace")
                    return json.loads(raw), dict(response.headers), \
                        round((time.perf_counter() - started) * 1000, 3)
            except urllib.error.HTTPError as error:
                body = error.read().decode("utf-8", "replace")
                if error.code not in {429, 502, 503, 504} or attempt == 2:
                    raise LMStudioError(f"{self.provider} HTTP {error.code}: {body[:4000]}") from error
                last_error = error
                retry_after = error.headers.get("Retry-After")
                if retry_after:
                    try:
                        delay = min(float(retry_after), max(0.0, remaining_budget), 30.0)
                        if delay > 0:
                            time.sleep(delay)
                            continue
                    except ValueError:
                        pass
            except (OSError, ValueError) as error:
                if attempt == 2:
                    raise LMStudioError(f"{self.provider} request failed: {error}") from error
                last_error = error
            time.sleep(0.25)
        raise LMStudioError(f"{self.provider} request failed: {last_error}")

    def probe(self) -> dict[str, Any]:
        errors: list[str] = []
        required = self.config["id"]
        for candidate in self.config["base_urls"]:
            self.base_url = candidate.rstrip("/")
            try:
                models, model_headers, model_elapsed = self._request(
                    "GET", "/v1/models", timeout=5)
                identifiers = [item.get("id") for item in models.get("data", [])]
                if required not in identifiers:
                    errors.append(f"{candidate}: required model absent")
                    continue
                if self.provider == "openrouter":
                    match = next(item for item in models.get("data", [])
                                 if item.get("id") == required)
                    supported = set(match.get("supported_parameters", []))
                    if "tools" not in supported:
                        errors.append(f"{candidate}: required model does not support tools")
                        continue
                    minimum_context = int(self.config.get("minimum_context_length", 0))
                    if int(match.get("context_length") or 0) < minimum_context:
                        errors.append(f"{candidate}: model context is below {minimum_context}")
                        continue
                    self.model_metadata = {
                        "provider": self.provider, "selected_base_url": self.base_url,
                        "required_model": required, "model": self._sanitize(match),
                        "response_headers": self._sanitize(model_headers),
                        "probe_elapsed_ms": model_elapsed,
                        "transport_attempts": self.last_request_attempts}
                    return self.model_metadata
                native, headers, elapsed = self._request("GET", "/api/v1/models", timeout=5)
                match = next((item for item in native.get("models", [])
                              if item.get("key") == required), None)
                loaded = (match or {}).get("loaded_instances", [])
                required_context = self.config.get("context_length")
                matching_instances = [instance for instance in loaded
                    if (required_context is None or
                        instance.get("config", {}).get("context_length") == required_context)]
                if not matching_instances:
                    errors.append(
                        f"{candidate}: required model is not loaded at context {required_context}")
                    continue
                self.model_metadata = {"selected_base_url": self.base_url,
                    "required_model": required, "openai_model_ids": identifiers,
                    "native_model": match, "matching_loaded_instances": matching_instances,
                    "response_headers": self._sanitize(headers),
                    "probe_elapsed_ms": elapsed, "transport_attempts": self.last_request_attempts}
                return self.model_metadata
            except LMStudioError as error:
                errors.append(f"{candidate}: {error}")
        self.base_url = None
        raise LMStudioError(f"no configured {self.provider} endpoint has the required model: " +
                            "; ".join(errors))

    def native_chat_smoke(self) -> dict[str, Any]:
        if self.provider == "openrouter":
            payload = {"model": self.config["id"], "input": "Reply with OK only.",
                       "temperature": 0, "seed": self.config["seed"],
                       "max_output_tokens": 64, "store": False}
            if self.config.get("reasoning") is not None:
                payload["reasoning"] = self.config["reasoning"]
            response, headers, elapsed = self._request(
                "POST", self.config["responses_path"], payload)
            return {"request": self._sanitize(payload), "response": self._sanitize(response),
                    "headers": self._sanitize(headers), "elapsed_ms": elapsed}
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

    def run_direct_final(self, instructions: str, user_input: str, evidence: str,
                         validator: Callable[[str], list[str]],
                         max_input_bytes: int = 120000,
                         final_schema: dict[str, Any] | None = None,
                         normalizer: Callable[[str], str] | None = None) -> dict[str, Any]:
        """Generate a final answer from one deterministic context, with one repair."""
        if self.base_url is None:
            self.probe()
        requests: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                 "reasoning_tokens": 0, "cached_tokens": 0}
        started = time.perf_counter()
        total_model_ms = 0.0
        raw_final = ""
        final = ""
        raw_validation_errors: list[str] = []
        validation_errors: list[str] = []
        normalizations: list[dict[str, Any]] = []
        headers: dict[str, Any] = {}
        for attempt in range(2):
            if attempt == 0:
                direct_instructions = instructions + """

Tools are unavailable. Use only the supplied target context and produce the exact final
answer requested by the task. Do not emit a tool-protocol wrapper, commentary, or markdown
fence.
"""
                if final_schema is not None:
                    direct_instructions += "\nRequired final JSON schema:\n" + \
                        canonical_json(final_schema) + "\n"
                envelope: dict[str, Any] = {"task": user_input, "target_context": evidence}
            else:
                direct_instructions = """You are a deterministic output-format repair step.
Return only the artifact required by the task. Do not add analysis, JSON wrappers, markdown
fences, or commentary. Preserve the previous answer's intended semantics; only correct the
reported structural problems.\n"""
                envelope = {"task": user_input}
                envelope["invalid_previous_answer"] = raw_final
                envelope["normalized_previous_answer"] = final
                envelope["validation_errors"] = validation_errors
            payload: dict[str, Any] = {"model": self.config["id"],
                "instructions": direct_instructions, "input": canonical_json(envelope),
                "temperature": self.config["temperature"], "seed": self.config["seed"],
                "max_output_tokens": self.config["max_output_tokens"], "store": False}
            if self.config.get("reasoning") is not None:
                payload["reasoning"] = self.config["reasoning"]
            payload_bytes = len(canonical_json(payload).encode("utf-8"))
            if payload_bytes > max_input_bytes:
                raise LMStudioError(
                    f"direct-final envelope exceeds input byte budget: {payload_bytes}>{max_input_bytes}")
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
                raise LMStudioError(f"direct-final response failed: {response.get('error')}")
            response_text = self._text(response)
            if attempt == 0:
                raw_final = response_text
                raw_validation_errors = validator(raw_final)
            final = normalizer(response_text) if normalizer is not None else response_text
            if final != response_text:
                normalizations.append({"attempt": attempt + 1,
                    "input_size": text_size(response_text), "output_size": text_size(final)})
            validation_errors = validator(final)
            if not validation_errors:
                break
        repair_attempted = bool(normalizations) or len(requests) > 1
        return {"transport": "deterministic-context", "final_text": final,
            "raw_final_text": raw_final, "raw_validation_errors": raw_validation_errors,
            "normalizations": normalizations, "model_repair_attempted": len(requests) > 1,
            "repair_attempted": repair_attempted,
            "repair_succeeded": repair_attempted and not validation_errors,
            "final_validation_errors": validation_errors,
            "usage": usage, "requests": requests, "responses": responses,
            "tool_events": [], "protocol_errors": [], "protocol_recoveries": [],
            "protocol_compliance": {"errors": 0, "recoveries": 0,
                                    "not_applicable": True},
            "model_elapsed_ms": total_model_ms,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "final_size": text_size(final), "raw_final_size": text_size(raw_final),
            "response_headers": self._sanitize(headers)}

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
                          max_input_bytes: int = 120000,
                          final_schema: dict[str, Any] | None = None,
                          initial_tool_events: list[dict[str, Any]] | None = None,
                          final_validator: Callable[[str], list[str]] | None = None,
                          final_normalizer: Callable[[str], str] | None = None) -> dict[str, Any]:
        if self.base_url is None:
            self.probe()
        protocol = json_protocol_instructions(tools)
        full_instructions = instructions + "\n" + protocol
        requests: list[dict[str, Any]] = []
        responses: list[dict[str, Any]] = []
        tool_events: list[dict[str, Any]] = json.loads(canonical_json(
            initial_tool_events or []))
        protocol_errors: list[str] = []
        protocol_recoveries: list[str] = []
        usage = {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                 "reasoning_tokens": 0, "cached_tokens": 0}
        transcript: list[dict[str, Any]] = []
        started = time.perf_counter()
        total_model_ms = 0.0
        executed_calls = 0
        turns = 0
        duplicate_tool_calls = 0
        force_final = False
        raw_final_text = ""
        raw_validation_errors: list[str] = []
        final_validation_errors: list[str] = []
        normalizations: list[dict[str, Any]] = []
        final_evidence_summary = {"included": 0, "omitted": 0, "utf8_bytes": 0}
        final_repair_attempted = False

        def finish(final: str, headers: dict[str, Any]) -> dict[str, Any]:
            return {"transport": "json-protocol", "final_text": final,
                "raw_final_text": raw_final_text or final,
                "raw_validation_errors": raw_validation_errors,
                "final_validation_errors": final_validation_errors,
                "normalizations": normalizations,
                "repair_attempted": final_repair_attempted or bool(normalizations),
                "repair_succeeded": (final_repair_attempted or bool(normalizations)) and
                    not final_validation_errors,
                "usage": usage, "requests": requests, "responses": responses,
                "tool_events": tool_events, "protocol_errors": protocol_errors,
                "protocol_recoveries": protocol_recoveries,
                "duplicate_tool_calls": duplicate_tool_calls,
                "initial_tool_events": len(initial_tool_events or []),
                "final_evidence": final_evidence_summary,
                "model_elapsed_ms": total_model_ms,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "final_size": text_size(final),
                "response_headers": self._sanitize(headers),
                "protocol_instructions": prompt_snapshot(protocol),
                "protocol_compliance": {"errors": len(protocol_errors),
                    "recoveries": len(protocol_recoveries)},
                "final_generation_separated": bool(
                    self.config.get("separate_final_generation"))}

        def direct_final(draft: str, prior_headers: dict[str, Any]) -> dict[str, Any]:
            nonlocal total_model_ms, raw_final_text, raw_validation_errors
            nonlocal final_validation_errors, final_evidence_summary
            nonlocal final_repair_attempted
            if not self.config.get("separate_final_generation"):
                raw_final_text = draft
                final = final_normalizer(draft) if final_normalizer else draft
                raw_validation_errors = final_validator(draft) if final_validator else []
                final_validation_errors = final_validator(final) if final_validator else []
                return finish(final, prior_headers)
            evidence, final_evidence_summary = compact_tool_evidence(
                tool_events, int(self.config.get("max_final_evidence_bytes", 8000)))
            draft_limit = int(self.config.get("max_final_draft_bytes", 4000))
            bounded_draft = _utf8_prefix(draft, draft_limit)
            final = bounded_draft
            headers = prior_headers
            for attempt in range(2 if final_validator else 1):
                final_instructions = instructions + """

Tool selection is complete and tools are unavailable. Produce only the exact final answer
requested by the task. Do not emit a tool-protocol wrapper, commentary, or markdown fence.
"""
                if final_schema is None:
                    final_instructions += """
Reconstruct behavior, not analyzer syntax. Use only the parameters a and b, uint32_t local
variables, integer constants, ordinary C operators, and structured control flow. Never copy
analysis identifiers or primitives such as tmp_v*, buffer_v*, stack_*, load32, store32,
extract, zext, registers, addresses as variables, or unresolved helper calls. Inline any
needed helper behavior. Return exactly uint32_t target(uint32_t a, uint32_t b) { ... }.
"""
                else:
                    final_instructions += "\nThe required final JSON schema is:\n" + \
                        canonical_json(final_schema) + "\n"
                if attempt == 0:
                    final_value: dict[str, Any] = {"task": user_input,
                        "evidence": evidence, "evidence_summary": final_evidence_summary,
                        "draft": bounded_draft}
                else:
                    final_repair_attempted = True
                    final_instructions += """
This is a deterministic structural repair. Preserve supported behavior, correct only the
reported validation problems, and return the required artifact with no wrapper.
"""
                    final_value = {"task": user_input, "evidence": evidence,
                        "invalid_previous_answer": final,
                        "validation_errors": final_validation_errors}
                payload: dict[str, Any] = {"model": self.config["id"],
                    "instructions": final_instructions,
                    "input": canonical_json(final_value),
                    "temperature": self.config["temperature"], "seed": self.config["seed"],
                    "max_output_tokens": self.config["max_output_tokens"], "store": False}
                if final_schema is not None and self.config.get("schema_constrained_final"):
                    payload["text"] = {"format": {"type": "json_schema",
                        "name": "objective_answers", "schema": final_schema, "strict": True}}
                if self.config.get("reasoning") is not None:
                    payload["reasoning"] = self.config["reasoning"]
                payload_bytes = len(canonical_json(payload).encode("utf-8"))
                if payload_bytes > max_input_bytes:
                    raise LMStudioError(
                        f"direct-final envelope exceeds input byte budget: {payload_bytes}>{max_input_bytes}")
                remaining = self.timeout - (time.perf_counter() - started)
                if remaining <= 0:
                    raise LMStudioError("task wall-clock budget exhausted before final generation")
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
                    raise LMStudioError(f"direct-final response failed: {response.get('error')}")
                response_text = self._text(response)
                if attempt == 0:
                    raw_final_text = response_text
                    raw_validation_errors = (final_validator(response_text)
                                             if final_validator else [])
                final = final_normalizer(response_text) if final_normalizer else response_text
                if final != response_text:
                    normalizations.append({"attempt": attempt + 1,
                        "input_size": text_size(response_text),
                        "output_size": text_size(final)})
                final_validation_errors = final_validator(final) if final_validator else []
                if not final_validation_errors:
                    break
            return finish(final, headers)

        while True:
            turns += 1
            if turns > max_tool_calls + 3:
                raise LMStudioError("JSON protocol turn budget exhausted")
            active_instructions = full_instructions
            if executed_calls >= max_tool_calls or force_final:
                active_instructions = instructions + """

Tool access is exhausted and no tool catalog is available. Return exactly one
JSON object with no markdown or surrounding text:
{"action":"final","content":FINAL_VALUE}
FINAL_VALUE must be the exact answer requested by the original task. Do not
request another tool.
"""
            prompt_transcript = json.loads(canonical_json(transcript))
            request_limit = min(max_input_bytes,
                int(self.config.get("max_protocol_request_bytes", max_input_bytes)))
            compactions: list[dict[str, Any]] = []
            while True:
                envelope = {"task": user_input, "transcript": prompt_transcript,
                            "remaining_tool_calls": (0 if force_final else
                                max_tool_calls - executed_calls)}
                if initial_tool_events:
                    envelope["initial_context"] = [{"tool": event.get("name"),
                        "arguments": event.get("arguments", {}),
                        "result": event.get("result")} for event in initial_tool_events]
                payload: dict[str, Any] = {"model": self.config["id"],
                    "instructions": active_instructions, "input": canonical_json(envelope),
                    "temperature": self.config["temperature"], "seed": self.config["seed"],
                    "max_output_tokens": self.config["max_output_tokens"], "store": False}
                if self.config.get("reasoning") is not None:
                    payload["reasoning"] = self.config["reasoning"]
                payload_bytes = len(canonical_json(payload).encode("utf-8"))
                if payload_bytes <= request_limit:
                    break
                compacted = False
                for index, event in enumerate(prompt_transcript):
                    controller = event.get("controller", {})
                    result = controller.get("tool_result")
                    if isinstance(result, str) and len(result) > 256:
                        result_bytes = result.encode("utf-8")
                        controller["tool_result"] = canonical_json({
                            "omitted_from_prompt": True,
                            "sha256": sha256_bytes(result_bytes),
                            "utf8_bytes": len(result_bytes)})
                        compactions.append({"transcript_index": index,
                            "sha256": sha256_bytes(result_bytes),
                            "utf8_bytes": len(result_bytes)})
                        compacted = True
                        break
                if not compacted:
                    raise LMStudioError(
                        f"request envelope cannot fit protocol byte budget: "
                        f"{payload_bytes}>{request_limit}")
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
            requests[-1]["_transcript_compactions"] = compactions
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
            if raw.strip() and (value is None or value.get("action") not in {"tool", "final"}):
                protocol_recoveries.append(
                    "accepted non-protocol model output as final")
                return direct_final(raw.strip(), headers)
            if (executed_calls >= max_tool_calls or force_final) and \
                    (value is None or value.get("action") != "final"):
                protocol_recoveries.append(
                    "accepted raw final after tool budget exhaustion")
                return direct_final(raw.strip(), headers)
            if value is None or value.get("action") not in {"tool", "final"}:
                message = "malformed JSON protocol response"
                protocol_errors.append(message + ": " + raw[:1000])
                next_input: dict[str, Any] = {"protocol_error": message,
                    "required": {"action": "tool or final"},
                    "remaining_tool_calls": max_tool_calls - executed_calls}
                transcript.append({"assistant_output": raw, "controller": next_input})
            elif value["action"] == "final":
                content = value.get("content")
                final = content if isinstance(content, str) else canonical_json(content)
                return direct_final(final, headers)
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
                duplicate = False
                try:
                    parsed_result = json.loads(result)
                    duplicate = isinstance(parsed_result, dict) and \
                        "same_result_as_call" in parsed_result
                except json.JSONDecodeError:
                    pass
                if duplicate:
                    duplicate_tool_calls += 1
                    force_final = True
                tool_events.append({"name": name, "arguments": self._sanitize(normalized_arguments),
                    "executed": was_executed,
                    "duplicate": duplicate,
                    "result": self._sanitize(result), "result_size": text_size(result)})
                next_input = {"tool_result": result,
                    "remaining_tool_calls": (0 if force_final else
                        max(0, max_tool_calls - executed_calls)),
                    "instruction": "Return the next strict JSON protocol object."}
                if duplicate:
                    next_input["instruction"] = (
                        "This exact request duplicated an earlier result and produced no new "
                        "evidence. Tool selection is closed; return action final now.")
                elif executed_calls >= max_tool_calls:
                    next_input["instruction"] = "Tool budget is exhausted. Return action final now."
                transcript.append({"assistant": value, "controller": next_input})
