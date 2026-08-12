from __future__ import annotations

import json
import pathlib
import time
import copy
from typing import Any, Callable

from .ghidra import GhidraExtractor
from .util import canonical_json, run


COMMON_TOOLS = [
    {"type": "function", "name": "inspect", "description": "Inspect binary metadata and analysis completeness.",
     "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"type": "function", "name": "list_functions", "description": "List analyzed functions.",
     "parameters": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 64}},
                    "additionalProperties": False}},
    {"type": "function", "name": "function_context", "description": "Get primary or low-level context for a function.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
                    "level": {"type": "string", "enum": ["primary", "low_level"]},
                    "limit": {"type": "integer", "minimum": 16, "maximum": 64}},
                    "required": ["address", "level"], "additionalProperties": False}},
    {"type": "function", "name": "calls", "description": "Get calls made by a function.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 64}},
                    "required": ["address"], "additionalProperties": False}},
    {"type": "function", "name": "xrefs", "description": "Get references to or from an address.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 64}},
                    "required": ["address"], "additionalProperties": False}},
]


AIRECE_NATIVE_TOOLS = [
    {"type": "function", "name": "fn", "description":
        "Get the bounded AIRECE agent digest for a function, normally a followed callee.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
        "limit": {"type": "integer", "minimum": 16, "maximum": 64}},
        "required": ["address"], "additionalProperties": False}},
    {"type": "function", "name": "fn_detail", "description":
        "Get a bounded lower-level view only when the supplied agent digest lacks a needed fact.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
        "view": {"type": "string", "enum": ["compact", "json", "pseudo", "ir"]},
        "limit": {"type": "integer", "minimum": 16, "maximum": 64}},
        "required": ["address", "view"], "additionalProperties": False}},
    COMMON_TOOLS[3], COMMON_TOOLS[4],
    {"type": "function", "name": "evidence", "description": "Resolve an AIRECE evidence or statement identifier.",
     "parameters": {"type": "object", "properties": {"locator": {"type": "string"}},
                    "required": ["locator"], "additionalProperties": False}},
    {"type": "function", "name": "slice", "description": "Get a backward dependency slice.",
     "parameters": {"type": "object", "properties": {"locator": {"type": "string"}},
                    "required": ["locator"], "additionalProperties": False}},
    {"type": "function", "name": "path", "description": "Find a bounded CFG path.",
     "parameters": {"type": "object", "properties": {"from": {"type": "string"}, "to": {"type": "string"}},
                    "required": ["from", "to"], "additionalProperties": False}},
    {"type": "function", "name": "flow", "description": "Ask a directed source-to-target flow question.",
     "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "target": {"type": "string"},
        "mode": {"type": "string", "enum": ["taint", "taint-symbolic", "symbolic"]}},
        "required": ["source", "target", "mode"], "additionalProperties": False}},
]


GHIDRA_NATIVE_TOOLS = [COMMON_TOOLS[2],
    {"type": "function", "name": "disassembly", "description": "Get bounded function disassembly.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
        "limit": {"type": "integer", "minimum": 16, "maximum": 64}},
                    "required": ["address"], "additionalProperties": False}},
    COMMON_TOOLS[3], COMMON_TOOLS[4]]


def tool_schema(track: str, condition: str) -> list[dict[str, Any]]:
    if track in {"single", "common"}:
        return json.loads(json.dumps(COMMON_TOOLS))
    return json.loads(json.dumps(AIRECE_NATIVE_TOOLS if condition == "airece"
                                 else GHIDRA_NATIVE_TOOLS))


class Backend:
    def __init__(self, binary: pathlib.Path, max_bytes: int):
        self.binary = binary
        self.max_bytes = max_bytes
        self._calls: dict[str, tuple[int, str]] = {}
        self._call_number = 0

    def _bounded(self, value: Any) -> str:
        value = copy.deepcopy(value)
        omitted = 0
        rendered = canonical_json(value)
        while len(rendered.encode("utf-8")) > self.max_bytes:
            lists: list[list[Any]] = []
            fields: list[tuple[dict[str, Any], str]] = []
            def collect(item: Any) -> None:
                if isinstance(item, list):
                    if item:
                        lists.append(item)
                    for child in item:
                        collect(child)
                elif isinstance(item, dict):
                    for key, child in item.items():
                        if isinstance(child, str) and key not in {"entry", "name", "error"}:
                            fields.append((item, key))
                        collect(child)
            collect(value)
            if lists:
                max(lists, key=lambda item: len(canonical_json(item[-1]).encode("utf-8"))).pop()
            elif fields:
                owner, key = max(fields, key=lambda item: len(item[0][item[1]].encode("utf-8")))
                del owner[key]
            else:
                return canonical_json({"ok": False, "error": "bounded result unavailable",
                                       "omitted": {"records": omitted + 1}})
            omitted += 1
            if isinstance(value, dict):
                value["omitted"] = {"records": omitted}
            rendered = canonical_json(value)
        return rendered

    def execute(self, name: str, arguments: dict[str, Any], track: str) -> str:
        cache_arguments = copy.deepcopy(arguments)
        if name in {"fn", "fn_detail", "function_context", "disassembly",
                    "calls", "xrefs", "functions", "list_functions"}:
            cache_arguments.setdefault("limit", 64)
        key = canonical_json({"name": name, "arguments": cache_arguments, "track": track})
        self._call_number += 1
        if key in self._calls:
            original, _ = self._calls[key]
            return canonical_json({"ok": True, "same_result_as_call": original})
        result = self._execute(name, arguments, track)
        self._calls[key] = (self._call_number, result)
        return result


class AireceBackend(Backend):
    def __init__(self, executable: pathlib.Path, binary: pathlib.Path,
                 max_bytes: int, timeout: float):
        super().__init__(binary, max_bytes)
        self.executable = executable
        self.timeout = timeout

    def _execute(self, name: str, arguments: dict[str, Any], track: str) -> str:
        requested_name = name
        if track in {"single", "common"}:
            name = {"list_functions": "functions", "function_context": "fn"}.get(name, name)
        command = [str(self.executable)]
        if name == "inspect": command += ["inspect", str(self.binary), "--profile", "balanced"]
        elif name == "functions": command += ["functions", str(self.binary), "--profile", "balanced"]
        elif name in {"fn", "fn_detail"}:
            view = (str(arguments["view"]) if requested_name == "fn_detail" else
                    ("agent" if requested_name == "fn" and "level" not in arguments else
                     ("agent" if arguments.get("level") == "primary" else "ir")))
            limit = min(max(int(arguments.get("limit", 64)), 16), 64)
            command += ["fn", str(self.binary), str(arguments["address"]), "--view", view,
                        "--profile", "fast", "--max-bytes", str(self.max_bytes),
                        "--max-statements", str(limit), "--max-evidence", str(limit)]
        elif name in {"calls", "xrefs"}:
            command += [name, str(self.binary), str(arguments["address"])]
            if name == "calls":
                command += ["--max-calls", str(min(max(int(arguments.get("limit", 64)), 1), 64))]
        elif name in {"evidence", "slice"}:
            command += [name, str(self.binary), str(arguments["locator"])]
        elif name == "path":
            command += ["path", str(self.binary), "--from", str(arguments["from"]),
                        "--to", str(arguments["to"]), "--max-states", "256"]
        elif name == "flow":
            command += ["flow", str(self.binary), "--source", str(arguments["source"]),
                        "--target", str(arguments["target"]), "--mode", str(arguments["mode"]),
                        "--function-depth", "3", "--max-states", "256", "--json"]
        else:
            return canonical_json({"ok": False, "error": "unavailable tool"})
        result = run(command, self.binary.parent, self.timeout)
        try:
            stdout: Any = json.loads(result["stdout"])
        except json.JSONDecodeError:
            stdout = result["stdout"]
        return self._bounded({"ok": result["exit"] in (0, 3),
            "partial": result["exit"] == 3, "exit": result["exit"],
            "elapsed_ms": result["elapsed_ms"], "result": stdout,
            "stderr": result["stderr"][-1000:]})


class GhidraBackend(Backend):
    def __init__(self, extractor: GhidraExtractor, binary: pathlib.Path, max_bytes: int):
        super().__init__(binary, max_bytes)
        self.document, self.extraction = extractor.extract(binary)

    def _function(self, address: str) -> dict[str, Any] | None:
        wanted = int(address, 0)
        for function in self.document["functions"]:
            if int(function["entry"], 0) == wanted or \
                    int(function["body_min"], 0) <= wanted <= int(function["body_max"], 0):
                return function
        return None

    def _execute(self, name: str, arguments: dict[str, Any], track: str) -> str:
        started = time.perf_counter()
        if name == "inspect": value: Any = self.document["program"]
        elif name == "list_functions":
            limit = min(max(int(arguments.get("limit", 64)), 1), 64)
            value = [{key: function[key] for key in ("entry", "name", "signature",
                                                      "body_min", "body_max")}
                     for function in self.document["functions"][:limit]]
        elif name in {"function_context", "disassembly", "calls", "xrefs"}:
            function = self._function(str(arguments["address"]))
            if function is None:
                return canonical_json({"ok": False, "error": "function unavailable"})
            if name == "function_context":
                level = arguments.get("level", "primary")
                keys = ("entry", "name", "signature", "body_min", "body_max",
                        "decompile_ok", "decompile_truncated", "decompiled_c") if \
                    level == "primary" else ("entry", "name", "signature", "instructions")
                value = {key: function[key] for key in keys}
                if level == "low_level":
                    value["instructions"] = value["instructions"][:min(
                        max(int(arguments.get("limit", 64)), 16), 64)]
            elif name == "disassembly": value = function["instructions"][:min(
                max(int(arguments.get("limit", 64)), 16), 64)]
            elif name == "calls": value = function["calls"][:min(
                max(int(arguments.get("limit", 64)), 1), 64)]
            else: value = {"to_function": function["xrefs_to"],
                           "from_function_calls": function["calls"]}
            if name == "xrefs":
                limit = min(max(int(arguments.get("limit", 64)), 1), 64)
                value = {key: items[:limit] for key, items in value.items()}
        else:
            return canonical_json({"ok": False, "error": "unavailable tool"})
        return self._bounded({"ok": True,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "result": value})
