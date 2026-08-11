from __future__ import annotations

import json
import pathlib
import time
from typing import Any, Callable

from .ghidra import GhidraExtractor
from .util import canonical_json, run


COMMON_TOOLS = [
    {"type": "function", "name": "inspect", "description": "Inspect binary metadata and analysis completeness.",
     "parameters": {"type": "object", "properties": {}, "additionalProperties": False}},
    {"type": "function", "name": "list_functions", "description": "List analyzed functions.",
     "parameters": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 256}},
                    "additionalProperties": False}},
    {"type": "function", "name": "function_context", "description": "Get primary or low-level context for a function.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
                    "level": {"type": "string", "enum": ["primary", "low_level"]}},
                    "required": ["address", "level"], "additionalProperties": False}},
    {"type": "function", "name": "calls", "description": "Get calls made by a function.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"}},
                    "required": ["address"], "additionalProperties": False}},
    {"type": "function", "name": "xrefs", "description": "Get references to or from an address.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"}},
                    "required": ["address"], "additionalProperties": False}},
]


AIRECE_NATIVE_TOOLS = [COMMON_TOOLS[0],
    {**COMMON_TOOLS[1], "name": "functions"},
    {"type": "function", "name": "fn", "description": "Render an AIRECE function view.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"},
        "view": {"type": "string", "enum": ["compact", "json", "pseudo", "ir"]}},
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


GHIDRA_NATIVE_TOOLS = [COMMON_TOOLS[0], COMMON_TOOLS[1], COMMON_TOOLS[2],
    {"type": "function", "name": "disassembly", "description": "Get bounded function disassembly.",
     "parameters": {"type": "object", "properties": {"address": {"type": "string"}},
                    "required": ["address"], "additionalProperties": False}},
    COMMON_TOOLS[3], COMMON_TOOLS[4]]


def tool_schema(track: str, condition: str) -> list[dict[str, Any]]:
    if track == "common":
        return json.loads(json.dumps(COMMON_TOOLS))
    return json.loads(json.dumps(AIRECE_NATIVE_TOOLS if condition == "airece"
                                 else GHIDRA_NATIVE_TOOLS))


class Backend:
    def __init__(self, binary: pathlib.Path, max_bytes: int):
        self.binary = binary
        self.max_bytes = max_bytes

    def _bounded(self, text: str, metadata: dict[str, Any] | None = None) -> str:
        encoded = text.encode("utf-8")
        if len(encoded) <= self.max_bytes:
            return text
        prefix = encoded[:max(0, self.max_bytes - 128)].decode("utf-8", "ignore")
        return prefix + "\n[bounded result truncated; absence is not negative evidence]"


class AireceBackend(Backend):
    def __init__(self, executable: pathlib.Path, binary: pathlib.Path,
                 max_bytes: int, timeout: float):
        super().__init__(binary, max_bytes)
        self.executable = executable
        self.timeout = timeout

    def execute(self, name: str, arguments: dict[str, Any], track: str) -> str:
        if track == "common":
            name = {"list_functions": "functions", "function_context": "fn"}.get(name, name)
        command = [str(self.executable)]
        if name == "inspect": command += ["inspect", str(self.binary), "--profile", "fast"]
        elif name == "functions": command += ["functions", str(self.binary), "--profile", "fast"]
        elif name == "fn":
            view = arguments.get("view") or ("compact" if arguments.get("level") == "primary" else "ir")
            command += ["fn", str(self.binary), str(arguments["address"]), "--view", view,
                        "--profile", "fast", "--max-bytes", str(self.max_bytes),
                        "--max-statements", "256", "--max-evidence", "256"]
        elif name in {"calls", "xrefs"}:
            command += [name, str(self.binary), str(arguments["address"])]
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
        return self._bounded(canonical_json({"ok": result["exit"] in (0, 3),
            "partial": result["exit"] == 3, "exit": result["exit"],
            "elapsed_ms": result["elapsed_ms"], "stdout": result["stdout"],
            "stderr": result["stderr"][-1000:]}))


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

    def execute(self, name: str, arguments: dict[str, Any], track: str) -> str:
        started = time.perf_counter()
        if name == "inspect": value: Any = self.document["program"]
        elif name == "list_functions":
            limit = min(int(arguments.get("limit", 256)), 256)
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
            elif name == "disassembly": value = function["instructions"]
            elif name == "calls": value = function["calls"]
            else: value = {"to_function": function["xrefs_to"],
                           "from_function_calls": function["calls"]}
        else:
            return canonical_json({"ok": False, "error": "unavailable tool"})
        return self._bounded(canonical_json({"ok": True,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
            "result": value}))
