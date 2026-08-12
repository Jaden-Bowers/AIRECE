from __future__ import annotations

import json
import pathlib
import re
from typing import Any

from .util import canonical_json, sha256_bytes, text_size


SECTION_NAMES = {
    "common": "Common system prompt",
    "airece": "AIRECE native-agent instruction pack",
    "ghidra": "Ghidra 12.1.2 headless native-agent instruction pack",
}


OBJECTIVE_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "properties": {
        "answers": {"type": "array", "minItems": 2, "maxItems": 2,
            "items": {"type": "object", "additionalProperties": False,
                "properties": {
                    "question_id": {"type": "string", "enum": ["q1", "q2"]},
                    "status": {"type": "string", "enum": ["answered", "unknown"]},
                    "parameter_count": {"type": ["integer", "null"]},
                    "category": {"type": ["string", "null"], "enum": [None,
                        "bit-manipulation", "sparse-switch", "loop-and-array",
                        "nested-branches", "direct-calls", "api-source-sink-flow",
                        "structure-access", "recursion", "dense-switch",
                        "global-read-write", "indirect-call"]},
                    "control_shape": {"type": ["string", "null"], "enum": [None,
                        "straight-line", "branch", "nested-branch", "loop",
                        "sparse-switch", "dense-switch", "call-oriented", "recursive"]},
                    "constants": {"type": "array", "items": {"type": "integer"}},
                    "case_values": {"type": "array", "items": {"type": "integer"}},
                    "return_dependencies": {"type": "array", "items": {
                        "type": "string", "enum": ["arg0", "arg1"]}},
                    "stack_memory_reads": {"type": ["boolean", "null"]},
                    "stack_memory_writes": {"type": ["boolean", "null"]},
                    "external_memory_reads": {"type": ["boolean", "null"]},
                    "external_memory_writes": {"type": ["boolean", "null"]},
                    "direct_call_count": {"type": ["integer", "null"]},
                    "indirect_call_count": {"type": ["integer", "null"]},
                    "imported_call_count": {"type": ["integer", "null"]},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "unknown_reason": {"type": ["string", "null"]},
                },
                "required": ["question_id", "status", "parameter_count", "category", "control_shape",
                             "constants", "case_values", "return_dependencies",
                             "stack_memory_reads", "stack_memory_writes",
                             "external_memory_reads", "external_memory_writes",
                             "direct_call_count", "indirect_call_count", "imported_call_count",
                             "evidence", "unknown_reason"]}},
    }, "required": ["answers"]}


def extract_sections(path: pathlib.Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    result: dict[str, str] = {}
    for key, heading in SECTION_NAMES.items():
        match = re.search(rf"(?ms)^## {re.escape(heading)}\s+```text\n(.*?)\n```", text)
        if not match:
            raise ValueError(f"instruction section not found: {heading}")
        result[key] = match.group(1) + "\n"
    return result


def objective_prompt(target_address: str) -> str:
    schema = canonical_json(OBJECTIVE_SCHEMA)
    return f"""Analyze the function at address {target_address}. Answer two objective questions.
q1: Choose its purpose category and control shape only from the schema enums, and report
its parameter count, important integer constants, and recovered switch case values. Omit
incidental stack offsets, dispatch-table offsets, and addresses from constants.
q2: Which arguments influence the return value? Separately report stack-local and external
memory reads/writes, and direct internal, indirect, and imported call-site counts. Use arg0
and arg1 for dependencies. Dispatch-table reads are control machinery, not external memory.
For every answered question include at least one function/instruction address or stable
evidence identifier returned by a tool. Use status unknown and null/empty fields when the
available evidence is insufficient. Return JSON matching this exact schema: {schema}
"""


def reconstruction_prompt(target_address: str) -> str:
    return f"""Reconstruct the behavior of the function at address {target_address}.
Return only one self-contained C function with this exact signature:
uint32_t target(uint32_t a, uint32_t b)
Do not include headers, main, prose, markdown fences, assembly, pragmas, imports, or calls
to operating-system or library APIs. Unsigned 32-bit wraparound is intentional.
Express recovered behavior using only a, b, uint32_t local variables, constants, ordinary C
operators, and structured control flow. A function-local static uint32_t variable is allowed
only when the evidence establishes state that persists across calls. Do not copy analyzer temporaries, registers, memory
primitives, addresses-as-variables, or unresolved helper names into the function.
"""


def prompt_snapshot(text: str) -> dict[str, Any]:
    return {"sha256": sha256_bytes(text.encode("utf-8")), **text_size(text)}


def validate_isolation(sections: dict[str, str], visible: str, track: str,
                       condition: str, forbidden: list[str]) -> None:
    if track in {"single", "common"}:
        if visible != sections["common"]:
            raise ValueError("blinded prompt is not byte-identical")
        if sections["airece"] in visible or sections["ghidra"] in visible:
            raise ValueError("native instruction pack leaked into common track")
    else:
        expected = sections["common"] + "\n" + sections[condition]
        if visible != expected:
            raise ValueError("native prompt does not contain exactly its matched pack")
        opposing = "ghidra" if condition == "airece" else "airece"
        if sections[opposing] in visible:
            raise ValueError("opposing instruction pack leaked")
    lowered = visible.lower()
    for item in forbidden:
        if item and item.lower() in lowered:
            raise ValueError(f"ground-truth token leaked into prompt: {item}")


def instructions(sections: dict[str, str], track: str, condition: str) -> str:
    return sections["common"] if track in {"single", "common"} else \
        sections["common"] + "\n" + sections[condition]
