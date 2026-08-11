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
                    "category": {"type": ["string", "null"]},
                    "constants": {"type": "array", "items": {"type": "integer"}},
                    "case_values": {"type": "array", "items": {"type": "integer"}},
                    "return_dependencies": {"type": "array", "items": {
                        "type": "string", "enum": ["arg0", "arg1"]}},
                    "memory_reads": {"type": ["boolean", "null"]},
                    "memory_writes": {"type": ["boolean", "null"]},
                    "direct_call_count": {"type": ["integer", "null"]},
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "unknown_reason": {"type": ["string", "null"]},
                },
                "required": ["question_id", "status", "parameter_count", "category",
                             "constants", "case_values", "return_dependencies",
                             "memory_reads", "memory_writes", "direct_call_count",
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
q1: What is its parameter count, broad purpose category, important integer constants,
and recovered switch case values? Omit incidental stack offsets and addresses from constants.
q2: Which arguments influence the return value, does it read or write memory, and how
many direct call sites occur in the function? Use arg0 and arg1 for dependencies.
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
"""


def prompt_snapshot(text: str) -> dict[str, Any]:
    return {"sha256": sha256_bytes(text.encode("utf-8")), **text_size(text)}


def validate_isolation(sections: dict[str, str], visible: str, track: str,
                       condition: str, forbidden: list[str]) -> None:
    if track == "common":
        if visible != sections["common"]:
            raise ValueError("common prompt is not byte-identical")
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
    return sections["common"] if track == "common" else \
        sections["common"] + "\n" + sections[condition]

