from __future__ import annotations

import json
import pathlib
import random
import re
import tempfile
from collections import defaultdict
from typing import Any

from .prompts import OBJECTIVE_SCHEMA
from .util import run


OBJECTIVE_FIELDS = ("parameter_count", "category", "control_shape", "constants",
                    "case_values", "return_dependencies", "stack_memory_reads",
                    "stack_memory_writes", "external_memory_reads",
                    "external_memory_writes", "direct_call_count",
                    "indirect_call_count", "imported_call_count")
SET_FIELDS = {"constants", "case_values", "return_dependencies"}
ARTIFACT_CORE_FIELDS = {"parameter_count", "case_values", "return_dependencies",
                        "external_memory_reads", "external_memory_writes",
                        "direct_call_count", "indirect_call_count", "imported_call_count"}


def extract_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```(?:json)?\s*", "", stripped)
        stripped = re.sub(r"\s*```$", "", stripped)
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError as error:
        start, end = stripped.find("{"), stripped.rfind("}")
        if start < 0 or end <= start:
            return None, str(error)
        try:
            value = json.loads(stripped[start:end + 1])
        except json.JSONDecodeError as nested:
            return None, str(nested)
    return (value, None) if isinstance(value, dict) else (None, "root is not object")


def validate_objective(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if set(value) != {"answers"} or not isinstance(value.get("answers"), list) or \
            len(value["answers"]) != 2:
        return ["root must contain exactly two answers"]
    required = set(OBJECTIVE_SCHEMA["properties"]["answers"]["items"]["required"])
    categories = set(OBJECTIVE_SCHEMA["properties"]["answers"]["items"]["properties"]
                     ["category"]["enum"])
    shapes = set(OBJECTIVE_SCHEMA["properties"]["answers"]["items"]["properties"]
                 ["control_shape"]["enum"])
    seen: set[str] = set()
    for index, answer in enumerate(value["answers"]):
        if not isinstance(answer, dict) or set(answer) != required:
            errors.append(f"answer {index} fields do not match schema")
            continue
        question = answer.get("question_id")
        if not isinstance(question, str) or question not in {"q1", "q2"} or question in seen:
            errors.append(f"answer {index} has invalid/duplicate question_id")
        if isinstance(question, str):
            seen.add(question)
        if answer.get("status") not in {"answered", "unknown"}:
            errors.append(f"answer {index} has invalid status")
        for field in ("parameter_count", "direct_call_count", "indirect_call_count",
                      "imported_call_count"):
            field_value = answer.get(field)
            if field_value is not None and (not isinstance(field_value, int) or
                                            isinstance(field_value, bool)):
                errors.append(f"answer {index}.{field} is not integer/null")
        category = answer.get("category")
        if category is not None and (not isinstance(category, str) or category not in categories):
            errors.append(f"answer {index}.category is outside enum")
        shape = answer.get("control_shape")
        if shape is not None and (not isinstance(shape, str) or shape not in shapes):
            errors.append(f"answer {index}.control_shape is outside enum")
        for field in ("constants", "case_values"):
            field_value = answer.get(field)
            if (not isinstance(field_value, list) or any(
                    not isinstance(item, int) or isinstance(item, bool)
                    for item in field_value)):
                errors.append(f"answer {index}.{field} is not an integer array")
        dependencies = answer.get("return_dependencies")
        if (not isinstance(dependencies, list) or
                any(not isinstance(item, str) or item not in {"arg0", "arg1"}
                    for item in dependencies)):
            errors.append(f"answer {index}.return_dependencies is outside enum")
        evidence = answer.get("evidence")
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            errors.append(f"answer {index}.evidence is not a string array")
        for field in ("stack_memory_reads", "stack_memory_writes",
                      "external_memory_reads", "external_memory_writes"):
            field_value = answer.get(field)
            if field_value is not None and not isinstance(field_value, bool):
                errors.append(f"answer {index}.{field} is not boolean/null")
        if answer.get("unknown_reason") is not None and not isinstance(
                answer.get("unknown_reason"), str):
            errors.append(f"answer {index}.unknown_reason is not string/null")
    return errors


def _evidence_valid(locator: str, transcript: str,
                    address_start: int, address_end: int) -> bool:
    if re.fullmatch(r"F[0-9a-fA-F]+:(?:S|E):[^\s]+", locator):
        return locator in transcript
    if re.fullmatch(r"A:0x[0-9a-fA-F]+-0x[0-9a-fA-F]+", locator):
        start = int(locator.split(":", 1)[1].split("-", 1)[0], 0)
        return address_start <= start <= address_end and locator in transcript
    try:
        address = int(locator, 0)
        return address_start <= address <= address_end and locator.lower() in transcript.lower()
    except ValueError:
        return False


def score_objective(text: str, truth: dict[str, Any], tool_events: list[dict[str, Any]],
                    address_start: int, address_end: int) -> dict[str, Any]:
    value, parse_error = extract_json(text)
    if value is None:
        return {"schema_valid": False, "schema_errors": [parse_error],
                "fields_correct": 0, "fields_total": len(OBJECTIVE_FIELDS),
                "exact_accuracy": 0.0, "accuracy": 0.0,
                "semantic_accuracy": 0.0, "semantic_points": 0.0,
                "artifact_core_fields": len(ARTIFACT_CORE_FIELDS),
                "artifact_core_exact": 0, "artifact_core_exact_accuracy": 0.0,
                "artifact_core_semantic_points": 0.0,
                "artifact_core_semantic_accuracy": 0.0,
                "unsupported_claims": 0,
                "claims": 0, "unknown_fields": len(OBJECTIVE_FIELDS),
                "evidence_valid": 0, "evidence_total": 0}
    errors = validate_objective(value)
    answers = {item.get("question_id"): item for item in value.get("answers", [])
               if isinstance(item, dict) and isinstance(item.get("question_id"), str)}
    q1_fields = {"parameter_count", "category", "control_shape", "constants", "case_values"}
    merged = {field: answers.get("q1" if field in q1_fields else "q2", {}).get(field)
              for field in OBJECTIVE_FIELDS}
    correct = 0
    unsupported = 0
    claims = 0
    unknown = 0
    semantic_points = 0.0
    artifact_exact = 0
    artifact_semantic_points = 0.0
    field_details: dict[str, Any] = {}
    for field in OBJECTIVE_FIELDS:
        actual = merged.get(field)
        expected = truth[field]
        answer = answers.get("q1" if field in q1_fields else "q2", {})
        # An answered empty set is a meaningful negative result. Only an explicit
        # unknown status or a null/missing value is unknown.
        is_unknown = answer.get("status") == "unknown" or actual is None
        if is_unknown:
            unknown += 1
        if field in SET_FIELDS:
            normalize = (lambda item: item & 0xffffffff) if field in {"constants", "case_values"} \
                else (lambda item: item)
            raw_items = actual if isinstance(actual, list) else []
            if field in {"constants", "case_values"}:
                raw_items = [item for item in raw_items
                             if isinstance(item, int) and not isinstance(item, bool)]
            else:
                raw_items = [item for item in raw_items if isinstance(item, str)]
            actual_set = {normalize(item) for item in raw_items}
            expected_set = {normalize(item) for item in expected}
            intersection = len(actual_set & expected_set)
            precision = intersection / len(actual_set) if actual_set else (1.0 if not expected_set else 0.0)
            recall = intersection / len(expected_set) if expected_set else (1.0 if not actual_set else 0.0)
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            exact = actual_set == expected_set and not is_unknown
            unsupported += len(actual_set - expected_set)
            claims += len(actual_set)
            field_details[field] = {"exact": exact, "precision": precision,
                                    "recall": recall, "f1": f1,
                                    "actual": sorted(actual_set, key=str),
                                    "expected": sorted(expected_set, key=str)}
            field_semantic = 0.0 if is_unknown else f1
            semantic_points += field_semantic
        else:
            exact = actual == expected and not is_unknown
            if actual is not None:
                claims += 1
                unsupported += 0 if exact else 1
            field_details[field] = {"exact": exact, "actual": actual, "expected": expected}
            field_semantic = float(exact)
            semantic_points += field_semantic
        if field in ARTIFACT_CORE_FIELDS:
            artifact_exact += int(exact)
            artifact_semantic_points += field_semantic
        correct += int(exact)
    transcript = "\n".join(str(event.get("result", "")) for event in tool_events)
    evidence = [item for answer in answers.values()
                for item in (answer.get("evidence", [])
                             if isinstance(answer.get("evidence"), list) else [])
                if isinstance(item, str)]
    evidence_valid = sum(_evidence_valid(item, transcript, address_start, address_end)
                         for item in evidence)
    return {"schema_valid": not errors, "schema_errors": errors,
            "fields_correct": correct, "fields_total": len(OBJECTIVE_FIELDS),
            "exact_accuracy": correct / len(OBJECTIVE_FIELDS),
            "accuracy": semantic_points / len(OBJECTIVE_FIELDS),
            "semantic_accuracy": semantic_points / len(OBJECTIVE_FIELDS),
            "semantic_points": semantic_points,
            "artifact_core_fields": len(ARTIFACT_CORE_FIELDS),
            "artifact_core_exact": artifact_exact,
            "artifact_core_exact_accuracy": artifact_exact / len(ARTIFACT_CORE_FIELDS),
            "artifact_core_semantic_points": artifact_semantic_points,
            "artifact_core_semantic_accuracy": artifact_semantic_points /
                len(ARTIFACT_CORE_FIELDS),
            "field_details": field_details,
            "unsupported_claims": unsupported, "claims": claims,
            "unsupported_claim_rate": unsupported / claims if claims else 0.0,
            "unknown_fields": unknown, "unknown_rate": unknown / len(OBJECTIVE_FIELDS),
            "evidence_valid": evidence_valid, "evidence_total": len(evidence),
            "evidence_validity_rate": evidence_valid / len(evidence) if evidence else 0.0,
            "answer": value}


def extract_c_function(text: str) -> tuple[str | None, str | None]:
    candidate = text.strip()
    fenced = re.search(r"```(?:c|cpp|c\+\+)?\s*(.*?)```", candidate, re.DOTALL)
    if fenced: candidate = fenced.group(1).strip()
    match = re.search(r"\buint32_t\s+target\s*\(\s*uint32_t\s+\w+\s*,\s*"
                      r"uint32_t\s+\w+\s*\)\s*\{", candidate)
    if not match: return None, "required function signature not found"
    start = match.start()
    brace = candidate.find("{", match.start())
    depth = 0
    for index in range(brace, len(candidate)):
        if candidate[index] == "{": depth += 1
        elif candidate[index] == "}":
            depth -= 1
            if depth == 0:
                function = candidate[start:index + 1]
                if "#" in function or re.search(
                        r"\b(?:main|system|popen|fopen|CreateProcess|WinExec|LoadLibrary|asm)\b",
                        function, re.IGNORECASE):
                    return None, "candidate contains a forbidden construct"
                return function, None
    return None, "unbalanced function braces"


def score_reconstruction(text: str, tests: list[dict[str, Any]], compiler: str,
                         linker: str, timeout_compile: float,
                         timeout_execute: float) -> dict[str, Any]:
    function, extraction_error = extract_c_function(text)
    base = {"extractable": function is not None, "extraction_error": extraction_error,
            "compiled": False, "tests_passed": 0, "tests_total": len(tests),
            "behavioral_rate": 0.0, "timeout": False, "crash": False}
    if function is None: return base
    checks = "\n".join(
        f"    if (target(UINT32_C({args[0]}), UINT32_C({args[1]})) != "
        f"UINT32_C({item['expected']})) ++failures;"
        for item in tests for args in [item["args"]])
    source = f"""typedef unsigned __int32 uint32_t;
#define UINT32_C(x) x##u
{function}
__declspec(dllimport) void __stdcall ExitProcess(unsigned long);
void bench_entry(void) {{
    unsigned long failures = 0;
{checks}
    ExitProcess(failures);
}}
"""
    with tempfile.TemporaryDirectory(prefix="airece-reconstruction-") as temporary:
        root = pathlib.Path(temporary)
        source_path, object_path, executable = root / "candidate.c", root / "candidate.obj", root / "candidate.exe"
        source_path.write_text(source, encoding="utf-8")
        compiled = run([compiler, "/nologo", "/TC", "/c", "/O2", "/GS-", "/Zl",
                        f"/Fo{object_path}", str(source_path)], root, timeout_compile)
        base["compile"] = {"exit": compiled["exit"], "elapsed_ms": compiled["elapsed_ms"],
                           "stdout": compiled["stdout"][-2000:],
                           "stderr": compiled["stderr"][-2000:]}
        if compiled["exit"] != 0: return base
        kits = pathlib.Path("C:/Program Files (x86)/Windows Kits/10/Lib")
        libraries = sorted(kits.glob("10.*/um/x64/kernel32.lib"), reverse=True)
        if not libraries:
            base["compile"]["stderr"] = "kernel32.lib unavailable"
            return base
        linked = run([linker, "/nologo", "/subsystem:console", "/nodefaultlib",
                      "/entry:bench_entry", f"/out:{executable}", str(object_path),
                      str(libraries[0])], root, timeout_compile)
        base["link"] = {"exit": linked["exit"], "elapsed_ms": linked["elapsed_ms"],
                        "stdout": linked["stdout"][-2000:], "stderr": linked["stderr"][-2000:]}
        if linked["exit"] != 0: return base
        base["compiled"] = True
        executed = run([str(executable)], root, timeout_execute)
        base["execute"] = {"exit": executed["exit"], "elapsed_ms": executed["elapsed_ms"],
                           "stdout": executed["stdout"][-1000:],
                           "stderr": executed["stderr"][-1000:]}
        base["timeout"] = bool(executed.get("timeout"))
        if executed["exit"] is not None and 0 <= executed["exit"] <= len(tests):
            base["tests_passed"] = len(tests) - executed["exit"]
        else:
            base["crash"] = not base["timeout"]
        base["behavioral_rate"] = base["tests_passed"] / len(tests) if tests else 0.0
        return base


def bootstrap_interval(pairs: list[tuple[float, float]], seed: int,
                       samples: int = 2000) -> dict[str, Any]:
    if not pairs: return {"pairs": 0, "difference": None, "ci95": [None, None]}
    differences = [left - right for left, right in pairs]
    rng = random.Random(seed)
    estimates = [sum(rng.choice(differences) for _ in differences) / len(differences)
                 for _ in range(samples)]
    estimates.sort()
    return {"pairs": len(pairs), "difference": sum(differences) / len(differences),
            "ci95": [estimates[int(samples * 0.025)],
                     estimates[min(samples - 1, int(samples * 0.975))]]}


def summarize(records: list[dict[str, Any]], seed: int = 9173) -> dict[str, Any]:
    groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        groups[(record["track"], record["condition"], record["task"])].append(record)
    output: dict[str, Any] = {"runs": len(records), "groups": {}, "paired": {}}
    for key, items in sorted(groups.items()):
        track, condition, task = key
        scores = [item.get("score", {}) for item in items]
        protocol_models = [item.get("model", {}) for item in items
            if item.get("model") and not item.get("model", {}).get(
                "protocol_compliance", {}).get("not_applicable", False)]
        def analysis_ms(item: dict[str, Any]) -> float:
            total = 0.0
            for event in item.get("model", {}).get("tool_events", []):
                try:
                    value = json.loads(event.get("result", "{}"))
                    total += float(value.get("elapsed_ms") or 0)
                except (ValueError, TypeError, json.JSONDecodeError):
                    pass
            return total

        group = {"runs": len(items), "failed": sum(bool(item.get("failure")) for item in items),
                 "input_tokens": sum(item.get("model", {}).get("usage", {}).get("input_tokens", 0) for item in items),
                 "output_tokens": sum(item.get("model", {}).get("usage", {}).get("output_tokens", 0) for item in items),
                 "total_tokens": sum(item.get("model", {}).get("usage", {}).get("total_tokens", 0) for item in items),
                 "tool_calls": sum(len(item.get("model", {}).get("tool_events", [])) for item in items),
                 "protocol_applicable": len(protocol_models),
                 "protocol_clean": sum(
                    model.get("protocol_compliance", {}).get("errors", 0) == 0 and
                    model.get("protocol_compliance", {}).get("recoveries", 0) == 0
                    for model in protocol_models),
                 "raw_structure_valid": sum(
                    not item.get("model", {}).get("raw_validation_errors", [])
                    for item in items if item.get("model")),
                 "final_structure_valid": sum(
                    not item.get("model", {}).get("final_validation_errors", [])
                    for item in items if item.get("model")),
                 "repairs_attempted": sum(bool(item.get("model", {}).get("repair_attempted"))
                    for item in items),
                 "repairs_succeeded": sum(bool(item.get("model", {}).get("repair_succeeded"))
                    for item in items),
                 "transcript_compactions": sum(len(request.get("_transcript_compactions", []))
                    for item in items for request in item.get("model", {}).get("requests", [])),
                 "transport_retries": sum(max(0, int(request.get("_transport_attempts", 1)) - 1)
                    for item in items for request in item.get("model", {}).get("requests", [])),
                 "duplicate_tool_calls": sum(int(item.get("model", {}).get(
                     "duplicate_tool_calls", 0)) for item in items),
                 "initial_tool_events": sum(int(item.get("model", {}).get(
                     "initial_tool_events", 0)) for item in items),
                 "final_evidence_bytes": sum(int(item.get("model", {}).get(
                     "final_evidence", {}).get("utf8_bytes", 0)) for item in items),
                 "analysis_ms": round(sum(analysis_ms(item) for item in items), 3),
                 "model_ms": round(sum(item.get("model", {}).get("model_elapsed_ms", 0) for item in items), 3),
                 "end_to_end_ms": round(sum(item.get("end_to_end_ms", 0) for item in items), 3),
                 "timeouts": sum(bool(item.get("score", {}).get("timeout")) for item in items)}
        if task == "objective":
            per_field: dict[str, Any] = {}
            for field in OBJECTIVE_FIELDS:
                details = [score.get("field_details", {}).get(field, {}) for score in scores]
                per_field[field] = {"exact": sum(bool(item.get("exact")) for item in details),
                    "total": len(details),
                    "precision_mean": sum(float(item.get("precision", item.get("exact", False)))
                                          for item in details) / len(details) if details else 0.0,
                    "recall_mean": sum(float(item.get("recall", item.get("exact", False)))
                                       for item in details) / len(details) if details else 0.0,
                    "f1_mean": sum(float(item.get("f1", item.get("exact", False)))
                                   for item in details) / len(details) if details else 0.0}
            group.update({"fields_correct": sum(item.get("fields_correct", 0) for item in scores),
                          "semantic_points": sum(item.get("semantic_points", 0.0)
                                                 for item in scores),
                          "artifact_core_fields": sum(item.get("artifact_core_fields", 0)
                                                      for item in scores),
                          "artifact_core_exact": sum(item.get("artifact_core_exact", 0)
                                                     for item in scores),
                          "artifact_core_semantic_points": sum(
                              item.get("artifact_core_semantic_points", 0.0)
                              for item in scores),
                          "schema_valid": sum(bool(item.get("schema_valid")) for item in scores),
                          "fields_total": sum(item.get("fields_total", 0) for item in scores),
                          "evidence_valid": sum(item.get("evidence_valid", 0) for item in scores),
                          "evidence_total": sum(item.get("evidence_total", 0) for item in scores),
                          "unsupported_claims": sum(item.get("unsupported_claims", 0) for item in scores),
                          "claims": sum(item.get("claims", 0) for item in scores),
                          "unknown_fields": sum(item.get("unknown_fields", 0) for item in scores),
                          "per_field": per_field})
        else:
            group.update({"compiled": sum(bool(item.get("compiled")) for item in scores),
                          "tests_passed": sum(item.get("tests_passed", 0) for item in scores),
                          "tests_total": sum(item.get("tests_total", 0) for item in scores)})
        output["groups"]["/".join(key)] = group
        group["rates"] = {
            "objective_exact_accuracy": group.get("fields_correct", 0) / group.get("fields_total", 1)
                if task == "objective" and group.get("fields_total", 0) else 0.0,
            "objective_semantic_accuracy": group.get("semantic_points", 0.0) /
                group.get("fields_total", 1)
                if task == "objective" and group.get("fields_total", 0) else 0.0,
            "artifact_core_exact_accuracy": group.get("artifact_core_exact", 0) /
                group.get("artifact_core_fields", 1)
                if task == "objective" and group.get("artifact_core_fields", 0) else 0.0,
            "artifact_core_semantic_accuracy": group.get(
                "artifact_core_semantic_points", 0.0) /
                group.get("artifact_core_fields", 1)
                if task == "objective" and group.get("artifact_core_fields", 0) else 0.0,
            "schema_validity": group.get("schema_valid", 0) / group["runs"]
                if task == "objective" and group["runs"] else None,
            "protocol_compliance": group.get("protocol_clean", 0) /
                group.get("protocol_applicable", 1)
                if group.get("protocol_applicable", 0) else None,
            "final_structure": group.get("final_structure_valid", 0) / group["runs"]
                if group["runs"] else 0.0,
            "raw_structure": group.get("raw_structure_valid", 0) / group["runs"]
                if group["runs"] else 0.0,
            "evidence_validity": group.get("evidence_valid", 0) / group.get("evidence_total", 1)
                if task == "objective" and group.get("evidence_total", 0) else 0.0,
            "unsupported_claim": group.get("unsupported_claims", 0) / group.get("claims", 1)
                if task == "objective" and group.get("claims", 0) else 0.0,
            "explicit_unknown": group.get("unknown_fields", 0) / group.get("fields_total", 1)
                if task == "objective" and group.get("fields_total", 0) else 0.0,
            "compile": group.get("compiled", 0) / group["runs"] if task == "reconstruction" else None,
            "behavioral": group.get("tests_passed", 0) / group.get("tests_total", 1)
                if task == "reconstruction" and group.get("tests_total", 0) else None}

    output["clustered_paired"] = {}
    for track in sorted({item["track"] for item in records}):
        for task in ("objective", "reconstruction"):
            by_key: dict[tuple[str, int], dict[str, dict[str, Any]]] = defaultdict(dict)
            for item in records:
                if item["track"] == track and item["task"] == task and not item.get("failure"):
                    by_key[(item["case_id"], item["repetition"])][item["condition"]] = item
            metric_pairs: dict[str, list[tuple[float, float]]] = defaultdict(list)
            metric_clusters: dict[str, dict[str, list[tuple[float, float]]]] = defaultdict(
                lambda: defaultdict(list))
            for pair in by_key.values():
                if set(pair) != {"airece", "ghidra"}: continue
                left, right = pair["airece"], pair["ghidra"]
                program_id = str(left.get("program_id", left["case_id"]))
                if task == "objective":
                    exact = (left["score"].get("exact_accuracy", 0.0),
                             right["score"].get("exact_accuracy", 0.0))
                    semantic = (left["score"]["semantic_accuracy"],
                                right["score"]["semantic_accuracy"])
                    metric_pairs["exact_accuracy"].append(exact)
                    metric_pairs["semantic_accuracy"].append(semantic)
                    metric_clusters["exact_accuracy"][program_id].append(exact)
                    metric_clusters["semantic_accuracy"][program_id].append(semantic)
                    artifact_exact = (left["score"].get("artifact_core_exact_accuracy", 0.0),
                                      right["score"].get("artifact_core_exact_accuracy", 0.0))
                    artifact_semantic = (
                        left["score"].get("artifact_core_semantic_accuracy", 0.0),
                        right["score"].get("artifact_core_semantic_accuracy", 0.0))
                    metric_pairs["artifact_core_exact_accuracy"].append(artifact_exact)
                    metric_pairs["artifact_core_semantic_accuracy"].append(artifact_semantic)
                    metric_clusters["artifact_core_exact_accuracy"][program_id].append(
                        artifact_exact)
                    metric_clusters["artifact_core_semantic_accuracy"][program_id].append(
                        artifact_semantic)
                else:
                    behavioral = (left["score"]["behavioral_rate"],
                                  right["score"]["behavioral_rate"])
                    metric_pairs["behavioral_rate"].append(behavioral)
                    metric_clusters["behavioral_rate"][program_id].append(behavioral)
                tokens = (left["model"]["usage"]["total_tokens"],
                          right["model"]["usage"]["total_tokens"])
                metric_pairs["total_tokens"].append(tokens)
                metric_clusters["total_tokens"][program_id].append(tokens)
            output["paired"][f"{track}/{task}"] = {
                name: bootstrap_interval(pairs, seed + index)
                for index, (name, pairs) in enumerate(sorted(metric_pairs.items()))}
            output["clustered_paired"][f"{track}/{task}"] = {
                name: bootstrap_interval([
                    (sum(left for left, _ in values) / len(values),
                     sum(right for _, right in values) / len(values))
                    for values in clusters.values()], seed + 100 + index)
                for index, (name, clusters) in enumerate(sorted(metric_clusters.items()))}
    return output
