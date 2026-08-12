from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from benchmarks.airece_bench.backends import Backend, tool_schema
from benchmarks.airece_bench.corpus import (FUNCTIONS, TEST_INPUTS, dense, direct_calls,
                                            indirect, local_array, nested, recursive,
                                            rotate, sparse, structure)
from benchmarks.airece_bench.prompts import (extract_sections, instructions,
                                             validate_isolation)
from benchmarks.airece_bench.lmstudio import (LMStudioAdapter,
                                               compact_tool_evidence)
from benchmarks.airece_bench.runner import (_assert_semantic_context, _records,
                                             _normalize_direct_final, _select_cases,
                                             _validate_direct_final,
                                             rebuild_jsonl)
from benchmarks.airece_bench.scoring import (extract_c_function, extract_json,
                                             score_objective, summarize,
                                             validate_objective)
from benchmarks.airece_bench.util import atomic_write_json, canonical_json, sha256_bytes


ROOT = pathlib.Path(__file__).resolve().parents[2]


class PromptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sections = extract_sections(ROOT / "docs" / "benchmark-tool-instructions.md")

    def test_common_schema_parity(self) -> None:
        left = canonical_json(tool_schema("common", "airece"))
        right = canonical_json(tool_schema("common", "ghidra"))
        self.assertEqual(left, right)
        self.assertEqual(sha256_bytes(left.encode()), sha256_bytes(right.encode()))
        self.assertEqual(left, canonical_json(tool_schema("single", "airece")))

    def test_native_schema_uses_progressive_disclosure(self) -> None:
        airece = {item["name"]: item for item in tool_schema("native", "airece")}
        self.assertNotIn("inspect", airece)
        self.assertNotIn("functions", airece)
        self.assertEqual(airece["fn"]["parameters"]["required"], ["address"])
        self.assertNotIn("view", airece["fn"]["parameters"]["properties"])
        detail_views = airece["fn_detail"]["parameters"]["properties"]["view"]["enum"]
        self.assertNotIn("agent", detail_views)
        ghidra = {item["name"]: item for item in tool_schema("native", "ghidra")}
        self.assertNotIn("inspect", ghidra)
        self.assertNotIn("list_functions", ghidra)

    def test_instruction_pack_isolation_and_hashing(self) -> None:
        common = instructions(self.sections, "common", "airece")
        validate_isolation(self.sections, common, "common", "airece", ["case-secret"])
        airece = instructions(self.sections, "native", "airece")
        ghidra = instructions(self.sections, "native", "ghidra")
        validate_isolation(self.sections, airece, "native", "airece", ["case-secret"])
        validate_isolation(self.sections, ghidra, "native", "ghidra", ["case-secret"])
        self.assertNotEqual(sha256_bytes(airece.encode()), sha256_bytes(ghidra.encode()))
        with self.assertRaises(ValueError):
            validate_isolation(self.sections, common + " case-secret", "common",
                               "airece", ["case-secret"])


class BackendTests(unittest.TestCase):
    class Dummy(Backend):
        def _execute(self, name, arguments, track):
            return self._bounded({"ok": True, "result": list(range(100))})

    def test_results_are_valid_bounded_json_and_duplicates_are_cached(self) -> None:
        backend = self.Dummy(pathlib.Path("fixture.bin"), 256)
        first = backend.execute("inspect", {}, "common")
        self.assertLessEqual(len(first.encode("utf-8")), 256)
        value = json.loads(first)
        self.assertGreater(value["omitted"]["records"], 0)
        duplicate = json.loads(backend.execute("inspect", {}, "common"))
        self.assertEqual(duplicate, {"ok": True, "same_result_as_call": 1})


class ParserScoringTests(unittest.TestCase):
    def test_json_extraction_and_schema(self) -> None:
        answer = {"answers": [
            {"question_id": "q1", "status": "answered", "parameter_count": 2,
             "category": "bit-manipulation", "constants": [31, -1515870811],
             "control_shape": "straight-line", "case_values": [],
             "return_dependencies": [], "stack_memory_reads": None,
             "stack_memory_writes": None, "external_memory_reads": None,
             "external_memory_writes": None, "direct_call_count": None,
             "indirect_call_count": None, "imported_call_count": None,
             "evidence": ["0x1000"], "unknown_reason": None},
            {"question_id": "q2", "status": "answered", "parameter_count": None,
             "category": None, "constants": [], "case_values": [],
             "control_shape": None, "return_dependencies": ["arg0", "arg1"],
             "stack_memory_reads": False, "stack_memory_writes": False,
             "external_memory_reads": False, "external_memory_writes": False,
             "direct_call_count": 0, "indirect_call_count": 0,
             "imported_call_count": 0,
             "evidence": ["0x1001"], "unknown_reason": None}]}
        parsed, error = extract_json("```json\n" + json.dumps(answer) + "\n```")
        self.assertIsNone(error)
        self.assertEqual(validate_objective(parsed), [])
        truth = {key: value for key, value in FUNCTIONS["f_19a7d3e1"].items()
                 if key not in {"source", "oracle"}}
        truth["parameter_count"] = 2
        truth.update({"control_shape": "straight-line",
            "stack_memory_reads": False, "stack_memory_writes": False,
            "external_memory_reads": False, "external_memory_writes": False,
            "indirect_call_count": 0, "imported_call_count": 0})
        truth.pop("memory_reads")
        truth.pop("memory_writes")
        score = score_objective(json.dumps(answer), truth,
            [{"result": "addresses 0x1000 and 0x1001"}], 0x1000, 0x1010)
        # An explicitly answered empty no-switch set is a meaningful correct result.
        self.assertEqual(score["fields_correct"], score["fields_total"])
        self.assertEqual(score["evidence_valid"], 2)

        unknown = json.loads(json.dumps(answer))
        unknown["answers"][0]["status"] = "unknown"
        unknown_score = score_objective(json.dumps(unknown), truth, [], 0x1000, 0x1010)
        self.assertFalse(unknown_score["field_details"]["parameter_count"]["exact"])
        self.assertEqual(unknown_score["field_details"]["constants"]["f1"], 1.0)
        self.assertFalse(unknown_score["field_details"]["constants"]["exact"])

        malformed = {"answers": [{"question_id": "q1"}]}
        self.assertTrue(validate_objective(malformed))
        wrong_type = json.loads(json.dumps(answer))
        wrong_type["answers"][0]["parameter_count"] = "two"
        wrong_type["answers"][0]["category"] = "invented"
        self.assertGreaterEqual(len(validate_objective(wrong_type)), 2)

    def test_source_extraction(self) -> None:
        function, error = extract_c_function(
            "uint32_t target(uint32_t a, uint32_t b) { return a + b; }")
        self.assertIsNone(error)
        self.assertIn("return a + b", function)
        function, error = extract_c_function(
            "uint32_t target(uint32_t a, uint32_t b) { system(\"x\"); return 0; }")
        self.assertIsNone(function)
        self.assertIn("forbidden", error)

    def test_direct_final_validation_rejects_recoverable_wrappers(self) -> None:
        function = "uint32_t target(uint32_t a, uint32_t b) { return a + b; }"
        self.assertEqual(_validate_direct_final("reconstruction", function), [])
        self.assertTrue(_validate_direct_final("reconstruction", "```c\n" + function + "\n```"))
        self.assertTrue(_validate_direct_final("objective", "```json\n{}\n```"))
        self.assertTrue(_validate_direct_final("reconstruction",
            "uint32_t target(uint32_t a, uint32_t b) { return load32(buffer_v1); }"))
        self.assertEqual(_normalize_direct_final(
            "reconstruction", "```c\n" + function + "\n```"), function)
        wrapped = json.dumps({"analysis": {"code": function}})
        self.assertEqual(_normalize_direct_final("reconstruction", wrapped), function)
        structured = json.dumps({
            "function_name": "target", "return_type": "uint32_t",
            "parameters": [{"name": "a", "type": "uint32_t"},
                           {"name": "b", "type": "uint32_t"}],
            "body": "return a + b;"})
        structured_function = _normalize_direct_final("reconstruction", structured)
        self.assertEqual(_validate_direct_final("reconstruction", structured_function), [])
        self.assertIn("return a + b;", structured_function)

    def test_objective_normalizer_repairs_only_structure(self) -> None:
        malformed = {"answers": [
            {"question_id": "q1", "status": "answered", "constants": ["0x7"],
             "case_values": None, "extra": "discard"},
            {"question_id": "q2", "status": "answered", "constants": None,
             "case_values": []}]}
        normalized = _normalize_direct_final("objective", json.dumps(malformed))
        value = json.loads(normalized)
        self.assertEqual(_validate_direct_final("objective", normalized), [])
        self.assertEqual(value["answers"][0]["constants"], [7])
        self.assertEqual(value["answers"][0]["case_values"], [])
        self.assertNotIn("extra", value["answers"][0])


class CorpusTests(unittest.TestCase):
    def test_oracles_are_bounded_and_deterministic(self) -> None:
        functions = [rotate, sparse, local_array, nested, direct_calls,
                     structure, recursive, dense, indirect]
        for function in functions:
            first = [function(a, b) for a, b in TEST_INPUTS]
            second = [function(a, b) for a, b in TEST_INPUTS]
            self.assertEqual(first, second)
            self.assertTrue(all(0 <= value <= 0xffffffff for value in first))

    def test_category_selection_is_deterministic(self) -> None:
        cases = [
            {"case_id": "slow", "artifact_id": "clangcl-o0-static-cpp",
             "truth": {"category": "dense-switch"}},
            {"case_id": "preferred", "artifact_id": "msvc-o2-none-cpp",
             "truth": {"category": "dense-switch"}},
            {"case_id": "global", "artifact_id": "msvc-o2-none-cpp",
             "truth": {"category": "global-read-write"}},
        ]
        config = {"selection_categories": ["dense-switch", "global-read-write"],
                  "corpus": {"seed": 1}}
        self.assertEqual([item["case_id"] for item in _select_cases(cases, config, 5)],
                         ["preferred", "global"])

    def test_balanced_selection_uses_one_case_per_category(self) -> None:
        cases = [
            {"case_id": "a1", "truth": {"category": "a"}},
            {"case_id": "a2", "truth": {"category": "a"}},
            {"case_id": "b1", "truth": {"category": "b"}},
        ]
        config = {"selection_balance_categories": True, "corpus": {"seed": 9}}
        selected = _select_cases(cases, config, 20)
        self.assertEqual(len(selected), 2)
        self.assertEqual({item["truth"]["category"] for item in selected}, {"a", "b"})

    def test_semantic_contract_covers_every_category(self) -> None:
        dense_results = ["arg1 + 0xb", "arg1 * 3", "arg1 - 0x13",
                         "arg1 ^ 0x55", "arg1 + 0x65", "arg1 - 7"]
        contexts = {
            "dense-switch": {"switches": [{"selector": "arg0 & 7",
                "cases": [{"value": index, "result": result}
                          for index, result in enumerate(dense_results)],
                "default": {"result": "arg1 ^ 0x313"}}]},
            "bit-manipulation": {"returns": [{"expression": "arg0 ^ arg1"}],
                "constants": ["0x1f", "0xa5a5a5a5"]},
            "sparse-switch": {"returns": [{"expression": str(index)} for index in range(4)],
                "conditions": [{"expression": "arg0 == 3 | arg0 == 9 | arg0 == 0x11"}]},
            "loop-and-array": {"returns": [{"expression": "arg0 + arg1 * 4"}],
                "constants": ["0x4"]},
            "nested-branches": {"returns": [{"expression": "a"}, {"expression": "b"}],
                "conditions": [{"expression": "a"}, {"expression": "b"}],
                "paths": [{"when": ["a"], "result": "a"},
                           {"when": ["not(a)"], "result": "b"}]},
            "direct-calls": {"calls": [{"kind_target": "direct:0x1(arg0=arg0)"},
                                          {"kind_target": "direct:0x1(arg0=arg1)"}],
                "returns": [{"expression": "result(direct:0x1) ^ result(direct:0x1)"}]},
            "recursion": {"calls": [{"kind_target": "direct:0x1"}]},
            "api-source-sink-flow": {"calls": [{"kind_target": "imported:0x1"},
                                                   {"kind_target": "imported:0x2"}],
                "memory_effects": [{"effect": "read:api-mediated"}]},
            "global-read-write": {"memory_effects": [{"effect": "read:global"},
                {"effect": "write:global", "expression": "arg0 ^ arg1"}],
                "state_updates": [{"prior_value": "global(initial=0x1)",
                                   "new_value": "arg0 ^ arg1",
                                   "persists_across_calls": True}]},
            "structure-access": {"returns": [{"expression": "arg0 + arg1"}],
                "constants": ["0x9", "0x1234"]},
            "indirect-call": {"calls": [{"kind_target": "indirect"}]},
        }
        self.assertEqual(set(contexts), {item["category"] for item in FUNCTIONS.values()})
        for context in contexts.values():
            context["function"] = {"parameter_count": 2}
        self.assertTrue(all(_assert_semantic_context(category, context)
                            for category, context in contexts.items()))


class ResumeTests(unittest.TestCase):
    def test_atomic_records_rebuild_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            atomic_write_json(root / "records" / "b.json", {"run_id": "b", "value": 2})
            atomic_write_json(root / "records" / "a.json", {"run_id": "a", "value": 1})
            records = _records(root)
            rebuild_jsonl(root, records)
            lines = [json.loads(line) for line in
                     (root / "runs.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual([item["run_id"] for item in lines], ["a", "b"])

    def test_records_can_be_isolated_to_selected_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            atomic_write_json(root / "records" / "dev.json", {
                "run_id": "dev", "config_fingerprint": "same", "case_id": "development"})
            atomic_write_json(root / "records" / "heldout.json", {
                "run_id": "heldout", "config_fingerprint": "same", "case_id": "heldout"})
            records = _records(root, "same", {"heldout"})
            self.assertEqual([item["run_id"] for item in records], ["heldout"])

    def test_all_failure_summary_has_zero_rates(self) -> None:
        result = summarize([{
            "run_id": "failed", "case_id": "case", "repetition": 0,
            "track": "common", "task": "objective", "condition": "airece",
            "failure": {"type": "Unavailable", "message": "offline"},
        }])
        group = result["groups"]["common/airece/objective"]
        self.assertEqual(group["rates"]["objective_exact_accuracy"], 0.0)
        self.assertEqual(group["rates"]["objective_semantic_accuracy"], 0.0)
        self.assertEqual(group["rates"]["explicit_unknown"], 0.0)

    def test_program_clustered_summary_averages_compiler_variants(self) -> None:
        records = []
        for case_id, left, right in (("variant-a", 1.0, 0.0),
                                     ("variant-b", 0.0, 0.0)):
            for condition, rate in (("airece", left), ("ghidra", right)):
                records.append({"run_id": case_id + condition, "case_id": case_id,
                    "program_id": "same-program", "repetition": 0, "track": "single",
                    "task": "reconstruction", "condition": condition,
                    "model": {"usage": {"total_tokens": 1}},
                    "score": {"behavioral_rate": rate}})
        clustered = summarize(records)["clustered_paired"]["single/reconstruction"]
        self.assertEqual(clustered["behavioral_rate"]["pairs"], 1)
        self.assertEqual(clustered["behavioral_rate"]["difference"], 0.5)


class ToolBudgetTests(unittest.TestCase):
    def test_openrouter_probe_uses_env_file_without_exposing_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            env_path = pathlib.Path(directory) / ".env"
            env_path.write_text("open_router_key=secret-test-key\n", encoding="utf-8")
            adapter = LMStudioAdapter({"provider": "openrouter", "id": "x-ai/test",
                "base_urls": ["https://unused/api"], "responses_path": "/v1/responses",
                "temperature": 0, "seed": 1, "max_output_tokens": 32,
                "api_key_env": "open_router_key", "env_file": str(env_path),
                "minimum_context_length": 16384}, 10)
            adapter._request = lambda *args, **kwargs: ({"data": [{
                "id": "x-ai/test", "context_length": 500000,
                "supported_parameters": ["tools", "structured_outputs"]}]},
                {"authorization": "must-not-survive"}, 1.0)  # type: ignore[method-assign]
            metadata = adapter.probe()
            self.assertEqual(metadata["provider"], "openrouter")
            self.assertEqual(metadata["required_model"], "x-ai/test")
            self.assertNotIn("authorization", metadata["response_headers"])
            self.assertEqual(adapter._sanitize("secret-test-key"), "<REDACTED_PATH>")

    def test_compact_final_evidence_deduplicates_and_prefers_baseline(self) -> None:
        baseline = '{"result":"agent"}'
        events = [
            {"name": "fn", "baseline": True, "arguments": {"address": "0x1"},
             "result": baseline},
            {"name": "inspect", "arguments": {}, "result": '{"program":true}'},
            {"name": "fn", "arguments": {"address": "0x1"}, "result": baseline},
            {"name": "fn", "arguments": {"address": "0x1"},
             "result": '{"ok":true,"same_result_as_call":1}'},
        ]
        evidence, summary = compact_tool_evidence(events, 1000)
        self.assertEqual([item["tool"] for item in evidence], ["fn"])
        self.assertEqual(summary["included"], 1)
        self.assertEqual(summary["omitted"], 3)

    def test_direct_final_records_and_repairs_invalid_structure(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"wrong":true}'}]}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"ok":true}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_direct_final(
            "instructions", "input", '{"context":true}',
            lambda text: [] if json.loads(text) == {"ok": True} else ["wrong fields"],
            10000, {"type": "object"})
        self.assertEqual(result["raw_final_text"], '{"wrong":true}')
        self.assertEqual(result["final_text"], '{"ok":true}')
        self.assertTrue(result["repair_attempted"])
        self.assertTrue(result["repair_succeeded"])
        self.assertIn("validation_errors", json.loads(result["requests"][1]["input"]))

    def test_exhausted_budget_forces_final_turn(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [
                {"type": "function_call", "call_id": "call-one", "name": "echo",
                 "arguments": "{}"}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [
                {"type": "message", "content": [
                    {"type": "output_text", "text": "done"}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_tools("instructions", "input", [],
                                   lambda name, args: "{}", 1, 10000)
        self.assertEqual(result["final_text"], "done")
        self.assertEqual(result["requests"][1]["tool_choice"], "none")
        self.assertEqual(len(result["tool_events"]), 1)

    def test_json_protocol_tool_then_final(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32,
            "reasoning": {"effort": "none"}}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"tool","name":"echo","arguments":{"value":"OK"}}'}]}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"final","content":"OK"}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        tools = [{"type": "function", "name": "echo", "description": "Echo",
                  "parameters": {"type": "object", "properties": {}}}]
        result = adapter.run_json_protocol(
            "instructions", "input", tools,
            lambda name, args: '{"value":"OK"}', 2, 10000)
        self.assertEqual(result["final_text"], "OK")
        self.assertEqual(result["transport"], "json-protocol")
        self.assertEqual(result["tool_events"][0]["name"], "echo")
        self.assertNotIn("previous_response_id", result["requests"][1])
        self.assertFalse(result["requests"][1]["store"])
        second_envelope = json.loads(result["requests"][1]["input"])
        self.assertEqual(second_envelope["transcript"][0]["assistant"]["name"], "echo")

    def test_json_protocol_initial_context_and_duplicate_force_final(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"status": "completed", "usage": {}, "output": [{"type": "message",
                "content": [{"type": "output_text", "text":
                    '{"action":"tool","name":"fn","arguments":{"address":"0x1"}}'}]}]},
            {"status": "completed", "usage": {}, "output": [{"type": "message",
                "content": [{"type": "output_text", "text":
                    '{"action":"final","content":"done"}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        initial = [{"name": "fn", "arguments": {"address": "0x1"},
                    "baseline": True, "result": '{"result":"agent"}'}]
        result = adapter.run_json_protocol("instructions", "input",
            [{"name": "fn", "parameters": {}}],
            lambda name, args: '{"ok":true,"same_result_as_call":1}',
            3, 10000, initial_tool_events=initial)
        first_envelope = json.loads(result["requests"][0]["input"])
        self.assertEqual(first_envelope["initial_context"][0]["tool"], "fn")
        self.assertEqual(result["duplicate_tool_calls"], 1)
        self.assertIn("Tool access is exhausted", result["requests"][1]["instructions"])

    def test_json_protocol_repairs_invalid_separated_final(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32,
            "separate_final_generation": True}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"status": "completed", "usage": {}, "output": [{"type": "message",
                "content": [{"type": "output_text", "text":
                    '{"action":"final","content":{"draft":true}}'}]}]},
            {"status": "completed", "usage": {}, "output": [{"type": "message",
                "content": [{"type": "output_text", "text": '{"wrong":true}'}]}]},
            {"status": "completed", "usage": {}, "output": [{"type": "message",
                "content": [{"type": "output_text", "text": '{"ok":true}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        validator = lambda text: [] if json.loads(text) == {"ok": True} else ["wrong"]
        result = adapter.run_json_protocol("instructions", "input", [],
            lambda name, args: "{}", 1, 10000,
            final_validator=validator)
        self.assertEqual(result["raw_final_text"], '{"wrong":true}')
        self.assertEqual(result["final_text"], '{"ok":true}')
        self.assertTrue(result["repair_attempted"])
        self.assertTrue(result["repair_succeeded"])

    def test_json_protocol_removes_tools_after_budget(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"tool","name":"echo","arguments":{}}'}]}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"final","content":"done"}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_json_protocol(
            "instructions", "input", [{"name": "echo", "parameters": {}}],
            lambda name, args: "{}", 1, 10000)
        self.assertEqual(result["final_text"], "done")
        self.assertIn("Tool access is exhausted", result["requests"][1]["instructions"])
        self.assertNotIn("Tool catalog", result["requests"][1]["instructions"])

    def test_json_protocol_accepts_nonfinal_response_after_budget(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"tool","name":"echo","arguments":{}}'}]}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"tool","name":"echo","arguments":{}}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_json_protocol(
            "instructions", "input", [{"name": "echo", "parameters": {}}],
            lambda name, args: "{}", 1, 10000)
        self.assertEqual(result["final_text"],
                         '{"action":"tool","name":"echo","arguments":{}}')
        self.assertEqual(result["protocol_recoveries"],
                         ["accepted raw final after tool budget exhaustion"])

    def test_json_protocol_compacts_old_tool_results(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32,
            "max_protocol_request_bytes": 2500}, 10)
        adapter.base_url = "http://unused"
        responses = iter([
            {"id": "one", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"tool","name":"echo","arguments":{}}'}]}]},
            {"id": "two", "status": "completed", "usage": {}, "output": [{
                "type": "message", "content": [{"type": "output_text",
                    "text": '{"action":"final","content":"done"}'}]}]},
        ])
        adapter._request = lambda *args, **kwargs: (next(responses), {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_json_protocol(
            "instructions", "input", [{"name": "echo", "parameters": {}}],
            lambda name, args: "x" * 5000, 2, 10000)
        compactions = result["requests"][1]["_transcript_compactions"]
        self.assertEqual(len(compactions), 1)
        self.assertEqual(compactions[0]["utf8_bytes"], 5000)

    def test_json_protocol_accepts_implicit_final(self) -> None:
        adapter = LMStudioAdapter({"id": "model", "base_urls": ["http://unused"],
            "responses_path": "/v1/responses", "native_chat_path": "/api/v1/chat",
            "temperature": 0, "seed": 1, "max_output_tokens": 32}, 10)
        adapter.base_url = "http://unused"
        response = {"id": "one", "status": "completed", "usage": {}, "output": [{
            "type": "message", "content": [{"type": "output_text",
                "text": "uint32_t target(uint32_t a, uint32_t b) { return a + b; }"}]}]}
        adapter._request = lambda *args, **kwargs: (response, {}, 1.0)  # type: ignore[method-assign]
        result = adapter.run_json_protocol(
            "instructions", "input", [{"name": "echo", "parameters": {}}],
            lambda name, args: "{}", 1, 10000)
        self.assertIn("uint32_t target", result["final_text"])
        self.assertEqual(result["protocol_recoveries"],
                         ["accepted non-protocol model output as final"])


if __name__ == "__main__":
    unittest.main()
