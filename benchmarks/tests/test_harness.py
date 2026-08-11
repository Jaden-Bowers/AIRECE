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
from benchmarks.airece_bench.lmstudio import LMStudioAdapter
from benchmarks.airece_bench.runner import _records, rebuild_jsonl
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
        # An empty no-switch set is not awarded as a recovered semantic fact.
        self.assertEqual(score["fields_correct"], score["fields_total"] - 1)
        self.assertEqual(score["evidence_valid"], 2)

        unknown = json.loads(json.dumps(answer))
        unknown["answers"][0]["status"] = "unknown"
        unknown_score = score_objective(json.dumps(unknown), truth, [], 0x1000, 0x1010)
        self.assertFalse(unknown_score["field_details"]["parameter_count"]["exact"])
        self.assertEqual(unknown_score["field_details"]["constants"]["f1"], 1.0)
        self.assertFalse(unknown_score["field_details"]["constants"]["exact"])

        malformed = {"answers": [{"question_id": "q1"}]}
        self.assertTrue(validate_objective(malformed))

    def test_source_extraction(self) -> None:
        function, error = extract_c_function(
            "uint32_t target(uint32_t a, uint32_t b) { return a + b; }")
        self.assertIsNone(error)
        self.assertIn("return a + b", function)
        function, error = extract_c_function(
            "uint32_t target(uint32_t a, uint32_t b) { system(\"x\"); return 0; }")
        self.assertIsNone(function)
        self.assertIn("forbidden", error)


class CorpusTests(unittest.TestCase):
    def test_oracles_are_bounded_and_deterministic(self) -> None:
        functions = [rotate, sparse, local_array, nested, direct_calls,
                     structure, recursive, dense, indirect]
        for function in functions:
            first = [function(a, b) for a, b in TEST_INPUTS]
            second = [function(a, b) for a, b in TEST_INPUTS]
            self.assertEqual(first, second)
            self.assertTrue(all(0 <= value <= 0xffffffff for value in first))


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
        self.assertEqual(group["rates"]["objective_accuracy"], 0.0)
        self.assertEqual(group["rates"]["explicit_unknown"], 0.0)


class ToolBudgetTests(unittest.TestCase):
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
