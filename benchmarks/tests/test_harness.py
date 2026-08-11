from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from benchmarks.airece_bench.backends import tool_schema
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


class ParserScoringTests(unittest.TestCase):
    def test_json_extraction_and_schema(self) -> None:
        answer = {"answers": [
            {"question_id": "q1", "status": "answered", "parameter_count": 2,
             "category": "bit-manipulation", "constants": [31, 0xa5a5a5a5],
             "case_values": [], "return_dependencies": [], "memory_reads": None,
             "memory_writes": None, "direct_call_count": None,
             "evidence": ["0x1000"], "unknown_reason": None},
            {"question_id": "q2", "status": "answered", "parameter_count": None,
             "category": None, "constants": [], "case_values": [],
             "return_dependencies": ["arg0", "arg1"], "memory_reads": False,
             "memory_writes": False, "direct_call_count": 0,
             "evidence": ["0x1001"], "unknown_reason": None}]}
        parsed, error = extract_json("```json\n" + json.dumps(answer) + "\n```")
        self.assertIsNone(error)
        self.assertEqual(validate_objective(parsed), [])
        truth = {key: value for key, value in FUNCTIONS["f_19a7d3e1"].items()
                 if key not in {"source", "oracle"}}
        truth["parameter_count"] = 2
        score = score_objective(json.dumps(answer), truth,
            [{"result": "addresses 0x1000 and 0x1001"}], 0x1000, 0x1010)
        self.assertEqual(score["fields_correct"], score["fields_total"])
        self.assertEqual(score["evidence_valid"], 2)

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


if __name__ == "__main__":
    unittest.main()
