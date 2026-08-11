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
from benchmarks.airece_bench.runner import _records, rebuild_jsonl
from benchmarks.airece_bench.scoring import (extract_c_function, extract_json,
                                             score_objective, validate_objective)
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


if __name__ == "__main__":
    unittest.main()

