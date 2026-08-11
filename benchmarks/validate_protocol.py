#!/usr/bin/env python3
"""Run a small structural validation suite against the configured local model."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from benchmarks.airece_bench.lmstudio import LMStudioAdapter  # noqa: E402
from benchmarks.airece_bench.util import atomic_write_json, load_json  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=pathlib.Path,
                        default=pathlib.Path("benchmarks/config.json"))
    parser.add_argument("--cases", type=int, default=20)
    parser.add_argument("--output", type=pathlib.Path,
                        default=pathlib.Path("out/protocol-validation.json"))
    arguments = parser.parse_args()
    config = load_json(arguments.config)["model"]
    adapter = LMStudioAdapter(config, 60)
    adapter.probe()
    records = []
    for index in range(arguments.cases):
        schema = {"type": "object", "additionalProperties": False,
                  "properties": {"case": {"type": "integer", "const": index},
                                 "valid": {"type": "boolean", "const": True}},
                  "required": ["case", "valid"]}
        try:
            result = adapter.run_json_protocol(
                "Follow the requested output contract exactly.",
                f"Return the JSON object for validation case {index} with valid true.",
                [], lambda _name, _arguments: "{}", 0, 120000, schema)
            value = json.loads(result["final_text"])
            structurally_valid = (isinstance(value, dict) and set(value) == {"case", "valid"}
                                  and isinstance(value["case"], int)
                                  and isinstance(value["valid"], bool))
            semantically_valid = value == {"case": index, "valid": True}
            protocol = result["protocol_compliance"]
            records.append({"case": index, "structurally_valid": structurally_valid,
                            "semantically_valid": semantically_valid,
                            "protocol_errors": protocol["errors"],
                            "protocol_recoveries": protocol["recoveries"],
                            "requests": len(result["requests"])})
        except Exception as error:
            records.append({"case": index, "structurally_valid": False,
                            "error": f"{type(error).__name__}: {error}"})
        atomic_write_json(arguments.output, {"schema": "airece.protocol-validation.v1",
            "requested": arguments.cases, "completed": len(records), "records": records})
    valid = sum(item["structurally_valid"] for item in records)
    report = {"schema": "airece.protocol-validation.v1", "requested": arguments.cases,
              "completed": len(records), "structurally_valid": valid,
              "structural_validity_rate": valid / len(records) if records else 0.0,
              "semantically_valid": sum(item.get("semantically_valid", False)
                                        for item in records),
              "protocol_clean": sum(not item.get("protocol_errors", 0) and
                                    not item.get("protocol_recoveries", 0)
                                    for item in records), "records": records}
    atomic_write_json(arguments.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["structural_validity_rate"] >= 0.95 else 1


if __name__ == "__main__":
    raise SystemExit(main())
