from __future__ import annotations

import json
import pathlib
import random
import time
from typing import Any

from .backends import AireceBackend, GhidraBackend, GhidraExtractor, tool_schema
from .corpus import build as build_corpus
from .lmstudio import LMStudioAdapter
from .prompts import (OBJECTIVE_SCHEMA, extract_sections, instructions, objective_prompt,
                      prompt_snapshot, reconstruction_prompt, validate_isolation)
from .scoring import score_objective, score_reconstruction, summarize
from .util import (atomic_write_json, atomic_write_text, canonical_json, load_json,
                   resolve, run, sha256_bytes, sha256_file)


def git(root: pathlib.Path, *arguments: str) -> str | None:
    result = run(["git", "-C", str(root), *arguments], root, 15)
    return result["stdout"].strip() if result["exit"] == 0 else None


def _records(output: pathlib.Path, config_fingerprint: str | None = None,
             case_ids: set[str] | None = None) -> list[dict[str, Any]]:
    records = []
    for path in sorted((output / "records").glob("*.json")) if (output / "records").is_dir() else []:
        try:
            record = load_json(path)
            matches_config = (config_fingerprint is None or
                              record.get("config_fingerprint") == config_fingerprint)
            matches_case = case_ids is None or record.get("case_id") in case_ids
            if matches_config and matches_case:
                records.append(record)
        except (OSError, json.JSONDecodeError):
            continue
    return records


def rebuild_jsonl(output: pathlib.Path, records: list[dict[str, Any]]) -> None:
    atomic_write_text(output / "runs.jsonl", "".join(
        canonical_json(record) + "\n" for record in sorted(records, key=lambda item: item["run_id"])))


def _function_bounds(document: dict[str, Any], address: str) -> tuple[int, int]:
    wanted = int(address, 0)
    for function in document["functions"]:
        if int(function["entry"], 0) == wanted:
            return int(function["body_min"], 0), int(function["body_max"], 0)
    return wanted, wanted


def _preflight_targets(airece: pathlib.Path, cases: list[dict[str, Any]],
                       ghidra: GhidraExtractor, max_bytes: int,
                       analyzer_timeout: float) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    failures: list[str] = []
    dense_results = ["arg1 + 0xb", "arg1 * 3", "arg1 - 0x13",
                     "arg1 ^ 0x55", "arg1 + 0x65", "arg1 - 7"]
    for case in cases:
        binary = pathlib.Path(case["binary"])
        wanted = int(case["target_address"], 0)
        row: dict[str, Any] = {"case_id": case["case_id"],
                               "target_address": case["target_address"]}
        try:
            airece_backend = AireceBackend(
                airece, binary, max_bytes, analyzer_timeout)
            raw = airece_backend.execute("function_context", {
                "address": case["target_address"], "level": "primary"}, "common")
            if len(raw.encode("utf-8")) > max_bytes:
                raise AssertionError("bounded response exceeds configured byte limit")
            envelope = json.loads(raw)
            context = envelope.get("result", {})
            if not envelope.get("ok") or int(context.get("function", {}).get("entry", "-1"), 0) != wanted:
                raise AssertionError("requested AIRECE function was not resolved exactly")
            if int(context.get("function", {}).get("instruction_count", 0)) <= 0:
                raise AssertionError("AIRECE function contains no decoded instructions")
            if envelope.get("omitted") or context.get("omitted", {}).get("facts"):
                raise AssertionError("AIRECE agent context was truncated")
            category = case.get("truth", {}).get("category")
            if category == "dense-switch":
                switches = context.get("switches", [])
                if (len(switches) != 1 or switches[0].get("selector") != "arg0 & 7" or
                        [item.get("value") for item in switches[0].get("cases", [])] != list(range(6)) or
                        [item.get("result") for item in switches[0].get("cases", [])] != dense_results or
                        switches[0].get("default", {}).get("result") != "arg1 ^ 0x313"):
                    raise AssertionError("dense-switch agent semantics are incomplete")
            elif category == "recursion" and not context.get("calls"):
                raise AssertionError("recursion agent context contains no call fact")
            elif category == "nested-branches" and (
                    len(context.get("conditions", [])) < 2 or
                    len(context.get("returns", [])) < 2):
                raise AssertionError("nested-branch agent context lacks conditions or results")
            elif category == "direct-calls" and len(context.get("calls", [])) < 2:
                raise AssertionError("direct-call agent context lacks both call sites")
            elif category == "global-read-write":
                effects = {item.get("effect") for item in context.get("memory_effects", [])}
                if not {"read:global", "write:global"}.issubset(effects):
                    raise AssertionError("global-memory agent context lacks read/write effects")
            row["airece"] = {"available": True, "bytes": len(raw.encode("utf-8")),
                             "instructions": context["function"]["instruction_count"],
                             "semantic_check": category in {"dense-switch", "recursion",
                                 "nested-branches", "direct-calls", "global-read-write"}}

            ghidra_backend = GhidraBackend(ghidra, binary, max_bytes)
            raw = ghidra_backend.execute("function_context", {
                "address": case["target_address"], "level": "low_level"}, "common")
            if len(raw.encode("utf-8")) > max_bytes:
                raise AssertionError("Ghidra bounded response exceeds configured byte limit")
            envelope = json.loads(raw)
            context = envelope.get("result", {})
            if not envelope.get("ok") or int(context.get("entry", "-1"), 0) != wanted:
                raise AssertionError("requested Ghidra function was not resolved exactly")
            instructions = context.get("instructions", [])
            if not instructions:
                raise AssertionError("Ghidra function contains no instructions")
            row["ghidra"] = {"available": True, "bytes": len(raw.encode("utf-8")),
                             "instructions": len(instructions),
                             "omitted_records": envelope.get("omitted", {}).get("records", 0)}
        except (AssertionError, OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
            row["error"] = str(error)
            failures.append(f"{case['case_id']}: {error}")
        report.append(row)
    if failures:
        raise RuntimeError("target preflight failed; model sessions were not started: " +
                           "; ".join(failures))
    return report


def _report(summary: dict[str, Any], manifest: dict[str, Any]) -> str:
    lines = ["# AIRECE AI-utility benchmark report", "",
             f"Status: **{manifest['status']}**", "",
             f"Validated analyzer: `{manifest['analyzer']['tag']}` / "
             f"`{manifest['analyzer']['commit']}`", "",
             f"Model: `{manifest['model']['id']}` via LM Studio Responses", "",
             f"Corpus: {manifest['corpus']['selected_cases']} selected cases from "
             f"{manifest['corpus']['total_cases']} generated cases; "
             f"{manifest['repetitions']} repetition(s).", "",
             "## Raw aggregates", "",
             "| Track / condition / task | Runs | Result counts | Tokens (in/out) | Tool calls |",
             "|---|---:|---|---:|---:|"]
    for key, group in summary.get("groups", {}).items():
        if key.endswith("objective"):
            result = (f"fields {group.get('fields_correct', 0)}/{group.get('fields_total', 0)}; "
                      f"evidence {group.get('evidence_valid', 0)}/{group.get('evidence_total', 0)}; "
                      f"unsupported {group.get('unsupported_claims', 0)}/{group.get('claims', 0)}")
        else:
            result = (f"compile {group.get('compiled', 0)}/{group['runs']}; tests "
                      f"{group.get('tests_passed', 0)}/{group.get('tests_total', 0)}")
        lines.append(f"| {key} | {group['runs']} | {result} | "
                     f"{group['input_tokens']}/{group['output_tokens']} | {group['tool_calls']} |")
    lines += ["", "## Paired differences (AIRECE minus Ghidra)", ""]
    for key, metrics in summary.get("paired", {}).items():
        lines.append(f"### {key}")
        lines.append("")
        for name, value in metrics.items():
            lines.append(f"- {name}: {value['difference']} (paired bootstrap 95% CI "
                         f"{value['ci95']}, n={value['pairs']})")
        lines.append("")
    lines += ["## Interpretation", "",
              "This report separates analyzer health from model usefulness. Missing or failed "
              "runs are reported as failures and are excluded from paired differences; they are "
              "never converted into wins. A smoke run is not publication-quality evidence.", "",
              "Generated source/oracles were hidden from model prompts. Raw transcripts and "
              "sanitized request/response envelopes are retained in `runs.jsonl`.", ""]
    return "\n".join(lines)


class BenchmarkRunner:
    def __init__(self, root: pathlib.Path, config_path: pathlib.Path,
                 overrides: dict[str, Any] | None = None):
        self.root = root
        self.config_path = config_path
        self.config = load_json(config_path)
        self.overrides = overrides or {}
        for name, value in self.overrides.items():
            if value is not None and name in self.config["budgets"]:
                self.config["budgets"][name] = value
        self.output = resolve(root, self.config["paths"]["output_root"])
        self.airece = resolve(root, self.config["paths"]["airece"])
        self.analyzer_report_path = resolve(root, self.config["paths"]["analyzer_report"])
        self.sections = extract_sections(resolve(root, self.config["paths"]["instruction_packs"]))

    def preflight(self, max_cases: int, repetitions: int, split: str,
                  rebuild_corpus: bool = True) -> tuple[dict[str, Any], list[dict[str, Any]],
                                                       GhidraExtractor, LMStudioAdapter]:
        health = load_json(self.analyzer_report_path)
        if not health.get("passed"):
            raise RuntimeError("frozen analyzer health report did not pass")
        if sha256_file(self.airece) != health["artifact"]["sha256"]:
            raise RuntimeError("AIRECE executable hash differs from the passing health report")
        status = git(self.root, "status", "--porcelain")
        if status:
            raise RuntimeError("benchmark run requires a clean AIRECE/harness checkout")
        for name, snapshot in health["repositories"].items():
            repository = pathlib.Path(snapshot["path"])
            if git(repository, "status", "--porcelain"):
                raise RuntimeError(f"repository is dirty at benchmark start: {name}")
            if git(repository, "rev-parse", "HEAD") != snapshot["revision"]:
                raise RuntimeError(f"repository revision changed since health report: {name}")
        corpus_manifest = build_corpus(self.root, self.config, self.output) if rebuild_corpus else \
            load_json(self.output / "corpus" / "manifest.json")
        if split not in {"development", "heldout"}:
            raise ValueError(f"unsupported corpus split: {split}")
        cases = [item for item in corpus_manifest["cases"] if item["split"] == split]
        random.Random(self.config["corpus"]["seed"]).shuffle(cases)
        cases = cases[:max_cases] if max_cases > 0 else cases
        ghidra = GhidraExtractor(resolve(self.root, self.config["paths"]["ghidra_root"]),
            self.root / "benchmarks" / "ghidra" / "AireceBenchmarkExport.java",
            self.output / "cache" / "ghidra", self.config["budgets"]["ghidra_timeout_seconds"])
        target_preflight = _preflight_targets(
            self.airece, cases, ghidra,
            self.config["budgets"]["max_tool_result_bytes"],
            self.config["budgets"]["analyzer_timeout_seconds"])
        lm = LMStudioAdapter(self.config["model"], self.config["budgets"]["task_timeout_seconds"],
                             [str(self.root),
                              *(str(pathlib.Path(item["binary"]).parent) for item in cases),
                              *(pathlib.Path(item["binary"]).name for item in cases)])
        model_metadata = lm.probe()
        native_smoke = lm.native_chat_smoke()
        version = run(["lms", "--version"], self.root, 10)
        analyzer_commit = git(self.root, "rev-parse", "HEAD")
        manifest = {"schema": "airece.ai-utility-manifest.v1", "status": "running",
            "created_unix": int(time.time()), "config": self.config,
            "config_sha256": sha256_file(self.config_path),
            "analyzer": {"tag": "post-diagnostic-candidate", "commit": analyzer_commit,
                         "harness_commit": git(self.root, "rev-parse", "HEAD"),
                         "executable": str(self.airece),
                         "sha256": health["artifact"]["sha256"],
                         "version": health["artifact"]["version"],
                         "health_report": str(self.analyzer_report_path),
                         "health_report_sha256": sha256_file(self.analyzer_report_path),
                         "components": health["repositories"]},
            "ghidra": ghidra.version_snapshot(),
            "model": {"id": self.config["model"]["id"], "metadata": model_metadata,
                      "model_file_sha256": None,
                      "model_file_hash_status": "not exposed by LM Studio API",
                      "lm_studio_version": version["stdout"].strip() or version["stderr"].strip(),
                      "chat_prompt_template": None,
                      "chat_prompt_template_status": "not exposed by LM Studio API",
                      "generation": self.config["model"], "native_chat_smoke": native_smoke},
            "instruction_packs": {name: prompt_snapshot(text)
                                  for name, text in self.sections.items()},
            "corpus": {"manifest": str(self.output / "corpus" / "manifest.json"),
                       "manifest_sha256": sha256_file(self.output / "corpus" / "manifest.json"),
                       "total_cases": len(corpus_manifest["cases"]), "split": split,
                       "selected_cases": len(cases), "artifacts": corpus_manifest["artifacts"]},
            "target_preflight": target_preflight,
            "repetitions": repetitions, "failures": [], "skipped": []}
        manifest["analyzer"]["source_delta_from_tag"] = None
        return manifest, cases, ghidra, lm

    def plan(self, cases: list[dict[str, Any]], repetitions: int) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        rng = random.Random(self.config["corpus"]["seed"])
        for case in cases:
            for repetition in range(repetitions):
                for track in self.config["tracks"]:
                    for task in ("objective", "reconstruction"):
                        if task not in case.get("tasks", ["objective", "reconstruction"]):
                            continue
                        conditions = list(self.config["conditions"])
                        rng.shuffle(conditions)
                        for order, condition in enumerate(conditions):
                            jobs.append({"case": case, "case_id": case["case_id"],
                                "repetition": repetition, "track": track, "task": task,
                                "condition": condition, "condition_order": order})
        return jobs

    def execute(self, max_cases: int, repetitions: int, dry_run: bool = False,
                split: str = "heldout",
                rebuild_corpus: bool = True) -> dict[str, Any]:
        if dry_run:
            corpus_path = self.output / "corpus" / "manifest.json"
            corpus = load_json(corpus_path) if corpus_path.is_file() else \
                build_corpus(self.root, self.config, self.output)
            cases = [item for item in corpus["cases"] if item["split"] == split]
            random.Random(self.config["corpus"]["seed"]).shuffle(cases)
            cases = cases[:max_cases] if max_cases > 0 else cases
            plan = self.plan(cases, repetitions)
            return {"dry_run": True, "jobs": len(plan),
                    "order": [{key: item[key] for key in ("case_id", "repetition", "track",
                                                           "task", "condition", "condition_order")}
                              for item in plan]}
        manifest, cases, ghidra, lm = self.preflight(
            max_cases, repetitions, split, rebuild_corpus)
        self.output.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self.output / "manifest.json", manifest)
        config_fingerprint = sha256_bytes(canonical_json(self.config).encode("utf-8"))
        selected_case_ids = {case["case_id"] for case in cases}
        for job in self.plan(cases, repetitions):
            case = job["case"]
            schemas = tool_schema(job["track"], job["condition"])
            schema_text = canonical_json(schemas)
            task_prompt = objective_prompt(case["target_address"]) if job["task"] == "objective" \
                else reconstruction_prompt(case["target_address"])
            visible = instructions(self.sections, job["track"], job["condition"])
            validate_isolation(self.sections, visible, job["track"], job["condition"],
                               [case["case_id"], case["opaque_symbol"],
                                pathlib.Path(case["binary"]).name])
            identity = {key: job[key] for key in ("case_id", "repetition", "track",
                                                   "task", "condition")}
            identity.update({"config": config_fingerprint,
                             "instructions": prompt_snapshot(visible)["sha256"],
                             "schema": sha256_bytes(schema_text.encode("utf-8")),
                             "task_prompt": prompt_snapshot(task_prompt)["sha256"]})
            run_id = sha256_bytes(canonical_json(identity).encode("utf-8"))[:24]
            record_path = self.output / "records" / f"{run_id}.json"
            if record_path.is_file():
                continue
            binary = pathlib.Path(case["binary"])
            record: dict[str, Any] = {"schema": "airece.ai-utility-run.v1", "run_id": run_id,
                "config_fingerprint": config_fingerprint, "split": split,
                **{key: job[key] for key in ("case_id", "repetition", "track", "task",
                                             "condition", "condition_order")},
                "binary_sha256": case["binary_sha256"],
                "target_address": case["target_address"],
                "instruction_snapshot": prompt_snapshot(visible),
                "tool_schema_snapshot": {"sha256": identity["schema"],
                    "utf8_bytes": len(schema_text.encode("utf-8"))},
                "task_prompt_snapshot": prompt_snapshot(task_prompt)}
            run_started = time.perf_counter()
            try:
                if job["condition"] == "airece":
                    backend: Any = AireceBackend(self.airece, binary,
                        self.config["budgets"]["max_tool_result_bytes"],
                        self.config["budgets"]["analyzer_timeout_seconds"])
                    ghidra_document, extraction = ghidra.extract(binary)
                else:
                    backend = GhidraBackend(ghidra, binary,
                        self.config["budgets"]["max_tool_result_bytes"])
                    ghidra_document, extraction = backend.document, backend.extraction
                bounds = _function_bounds(ghidra_document, case["target_address"])
                record["ghidra_extraction"] = extraction
                def execute_tool(name: str, arguments: dict[str, Any]) -> str:
                    return backend.execute(name, arguments, job["track"])
                if self.config["model"].get("tool_transport") == "json-protocol":
                    model = lm.run_json_protocol(visible, task_prompt, schemas,
                        execute_tool, self.config["budgets"]["max_tool_calls"],
                        self.config["budgets"]["max_input_bytes"],
                        OBJECTIVE_SCHEMA if job["task"] == "objective" else None)
                else:
                    model = lm.run_tools(visible, task_prompt, schemas,
                        execute_tool, self.config["budgets"]["max_tool_calls"],
                        self.config["budgets"]["max_input_bytes"])
                record["model"] = model
                if job["task"] == "objective":
                    record["score"] = score_objective(model["final_text"], case["truth"],
                                                       model["tool_events"], *bounds)
                else:
                    record["score"] = score_reconstruction(model["final_text"], case["tests"],
                        "clang-cl", "lld-link",
                        self.config["budgets"]["compile_timeout_seconds"],
                        self.config["budgets"]["execute_timeout_seconds"])
            except Exception as error:
                record["failure"] = {"type": type(error).__name__, "message": str(error)}
            record["end_to_end_ms"] = round((time.perf_counter() - run_started) * 1000, 3)
            atomic_write_json(record_path, record)
            rebuild_jsonl(self.output, _records(
                self.output, config_fingerprint, selected_case_ids))
        records = _records(self.output, config_fingerprint, selected_case_ids)
        summary = summarize(records)
        atomic_write_json(self.output / "summary.json", summary)
        failures = [{"run_id": item["run_id"], **item["failure"]}
                    for item in records if item.get("failure")]
        manifest["status"] = "complete_with_failures" if failures else "complete"
        manifest["failures"] = failures
        manifest["completed_unix"] = int(time.time())
        atomic_write_json(self.output / "manifest.json", manifest)
        atomic_write_text(self.output / "report.md", _report(summary, manifest))
        rebuild_jsonl(self.output, records)
        return {"manifest": manifest, "summary": summary,
                "paths": {name: str(self.output / name) for name in
                          ("manifest.json", "runs.jsonl", "summary.json", "report.md")}}
