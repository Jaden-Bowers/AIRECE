from __future__ import annotations

import json
import pathlib
import random
import re
import time
from typing import Any

from .backends import AireceBackend, GhidraBackend, GhidraExtractor, tool_schema
from .corpus import build as build_corpus
from .lmstudio import LMStudioAdapter
from .prompts import (OBJECTIVE_SCHEMA, extract_sections, instructions, objective_prompt,
                      prompt_snapshot, reconstruction_prompt, validate_isolation)
from .scoring import (extract_c_function, score_objective,
                      score_reconstruction, summarize, validate_objective)
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


def _select_cases(cases: list[dict[str, Any]], config: dict[str, Any],
                  max_cases: int) -> list[dict[str, Any]]:
    categories = config.get("selection_categories") or []
    if categories:
        selected: list[dict[str, Any]] = []
        for category in categories:
            candidates = [item for item in cases
                          if item.get("truth", {}).get("category") == category]
            if not candidates:
                raise ValueError(f"no case in selected split for category: {category}")
            candidates.sort(key=lambda item: (
                0 if item.get("artifact_id") == "msvc-o2-none-cpp" else
                1 if str(item.get("artifact_id", "")).startswith("msvc-o2-none") else 2,
                str(item.get("artifact_id", "")), item["case_id"]))
            selected.append(candidates[0])
        return selected[:max_cases] if max_cases > 0 else selected
    if config.get("selection_balance_categories"):
        rng = random.Random(config["corpus"]["seed"])
        selected = []
        for category in sorted({item.get("truth", {}).get("category") for item in cases}):
            candidates = [item for item in cases
                          if item.get("truth", {}).get("category") == category]
            rng.shuffle(candidates)
            selected.append(candidates[0])
        return selected[:max_cases] if max_cases > 0 else selected
    shuffled = list(cases)
    random.Random(config["corpus"]["seed"]).shuffle(shuffled)
    return shuffled[:max_cases] if max_cases > 0 else shuffled


def _function_bounds(document: dict[str, Any], address: str) -> tuple[int, int]:
    wanted = int(address, 0)
    for function in document["functions"]:
        if int(function["entry"], 0) == wanted:
            return int(function["body_min"], 0), int(function["body_max"], 0)
    return wanted, wanted


def _validate_direct_final(task: str, text: str) -> list[str]:
    """Require a raw schema object or a raw C function, without wrappers."""
    if task == "objective":
        try:
            value = json.loads(text.strip())
        except json.JSONDecodeError as error:
            return [f"final answer is not raw JSON: {error.msg}"]
        return validate_objective(value)
    function, error = extract_c_function(text)
    if error is not None or function is None:
        return [error or "invalid C function"]
    if text.strip() != function.strip():
        return ["final answer must contain exactly one raw C function and no wrapper"]
    analyzer_syntax = re.search(
        r"\b(?:tmp_(?:v)?\d+|tmp\d+|buffer_v\d+|stack_[A-Za-z0-9_]*|"
        r"global_[0-9a-fA-F]+|arg[01]|r(?:ax|bx|cx|dx|si|di|sp|bp|8|9|10|11|12|13|14|15)|"
        r"load(?:8|16|32|64)|"
        r"store(?:8|16|32|64)|extract|[zs]ext|sub_[0-9a-fA-F]+|"
        r"uint(?:8|16|64)_t)\b", function)
    if analyzer_syntax:
        return [f"function contains unresolved analyzer syntax: {analyzer_syntax.group(0)}"]
    return []


def _normalize_direct_final(task: str, text: str) -> str:
    """Remove only recoverable presentation wrappers; never invent semantics."""
    candidate = text.strip()
    fenced = re.fullmatch(r"```(?:json|c)?\s*\n?(.*?)\n?```", candidate,
                          flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = fenced.group(1).strip()
    if task == "objective":
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            return candidate
        if not isinstance(parsed, dict) or not isinstance(parsed.get("answers"), list):
            return candidate
        required = OBJECTIVE_SCHEMA["properties"]["answers"]["items"]["required"]
        array_fields = {"constants", "case_values", "return_dependencies", "evidence"}
        normalized_answers: list[dict[str, Any]] = []
        for index, source in enumerate(parsed["answers"][:2]):
            if not isinstance(source, dict):
                return candidate
            answer: dict[str, Any] = {}
            for field in required:
                if field in source:
                    value = source[field]
                elif field == "question_id":
                    value = f"q{index + 1}"
                elif field == "status":
                    value = "unknown"
                else:
                    value = [] if field in array_fields else None
                if field in array_fields and value is None:
                    value = []
                if field in {"constants", "case_values"} and isinstance(value, list):
                    converted: list[Any] = []
                    for item in value:
                        if isinstance(item, str):
                            try:
                                item = int(item, 0)
                            except ValueError:
                                pass
                        converted.append(item)
                    value = converted
                answer[field] = value
            normalized_answers.append(answer)
        if len(normalized_answers) != 2:
            return candidate
        return canonical_json({"answers": normalized_answers})
    if candidate.startswith("uint32_t target"):
        function, error = extract_c_function(candidate)
        if error is None and function is not None:
            return function.strip()
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return candidate
    if isinstance(parsed, dict):
        parameters = parsed.get("parameters")
        contract = (
            parsed.get("function_name") == "target" and
            parsed.get("return_type") == "uint32_t" and
            isinstance(parameters, list) and
            [(item.get("name"), item.get("type")) for item in parameters
             if isinstance(item, dict)] == [("a", "uint32_t"), ("b", "uint32_t")] and
            isinstance(parsed.get("body"), str))
        if contract:
            found, found_error = extract_c_function(
                "uint32_t target(uint32_t a, uint32_t b) {\n" +
                parsed["body"].strip() + "\n}")
            if found_error is None and found is not None:
                return found.strip()
    recovered: list[str] = []
    def visit(value: Any) -> None:
        if isinstance(value, str):
            variants = [value]
            if "\\n" in value or "\\r" in value or "\\t" in value:
                variants.append(value.replace("\\r\\n", "\n").replace("\\n", "\n")
                                .replace("\\r", "\n").replace("\\t", "\t"))
            for variant in variants:
                found, found_error = extract_c_function(variant)
                if found_error is None and found is not None:
                    recovered.append(found.strip())
        elif isinstance(value, dict):
            signature, body = value.get("signature"), value.get("body")
            if (isinstance(signature, str) and isinstance(body, str) and
                    signature.strip() == "uint32_t target(uint32_t a, uint32_t b)"):
                found, found_error = extract_c_function(signature.strip() + " { " +
                                                        body.strip() + " }")
                if found_error is None and found is not None:
                    recovered.append(found.strip())
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(parsed)
    return min(recovered, key=len) if recovered else candidate


def _assert_semantic_context(category: str | None, context: dict[str, Any]) -> bool:
    """Enforce one deterministic agent-view contract for every fixture family."""
    if context.get("function", {}).get("parameter_count") != 2:
        raise AssertionError("agent context did not recover both fixture parameters")
    returns = [str(item.get("expression", "")) for item in context.get("returns", [])]
    conditions = [str(item.get("expression", "")) for item in context.get("conditions", [])]
    calls = [str(item.get("kind_target", "")) for item in context.get("calls", [])]
    effects = {str(item.get("effect", "")) for item in context.get("memory_effects", [])}
    constants = {str(item).lower() for item in context.get("constants", [])}
    if category == "dense-switch":
        dense_results = ["arg1 + 0xb", "arg1 * 3", "arg1 - 0x13",
                         "arg1 ^ 0x55", "arg1 + 0x65", "arg1 - 7"]
        switches = context.get("switches", [])
        if (len(switches) != 1 or switches[0].get("selector") != "arg0 & 7" or
                [item.get("value") for item in switches[0].get("cases", [])] != list(range(6)) or
                [item.get("result") for item in switches[0].get("cases", [])] != dense_results or
                switches[0].get("default", {}).get("result") != "arg1 ^ 0x313"):
            raise AssertionError("dense-switch agent semantics are incomplete")
    elif category == "bit-manipulation":
        joined = " | ".join(returns)
        if ("arg0" not in joined or "arg1" not in joined or
                "0xa5a5a5a5" not in constants or
                ("0x1f" not in constants and "rol(" not in joined)):
            raise AssertionError("bit-manipulation agent context lacks argument flow or constants")
    elif category == "sparse-switch":
        joined = " | ".join(conditions)
        case_constants = {"0x3", "0x9", "0x11"}
        if (len(returns) < 4 or not (case_constants.issubset(constants) or
                all(value in joined for value in ("3", "9", "0x11")))):
            raise AssertionError("sparse-switch agent context lacks cases or results")
    elif category == "loop-and-array":
        if not any("arg0" in item and "arg1" in item and
                   ("* 4" in item or "4 *" in item) for item in returns):
            raise AssertionError("loop agent context lacks the recovered aggregate expression")
    elif category == "nested-branches":
        paths = context.get("paths", [])
        if (len(conditions) < 2 or len(returns) < 2 or len(paths) < 2 or
                any(not item.get("when") or not item.get("result") for item in paths)):
            raise AssertionError("nested-branch context lacks linked conditions and results")
    elif category == "direct-calls":
        joined_returns = " | ".join(returns)
        if (len([item for item in calls if item.startswith("direct:")]) < 2 or
                not any("arg0=arg0" in item for item in calls) or
                not any("arg0=arg1" in item for item in calls) or
                joined_returns.count("result(direct:") < 2):
            raise AssertionError("direct-call context lacks distinct arguments or results")
    elif category == "recursion":
        if not any(item.startswith("direct:") for item in calls):
            raise AssertionError("recursion agent context contains no recursive call fact")
    elif category == "api-source-sink-flow":
        if (len([item for item in calls if item.startswith("imported:")]) < 2 or
                "read:api-mediated" not in effects):
            raise AssertionError("API flow context lacks imported calls or API-mediated effects")
    elif category == "global-read-write":
        if not {"read:global", "write:global"}.issubset(effects):
            raise AssertionError("global-memory agent context lacks read/write effects")
        writes = [str(item.get("expression", ""))
                  for item in context.get("memory_effects", [])
                  if item.get("effect") == "write:global"]
        if not any("arg0" in item and "arg1" in item for item in writes):
            raise AssertionError("global-memory context lacks the written value expression")
        updates = context.get("state_updates", [])
        if (not updates or not updates[0].get("persists_across_calls") or
                "initial=" not in str(updates[0].get("prior_value", ""))):
            raise AssertionError("global-memory context lacks persistent initial state")
    elif category == "structure-access":
        if (not any("arg0" in item and "arg1" in item for item in returns) or
                not {"0x9", "0x1234"}.issubset(constants)):
            raise AssertionError("structure-access context lacks field expression or constants")
    elif category == "indirect-call":
        if not any(item.startswith("indirect(") or item == "indirect" for item in calls):
            raise AssertionError("indirect-call agent context lacks an indirect call fact")
    else:
        return False
    return True


def _preflight_targets(airece: pathlib.Path, cases: list[dict[str, Any]],
                       ghidra: GhidraExtractor, max_bytes: int,
                       analyzer_timeout: float,
                       semantic_gate: bool = False) -> list[dict[str, Any]]:
    report: list[dict[str, Any]] = []
    failures: list[str] = []
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
            semantic_check = (_assert_semantic_context(
                case.get("truth", {}).get("category"), context) if semantic_gate else None)
            row["airece"] = {"available": True, "bytes": len(raw.encode("utf-8")),
                             "instructions": context["function"]["instruction_count"],
                             "semantic_check": semantic_check,
                             "semantic_gate_applied": semantic_gate}

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
                      f"raw/final structure {group.get('raw_structure_valid', 0)}/"
                      f"{group.get('final_structure_valid', 0)} of {group['runs']}; "
                      f"unsupported {group.get('unsupported_claims', 0)}/{group.get('claims', 0)}")
        else:
            result = (f"compile {group.get('compiled', 0)}/{group['runs']}; tests "
                      f"{group.get('tests_passed', 0)}/{group.get('tests_total', 0)}; "
                      f"raw/final structure {group.get('raw_structure_valid', 0)}/"
                      f"{group.get('final_structure_valid', 0)} of {group['runs']}")
        lines.append(f"| {key} | {group['runs']} | {result} | "
                     f"{group['input_tokens']}/{group['output_tokens']} | {group['tool_calls']} |")
    lines += ["", "## Paired case differences (AIRECE minus Ghidra)", ""]
    for key, metrics in summary.get("paired", {}).items():
        lines.append(f"### {key}")
        lines.append("")
        for name, value in metrics.items():
            lines.append(f"- {name}: {value['difference']} (paired bootstrap 95% CI "
                         f"{value['ci95']}, n={value['pairs']})")
        lines.append("")
    lines += ["## Program-clustered differences (AIRECE minus Ghidra)", "",
              "Compiler/optimization variants of one source program are averaged before "
              "bootstrap resampling.", ""]
    for key, metrics in summary.get("clustered_paired", {}).items():
        lines.append(f"### {key}")
        lines.append("")
        for name, value in metrics.items():
            lines.append(f"- {name}: {value['difference']} (program-clustered bootstrap "
                         f"95% CI {value['ci95']}, programs={value['pairs']})")
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
            current_revision = git(repository, "rev-parse", "HEAD")
            if current_revision != snapshot["revision"]:
                if name != "airece":
                    raise RuntimeError(f"repository revision changed since health report: {name}")
                changed = git(repository, "diff", "--name-only",
                              f"{snapshot['revision']}..{current_revision}")
                changed_paths = [item for item in (changed or "").splitlines() if item]
                allowed = all(item.startswith("benchmarks/") or
                              item == "docs/benchmark-tool-instructions.md"
                              for item in changed_paths)
                if not changed_paths or not allowed:
                    raise RuntimeError("AIRECE source changed after analyzer freeze: " +
                                       ", ".join(changed_paths))
        corpus_manifest = build_corpus(self.root, self.config, self.output) if rebuild_corpus else \
            load_json(self.output / "corpus" / "manifest.json")
        if split not in {"development", "heldout"}:
            raise ValueError(f"unsupported corpus split: {split}")
        cases = _select_cases(
            [item for item in corpus_manifest["cases"] if item["split"] == split],
            self.config, max_cases)
        ghidra = GhidraExtractor(resolve(self.root, self.config["paths"]["ghidra_root"]),
            self.root / "benchmarks" / "ghidra" / "AireceBenchmarkExport.java",
            self.output / "cache" / "ghidra", self.config["budgets"]["ghidra_timeout_seconds"])
        target_preflight = _preflight_targets(
            self.airece, cases, ghidra,
            self.config["budgets"]["max_tool_result_bytes"],
            self.config["budgets"]["analyzer_timeout_seconds"],
            semantic_gate=split == "development")
        lm = LMStudioAdapter(self.config["model"], self.config["budgets"]["task_timeout_seconds"],
                             [str(self.root),
                              *(str(pathlib.Path(item["binary"]).parent) for item in cases),
                              *(pathlib.Path(item["binary"]).name for item in cases)])
        model_metadata = lm.probe()
        native_smoke = lm.native_chat_smoke()
        version = run(["lms", "--version"], self.root, 10)
        harness_commit = git(self.root, "rev-parse", "HEAD")
        analyzer_commit = health["repositories"]["airece"]["revision"]
        manifest = {"schema": "airece.ai-utility-manifest.v1", "status": "running",
            "created_unix": int(time.time()), "config": self.config,
            "config_sha256": sha256_file(self.config_path),
            "analyzer": {"tag": "airece-agent-view-freeze-2026-08-11",
                         "commit": analyzer_commit,
                         "freeze_tag": "airece-agent-view-freeze-2026-08-11",
                         "harness_commit": harness_commit,
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
        selected_tasks = self.config.get("selection_tasks", ["objective", "reconstruction"])
        for case in cases:
            for repetition in range(repetitions):
                for track in self.config["tracks"]:
                    for task in selected_tasks:
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
            corpus = build_corpus(self.root, self.config, self.output) if rebuild_corpus else \
                load_json(corpus_path)
            cases = _select_cases(
                [item for item in corpus["cases"] if item["split"] == split],
                self.config, max_cases)
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
                "program_id": case.get("program_id", case["case_id"]),
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
                initial_tool_events: list[dict[str, Any]] = []
                if job["track"] == "native":
                    baseline_name = "fn" if job["condition"] == "airece" else \
                        "function_context"
                    baseline_arguments = ({"address": case["target_address"], "limit": 64}
                        if job["condition"] == "airece" else
                        {"address": case["target_address"], "level": "primary", "limit": 64})
                    baseline = execute_tool(baseline_name, baseline_arguments)
                    initial_tool_events.append({"name": baseline_name,
                        "arguments": baseline_arguments, "executed": True,
                        "baseline": True, "result": baseline,
                        "result_size": {"utf8_bytes": len(baseline.encode("utf-8"))}})
                if job["track"] == "single":
                    context = execute_tool("function_context", {
                        "address": case["target_address"], "level": "primary"})
                    context_event = {"name": "function_context", "arguments": {
                        "address": case["target_address"], "level": "primary"},
                        "executed": True, "result": context,
                        "result_size": {"utf8_bytes": len(context.encode("utf-8"))}}
                    def validate_final(text: str) -> list[str]:
                        return _validate_direct_final(job["task"], text)
                    model = lm.run_direct_final(
                        visible, task_prompt, context, validate_final,
                        self.config["budgets"]["max_input_bytes"],
                        OBJECTIVE_SCHEMA if job["task"] == "objective" else None,
                        lambda text: _normalize_direct_final(job["task"], text))
                    model["tool_events"] = [context_event]
                elif self.config["model"].get("tool_transport") == "json-protocol":
                    model = lm.run_json_protocol(visible, task_prompt, schemas,
                        execute_tool, self.config["budgets"]["max_tool_calls"],
                        self.config["budgets"]["max_input_bytes"],
                        OBJECTIVE_SCHEMA if job["task"] == "objective" else None,
                        initial_tool_events,
                        lambda text: _validate_direct_final(job["task"], text),
                        lambda text: _normalize_direct_final(job["task"], text))
                else:
                    model = lm.run_tools(visible, task_prompt, schemas,
                        execute_tool, self.config["budgets"]["max_tool_calls"],
                        self.config["budgets"]["max_input_bytes"])
                if job["track"] != "single" and "raw_validation_errors" not in model:
                    raw_final = model["final_text"]
                    normalized_final = _normalize_direct_final(job["task"], raw_final)
                    model["raw_final_text"] = raw_final
                    model["raw_validation_errors"] = _validate_direct_final(
                        job["task"], raw_final)
                    model["final_text"] = normalized_final
                    model["final_validation_errors"] = _validate_direct_final(
                        job["task"], normalized_final)
                    model["normalizations"] = ([{"input_size": len(raw_final.encode("utf-8")),
                        "output_size": len(normalized_final.encode("utf-8"))}]
                        if normalized_final != raw_final else [])
                    model["repair_attempted"] = normalized_final != raw_final
                    model["repair_succeeded"] = (normalized_final != raw_final and
                        not model["final_validation_errors"])
                record["model"] = model
                if job["task"] == "objective":
                    record["raw_score"] = score_objective(
                        model.get("raw_final_text", model["final_text"]), case["truth"],
                        model["tool_events"], *bounds)
                    record["score"] = score_objective(model["final_text"], case["truth"],
                                                       model["tool_events"], *bounds)
                else:
                    record["raw_score"] = score_reconstruction(
                        model.get("raw_final_text", model["final_text"]), case["tests"],
                        "clang-cl", "lld-link",
                        self.config["budgets"]["compile_timeout_seconds"],
                        self.config["budgets"]["execute_timeout_seconds"])
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
