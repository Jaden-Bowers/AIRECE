from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import Any

from .util import atomic_write_json, load_json, run, sha256_file


class GhidraExtractor:
    def __init__(self, root: pathlib.Path, script: pathlib.Path,
                 cache: pathlib.Path, timeout: float):
        self.root = root
        self.headless = root / "support" / "analyzeHeadless.bat"
        self.script = script
        self.options_path = script.parent / "analysis-options.json"
        self.cache = cache
        self.timeout = timeout
        if not self.headless.is_file():
            raise FileNotFoundError(f"analyzeHeadless.bat not found: {self.headless}")
        if not self.script.is_file():
            raise FileNotFoundError(f"Ghidra exporter not found: {self.script}")
        if not self.options_path.is_file():
            raise FileNotFoundError(f"Ghidra analysis options not found: {self.options_path}")
        self.options = load_json(self.options_path)

    def version_snapshot(self) -> dict[str, Any]:
        properties = self.root / "Ghidra" / "application.properties"
        values: dict[str, str] = {}
        if properties.is_file():
            for line in properties.read_text(encoding="utf-8", errors="replace").splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    key, value = line.split("=", 1)
                    values[key.strip()] = value.strip()
        return {"root": str(self.root), "application": values,
                "launcher_sha256": sha256_file(self.headless),
                "exporter_sha256": sha256_file(self.script),
                "analysis_options": self.options,
                "analysis_options_sha256": sha256_file(self.options_path)}

    def extract(self, binary: pathlib.Path) -> tuple[dict[str, Any], dict[str, Any]]:
        digest = sha256_file(binary)
        destination = self.cache / f"{digest}.json"
        metadata_path = self.cache / f"{digest}.metadata.json"
        if destination.is_file() and metadata_path.is_file():
            document = load_json(destination)
            metadata = load_json(metadata_path)
            if document.get("schema") == "airece.ghidra-export.v1" and \
                    metadata.get("exporter_sha256") == sha256_file(self.script) and \
                    metadata.get("analysis_options_sha256") == sha256_file(self.options_path):
                metadata["cached"] = True
                return document, metadata
        self.cache.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="ghidra-project-", dir=self.cache) as temporary:
            temporary_root = pathlib.Path(temporary)
            export = temporary_root / "export.json"
            arguments = [str(self.headless), str(temporary_root), "benchmark",
                         "-deleteProject", "-import", str(binary),
                         "-analysisTimeoutPerFile", str(max(1, int(self.timeout))),
                         "-scriptPath", str(self.script.parent), "-postScript",
                         self.script.name, str(export),
                         str(self.options["max_functions"]),
                         str(self.options["max_instructions_per_function"]),
                         str(self.options["max_decompiled_characters"]),
                         str(self.options["decompiler_timeout_per_function_seconds"])]
            command_line = subprocess.list2cmdline(arguments)
            result = run(["cmd.exe", "/d", "/s", "/c", command_line],
                         self.script.parent, self.timeout + 45)
            if result["exit"] != 0 or not export.is_file():
                raise RuntimeError("Ghidra headless export failed: " +
                                   json.dumps({"exit": result["exit"],
                                               "stdout": result["stdout"][-4000:],
                                               "stderr": result["stderr"][-4000:]}))
            document = load_json(export)
            if document.get("schema") != "airece.ghidra-export.v1" or \
                    not document.get("functions"):
                raise RuntimeError("Ghidra export was missing or invalid")
            metadata = {"cached": False, "binary_sha256": digest,
                        "exporter_sha256": sha256_file(self.script),
                        "analysis_options_sha256": sha256_file(self.options_path),
                        "command": arguments, "elapsed_ms": result["elapsed_ms"],
                        "process_exit": result["exit"],
                        "stdout_tail": result["stdout"][-4000:],
                        "stderr_tail": result["stderr"][-4000:]}
            atomic_write_json(destination, document)
            atomic_write_json(metadata_path, metadata)
            return document, metadata
