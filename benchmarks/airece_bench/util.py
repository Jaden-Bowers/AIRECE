from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_write_text(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp",
                                             dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def atomic_write_json(path: pathlib.Path, value: Any) -> None:
    atomic_write_text(path, json.dumps(value, ensure_ascii=False, indent=2,
                                       sort_keys=True) + "\n")


def run(command: list[str], cwd: pathlib.Path, timeout: float,
        input_text: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command, cwd=cwd, input=input_text, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout, check=False)
        return {"command": command, "exit": completed.returncode,
                "stdout": completed.stdout, "stderr": completed.stderr,
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3)}
    except subprocess.TimeoutExpired as error:
        return {"command": command, "exit": None,
                "stdout": error.stdout or "", "stderr": error.stderr or "",
                "elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
                "timeout": True}


def load_json(path: pathlib.Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def resolve(root: pathlib.Path, value: str | pathlib.Path) -> pathlib.Path:
    path = pathlib.Path(value)
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def text_size(text: str) -> dict[str, int | str]:
    encoded = text.encode("utf-8")
    return {"utf8_bytes": len(encoded), "unicode_characters": len(text),
            "estimated_tokens": (len(encoded) + 3) // 4,
            "token_method": "utf8-bytes-divided-by-4-ceiling"}

