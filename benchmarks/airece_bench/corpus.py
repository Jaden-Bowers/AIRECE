from __future__ import annotations

import argparse
import json
import pathlib
import struct
import sys
from typing import Any, Callable

from .util import atomic_write_json, load_json, resolve, run, sha256_file


MASK = 0xffffffff


def u32(value: int) -> int:
    return value & MASK


def rotate(a: int, b: int) -> int:
    count = b & 31
    rotated = a if count == 0 else u32((a << count) | (a >> (32 - count)))
    return rotated ^ 0xa5a5a5a5


def sparse(a: int, b: int) -> int:
    return u32({3: b + 31, 9: b ^ 97, 17: b * 173}.get(a, b - 1))


def local_array(a: int, b: int) -> int:
    values = [a, b, a ^ b, u32(a + b)]
    return u32(sum(u32(value * (index + 1)) for index, value in enumerate(values)))


def nested(a: int, b: int) -> int:
    if a & 1:
        return u32((a + b) ^ 0x55) if b > 100 else u32(a * 3 + b)
    return u32(a + 7) if b == 0 else u32((a - b) ^ 0x33)


def direct_calls(a: int, b: int) -> int:
    return u32(u32(a * 7 + 3) ^ u32(b * 7 + 3))


def structure(a: int, b: int) -> int:
    return u32((a ^ 0x1234) + u32(b + 9))


def recursive(a: int, b: int) -> int:
    value = a & 7
    result = 1 if value <= 1 else 1 + sum(range(2, value + 1))
    return u32(result + b)


def dense(a: int, b: int) -> int:
    key = a & 7
    operations = {0: b + 11, 1: b * 3, 2: b - 19, 3: b ^ 0x55,
                  4: b + 101, 5: b - 7}
    return u32(operations.get(key, b ^ 0x313))


def indirect(a: int, b: int) -> int:
    transformed = b + 0x21 if a & 1 else b ^ 0x87654321
    return u32(transformed + (a & 0xff))


FUNCTIONS: dict[str, dict[str, Any]] = {
    "f_19a7d3e1": {"source": "c", "category": "bit-manipulation",
        "constants": [31, 0xa5a5a5a5], "case_values": [], "memory_reads": False,
        "memory_writes": False, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 0, "oracle": rotate},
    "f_2bc8e4f2": {"source": "c", "category": "sparse-switch",
        "constants": [3, 9, 17, 31, 97, 173], "case_values": [3, 9, 17],
        "memory_reads": False, "memory_writes": False,
        "return_dependencies": ["arg0", "arg1"], "direct_call_count": 0,
        "oracle": sparse},
    "f_3cd9f503": {"source": "c", "category": "loop-and-array",
        "constants": [4], "case_values": [], "memory_reads": True,
        "memory_writes": True, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 0, "oracle": local_array},
    "f_4dea0614": {"source": "c", "category": "nested-branches",
        "constants": [1, 3, 7, 100, 0x33, 0x55], "case_values": [],
        "memory_reads": False, "memory_writes": False,
        "return_dependencies": ["arg0", "arg1"], "direct_call_count": 0,
        "oracle": nested},
    "f_5efb1725": {"source": "c", "category": "direct-calls",
        "constants": [3, 7], "case_values": [], "memory_reads": False,
        "memory_writes": False, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 2, "oracle": direct_calls},
    "f_b5f17d8b": {"source": "c", "category": "api-source-sink-flow",
        "constants": [4], "case_values": [], "memory_reads": True,
        "memory_writes": True, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 2, "tasks": ["objective"]},
    "f_60ac2836": {"source": "cpp", "category": "structure-access",
        "constants": [9, 0x1234], "case_values": [], "memory_reads": False,
        "memory_writes": False, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 0, "oracle": structure},
    "f_71bd3947": {"source": "cpp", "category": "recursion",
        "constants": [1, 7], "case_values": [], "memory_reads": False,
        "memory_writes": False, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 1, "oracle": recursive},
    "f_82ce4a58": {"source": "cpp", "category": "dense-switch",
        "constants": [7, 11, 19, 0x55, 101, 0x313],
        "case_values": [0, 1, 2, 3, 4, 5], "memory_reads": False,
        "memory_writes": False, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 0, "oracle": dense},
    "f_93df5b69": {"source": "cpp", "category": "global-read-write",
        "constants": [0x44, 0x10203040], "case_values": [], "memory_reads": True,
        "memory_writes": True, "return_dependencies": ["arg0", "arg1"],
        "direct_call_count": 0, "tasks": ["objective"]},
    "f_a4e06c7a": {"source": "cpp", "category": "indirect-call",
        "constants": [1, 0x21, 0xff, 0x87654321], "case_values": [],
        "memory_reads": True, "memory_writes": False,
        "return_dependencies": ["arg0", "arg1"], "direct_call_count": 0,
        "oracle": indirect},
}


TEST_INPUTS = [(0, 0), (1, 2), (3, 4), (9, 100), (17, 0xffffffff),
               (0x12345678, 31), (0xffffffff, 1), (6, 101), (8, 7),
               (0x80000000, 0x10203040)]


def pe_exports(path: pathlib.Path) -> dict[str, str]:
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3c)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"not PE: {path}")
    section_count, optional_size = struct.unpack_from("<H12xH", data, pe + 6)
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    image_base = struct.unpack_from("<Q", data, optional + 24)[0]
    directory = optional + (112 if magic == 0x20b else 96)
    export_rva = struct.unpack_from("<I", data, directory)[0]
    sections = optional + optional_size

    def offset(rva: int) -> int:
        for index in range(section_count):
            section = sections + index * 40
            virtual_size, virtual_address, raw_size, raw = struct.unpack_from(
                "<IIII", data, section + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw + rva - virtual_address
        raise ValueError(f"RVA outside sections: {rva:#x}")

    export = offset(export_rva)
    function_count, name_count, functions_rva, names_rva, ordinals_rva = \
        struct.unpack_from("<IIIII", data, export + 20)
    result: dict[str, str] = {}
    for index in range(name_count):
        name_rva = struct.unpack_from("<I", data, offset(names_rva) + index * 4)[0]
        name_offset = offset(name_rva)
        name = data[name_offset:data.index(b"\0", name_offset)].decode("ascii")
        ordinal = struct.unpack_from("<H", data, offset(ordinals_rva) + index * 2)[0]
        if ordinal < function_count:
            rva = struct.unpack_from("<I", data, offset(functions_rva) + ordinal * 4)[0]
            result[name] = f"0x{image_base + rva:x}"
    return result


def build(root: pathlib.Path, config: dict[str, Any], output: pathlib.Path) -> dict[str, Any]:
    corpus_root = root / "benchmarks" / "corpus"
    build_root = output / "corpus" / "build"
    commands: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    for compiler in config["corpus"]["compilers"]:
        for optimization in config["corpus"]["optimizations"]:
          for crt in config["corpus"].get("crt_variants", ["none"]):
            label = f"{compiler}-{optimization.lower()}-{crt}"
            directory = build_root / label
            if compiler == "clangcl":
                release = directory / "Release"
                release.mkdir(parents=True, exist_ok=True)
                for language in ("c", "cpp"):
                    source = corpus_root / "source" / f"fixture_{language}.{language}"
                    object_path = release / f"artifact_{language}.obj"
                    binary = release / f"artifact_{language}.dll"
                    compile_command = ["clang-cl", "/nologo", "/c", "/GS-", "/Gy-",
                                       "/Od" if optimization == "O0" else "/O2",
                                       f"/Fo{object_path}", str(source)]
                    if crt == "none":
                        compile_command.append("/Zl")
                    else:
                        compile_command.append("/MT" if crt == "static" else "/MD")
                    if language == "cpp":
                        compile_command.extend(["/GR-", "/EHsc-"])
                    result = run(compile_command, root, 120)
                    commands.append(result)
                    if result["exit"] != 0:
                        raise RuntimeError(
                            f"corpus compile failed for {label}/{language}: "
                            f"{result['stdout']} {result['stderr']}")
                    if crt == "none":
                        link_command = ["lld-link", "/dll", "/nodefaultlib", "/debug:none",
                                        "/incremental:no", "/opt:noref", "/opt:noicf",
                                        "/entry:bench_entry", f"/out:{binary}", str(object_path)]
                        kits = pathlib.Path("C:/Program Files (x86)/Windows Kits/10/Lib")
                        kernel = sorted(kits.glob("10.*/um/x64/kernel32.lib"), reverse=True)
                        if not kernel:
                            raise RuntimeError("kernel32.lib unavailable for API-shaped fixture")
                        if language == "c":
                            link_command.append(str(kernel[0]))
                    else:
                        link_command = ["clang-cl", "/nologo", "/LD", str(object_path),
                                        "/link", "/debug:none", "/incremental:no",
                                        "/opt:noref", "/opt:noicf", f"/out:{binary}",
                                        f"/implib:{release / f'artifact_{language}.lib'}"]
                        if language == "c":
                            link_command.append("kernel32.lib")
                    result = run(link_command, root, 120)
                    commands.append(result)
                    if result["exit"] != 0:
                        raise RuntimeError(
                            f"corpus link failed for {label}/{language}: "
                            f"{result['stdout']} {result['stderr']}")
                    artifacts.append({"id": f"{label}-{language}",
                                      "path": str(binary.resolve()),
                                      "sha256": sha256_file(binary),
                                      "bytes": binary.stat().st_size,
                                      "compiler": compiler,
                                      "optimization": optimization,
                                      "crt": crt,
                                      "language": language,
                                      "exports": pe_exports(binary)})
                continue
            configure = ["cmake", "-S", str(corpus_root), "-B", str(directory),
                         "-G", "Visual Studio 17 2022", "-A", "x64",
                         f"-DBENCH_OPT={optimization}", f"-DBENCH_CRT={crt}"]
            result = run(configure, root, 120)
            commands.append(result)
            if result["exit"] != 0:
                raise RuntimeError(f"corpus configure failed for {label}: {result['stderr']}")
            result = run(["cmake", "--build", str(directory), "--config", "Release"],
                         root, 180)
            commands.append(result)
            if result["exit"] != 0:
                raise RuntimeError(f"corpus build failed for {label}: {result['stderr']}")
            for language in ("c", "cpp"):
                binary = directory / "Release" / f"artifact_{language}.dll"
                if not binary.is_file():
                    raise RuntimeError(f"missing corpus artifact: {binary}")
                artifacts.append({"id": f"{label}-{language}", "path": str(binary.resolve()),
                                  "sha256": sha256_file(binary), "bytes": binary.stat().st_size,
                                  "compiler": compiler, "optimization": optimization,
                                  "crt": crt, "language": language,
                                  "exports": pe_exports(binary)})

    cases: list[dict[str, Any]] = []
    for artifact in artifacts:
        for function_name, definition in FUNCTIONS.items():
            if definition["source"] != artifact["language"]:
                continue
            address = artifact["exports"].get(function_name)
            if not address:
                raise RuntimeError(f"export {function_name} absent from {artifact['path']}")
            oracle: Callable[[int, int], int] | None = definition.get("oracle")
            case_id = sha256_file(pathlib.Path(artifact["path"]))[:6] + "-" + function_name[2:]
            truth = {key: value for key, value in definition.items()
                     if key not in {"source", "oracle", "tasks"}}
            truth["parameter_count"] = 2
            cases.append({"case_id": case_id, "split": "development" if function_name in
                          {"f_19a7d3e1", "f_60ac2836"} else "heldout",
                          "artifact_id": artifact["id"], "binary": artifact["path"],
                          "binary_sha256": artifact["sha256"], "target_address": address,
                          "opaque_symbol": function_name, "truth": truth,
                          "tasks": definition.get("tasks", ["objective", "reconstruction"]),
                          "tests": ([{"args": [a, b], "expected": oracle(a, b)}
                                    for a, b in TEST_INPUTS] if oracle else [])})
    cases.sort(key=lambda item: item["case_id"])
    manifest = {"schema": "airece.benign-corpus.v1", "seed": config["corpus"]["seed"],
                "artifacts": artifacts, "cases": cases,
                "source_hashes": {str(path.relative_to(root)): sha256_file(path)
                    for path in sorted((corpus_root / "source").glob("*")) if path.is_file()},
                "build_commands": [{key: value for key, value in command.items()
                                    if key in {"command", "exit", "elapsed_ms"}}
                                   for command in commands]}
    atomic_write_json(output / "corpus" / "manifest.json", manifest)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the deterministic benign corpus")
    parser.add_argument("--config", default="benchmarks/config.json")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    root = pathlib.Path(__file__).resolve().parents[2]
    config = load_json(resolve(root, args.config))
    output = resolve(root, args.output or config["paths"]["output_root"])
    manifest = build(root, config, output)
    print(json.dumps({"artifacts": len(manifest["artifacts"]),
                      "cases": len(manifest["cases"]),
                      "manifest": str(output / "corpus" / "manifest.json")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
