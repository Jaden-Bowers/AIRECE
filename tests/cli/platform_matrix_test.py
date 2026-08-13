#!/usr/bin/env python3
"""Compile and verify the native PE or ELF x86/x64 ABI matrix."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile

from source_semantics_test import binary_exports, run


def require(command: list[str], label: str) -> None:
    completed = subprocess.run(
        command, capture_output=True, text=True, timeout=60, check=False)
    if completed.returncode != 0:
        raise AssertionError(
            f"{label} failed ({completed.returncode}):\n"
            f"{completed.stdout}\n{completed.stderr}")


def build_pe(source: pathlib.Path, clang_cl: pathlib.Path,
             lld_link: pathlib.Path, directory: pathlib.Path) -> list[tuple[str, str, str, pathlib.Path]]:
    fixtures: list[tuple[str, str, str, pathlib.Path]] = []
    for bits, target, machine, entry in (
            (64, "x86_64-pc-windows-msvc", "x64", "airece_platform_entry"),
            (32, "i686-pc-windows-msvc", "x86", "airece_platform_entry")):
        obj = directory / f"platform-pe{bits}.obj"
        binary = directory / f"platform-pe{bits}.dll"
        require([
            str(clang_cl), f"--target={target}", "/nologo", "/c", "/O2", "/Ob0",
            "/GS-", f"/Fo{obj}", str(source),
        ], f"PE{bits} compile")
        require([
            str(lld_link), "/dll", f"/machine:{machine}", f"/entry:{entry}",
            "/nodefaultlib", f"/out:{binary}", str(obj),
        ], f"PE{bits} link")
        fixtures.append(("pe", f"x86_{bits}", "win64" if bits == 64 else "cdecl-x86", binary))
    return fixtures


def build_elf(source: pathlib.Path, compiler: pathlib.Path,
              directory: pathlib.Path) -> list[tuple[str, str, str, pathlib.Path]]:
    fixtures: list[tuple[str, str, str, pathlib.Path]] = []
    for bits, abi in ((64, "sysv-x64"), (32, "cdecl-x86")):
        binary = directory / f"platform-elf{bits}.so"
        require([
            str(compiler), f"-m{bits}", "-shared", "-nostdlib", "-O2",
            "-fno-stack-protector", "-fcf-protection=none",
            "-Wl,-e,airece_platform_entry", "-o", str(binary), str(source),
        ], f"ELF{bits} compile/link")
        fixtures.append(("elf", f"x86_{bits}", abi, binary))
    return fixtures


def verify(airece: pathlib.Path, fixture: tuple[str, str, str, pathlib.Path]) -> None:
    expected_format, expected_arch, expected_abi, binary = fixture
    exports = binary_exports(binary)
    address = exports.get("airece_platform_mix")
    if address is None:
        raise AssertionError(f"platform function is not exported by {binary}")
    raw = run(
        airece, "fn", str(binary), address, "--view", "agent",
        "--profile", "fast", "--max-bytes", "4096",
        "--max-statements", "128", "--max-evidence", "128")
    document = json.loads(raw)
    metadata = document.get("binary", {})
    actual = (metadata.get("format"), metadata.get("architecture"),
              metadata.get("calling_convention"))
    expected = (expected_format, expected_arch, expected_abi)
    if actual != expected:
        raise AssertionError(f"wrong platform metadata for {binary}: {actual} != {expected}")
    parameters = document.get("function", {}).get("parameters", [])
    if [item.get("name") for item in parameters[:2]] != ["arg0", "arg1"]:
        raise AssertionError(f"ABI arguments were not recovered for {binary}: {parameters}")
    expressions = [item.get("expression", "") for item in document.get("returns", [])]
    if not any("arg0" in item and "arg1" in item for item in expressions):
        raise AssertionError(f"return expression lost ABI arguments for {binary}: {expressions}")
    if len(raw.encode("utf-8")) > 4096:
        raise AssertionError(f"agent view exceeded its byte budget for {binary}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--airece", required=True, type=pathlib.Path)
    parser.add_argument("--source", required=True, type=pathlib.Path)
    parser.add_argument("--format", required=True, choices=("pe", "elf"))
    parser.add_argument("--clang-cl", type=pathlib.Path)
    parser.add_argument("--lld-link", type=pathlib.Path)
    parser.add_argument("--cc", type=pathlib.Path)
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="airece-platform-") as temporary:
        directory = pathlib.Path(temporary)
        if arguments.format == "pe":
            if not arguments.clang_cl or not arguments.lld_link:
                raise AssertionError("PE matrix requires clang-cl and lld-link")
            fixtures = build_pe(
                arguments.source, arguments.clang_cl, arguments.lld_link, directory)
        else:
            if not arguments.cc:
                raise AssertionError("ELF matrix requires a C compiler")
            fixtures = build_elf(arguments.source, arguments.cc, directory)
        for fixture in fixtures:
            verify(arguments.airece, fixture)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
