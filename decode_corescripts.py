#!/usr/bin/env python3
"""Decode legacy Roblox instructions, export Lua 5.1 chunks, and decompile them."""

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

import extract_corescripts as extractor


DECODE_KEY = 6700417
OPCODES = (
    "MOVE", "LOADK", "LOADBOOL", "LOADNIL", "GETUPVAL", "GETGLOBAL", "GETTABLE",
    "SETGLOBAL", "SETUPVAL", "SETTABLE", "NEWTABLE", "SELF", "ADD", "SUB", "MUL",
    "DIV", "MOD", "POW", "UNM", "NOT", "LEN", "CONCAT", "JMP", "EQ", "LT", "LE",
    "TEST", "TESTSET", "CALL", "TAILCALL", "RETURN", "FORLOOP", "FORPREP",
    "TFORLOOP", "SETLIST", "CLOSE", "CLOSURE", "VARARG",
)
SHUFFLE = (2, 6, 4, 7, 1, 8, 0, 3, 5)
SECURE_OPCODES = tuple(OPCODES[group * 9 + index] for group in range(4) for index in SHUFFLE) + (
    "VARARG", "CLOSURE",
)
ABX_OPCODES = {"LOADK", "GETGLOBAL", "SETGLOBAL", "CLOSURE"}
ASBX_OPCODES = {"JMP", "FORLOOP", "FORPREP"}
TOOL_ROOT = Path(__file__).resolve().parent / "analysis" / "tools"
STAGED_TOOLS = []


def decode_prototype(prototype, path="0"):
    instructions = []
    extra_word = False
    for pc, encoded in enumerate(prototype["encoded_instructions"]):
        word = encoded * DECODE_KEY & extractor.MASK32
        if extra_word:
            instructions.append({"pc": pc, "opcode": "EXTRA", "word": word})
            extra_word = False
            continue
        opcode_index = word >> 26
        if opcode_index >= len(SECURE_OPCODES):
            raise extractor.FormatError(f"Invalid opcode {opcode_index} at prototype {path}, PC {pc}")
        opcode = SECURE_OPCODES[opcode_index]
        arg_a = word >> 18 & 255
        arg_b = word & 511
        arg_c = word >> 9 & 511
        arg_bx = word & 262143
        arg_sbx = arg_bx - 131071
        if opcode not in ASBX_OPCODES | {"EQ", "LT", "LE"} and arg_a >= prototype["stack_size"]:
            raise extractor.FormatError(f"Invalid register at prototype {path}, PC {pc}")
        if opcode in {"LOADK", "GETGLOBAL", "SETGLOBAL"} and arg_bx >= len(prototype["constants"]):
            raise extractor.FormatError(f"Invalid constant at prototype {path}, PC {pc}")
        if opcode == "CLOSURE" and arg_bx >= len(prototype["children"]):
            raise extractor.FormatError(f"Invalid child prototype at prototype {path}, PC {pc}")
        if opcode in ASBX_OPCODES and not 0 <= pc + 1 + arg_sbx < len(prototype["encoded_instructions"]):
            raise extractor.FormatError(f"Invalid jump target at prototype {path}, PC {pc}")
        standard_opcode = OPCODES.index(opcode)
        if opcode in ABX_OPCODES | ASBX_OPCODES:
            stock_word = standard_opcode | arg_a << 6 | arg_bx << 14
        else:
            if opcode == "MOVE":
                arg_c = 0
            stock_word = standard_opcode | arg_a << 6 | arg_c << 14 | arg_b << 23
        instructions.append({
            "pc": pc, "opcode": opcode, "word": stock_word,
            "arg_a": arg_a, "arg_b": arg_b, "arg_c": arg_c,
            "arg_bx": arg_bx, "arg_sbx": arg_sbx,
        })
        extra_word = opcode == "SETLIST" and arg_c == 0
    if extra_word:
        raise extractor.FormatError(f"Missing SETLIST extra word in prototype {path}")
    if not instructions or instructions[-1]["opcode"] != "RETURN":
        raise extractor.FormatError(f"Prototype {path} does not end with RETURN")
    lines = [value ^ pc << 8 for pc, value in enumerate(prototype["encoded_lineinfo"])]
    if lines and (len(lines) != len(instructions) or max(lines) > 10000000):
        raise extractor.FormatError(f"Invalid decoded line information in prototype {path}")
    result = dict(prototype)
    result["instructions"] = instructions
    result["lineinfo"] = lines
    result["children"] = [decode_prototype(child, path + "." + str(index)) for index, child in enumerate(prototype["children"])]
    return result


def lua51_chunk(parsed, root, name, size_t=8):
    output = bytearray(b"\x1bLua\x51\x00\x01\x04" + bytes((size_t, 4, 8, 0)))
    strings = [bytes.fromhex(value) for value in parsed["strings_hex"]]

    def integer(value):
        output.extend(struct.pack("<I", value))

    def string(value):
        length = 0 if value is None else len(value) + 1
        output.extend(struct.pack("<Q" if size_t == 8 else "<I", length))
        if value is not None:
            output.extend(value + b"\0")

    def table_string(index):
        string(strings[index - 1] if index else None)

    def prototype(current, is_root=False):
        string(("@" + name + ".lua").encode("utf-8") if is_root else None)
        lines = current["lineinfo"]
        integer(0 if is_root or not lines else min(lines))
        integer(0 if is_root or not lines else max(lines))
        output.extend(bytes((current["upvalue_count"], current["parameter_count"], current["vararg"], current["stack_size"])))
        integer(len(current["instructions"]))
        for instruction in current["instructions"]:
            integer(instruction["word"])
        integer(len(current["constants"]))
        for constant in current["constants"]:
            kind = constant["type"]
            if kind == "nil":
                output.append(0)
            elif kind in ("false", "true"):
                output.extend(bytes((1, int(kind == "true"))))
            elif kind == "number":
                output.append(3)
                output.extend(struct.pack("<d", float(constant["value"])))
            elif kind == "string":
                output.append(4)
                table_string(constant["string_index"])
        integer(len(current["children"]))
        for child in current["children"]:
            prototype(child)
        integer(len(lines))
        for line in lines:
            integer(line)
        integer(len(current["locals"]))
        for local in current["locals"]:
            table_string(local["string_index"])
            integer(local["start_pc"])
            integer(local["end_pc"])
        integer(len(current["upvalue_names"]))
        for index in current["upvalue_names"]:
            table_string(index)

    prototype(root, True)
    return bytes(output)


def disassembly(parsed, root, name):
    output = ["Decoded legacy Roblox instructions: " + name]
    strings = parsed["strings"]

    def constant_text(current, index):
        if index >= len(current["constants"]):
            return "INVALID_CONSTANT"
        constant = current["constants"][index]
        if constant["type"] == "string":
            return json.dumps(strings[constant["string_index"] - 1], ensure_ascii=True)
        return str(constant.get("value", constant["type"]))

    def operand(current, value):
        return "K" + str(value - 256) + "=" + constant_text(current, value - 256) if value >= 256 else "R" + str(value)

    def prototype(current, path):
        output.append(f'\nFUNCTION {path}: {current["parameter_count"]} parameters, {current["upvalue_count"]} upvalues, {current["stack_size"]} registers')
        for instruction in current["instructions"]:
            pc = instruction["pc"]
            opcode = instruction["opcode"]
            if opcode == "EXTRA":
                text = str(instruction["word"])
            else:
                arg_a, arg_b, arg_c = (instruction[key] for key in ("arg_a", "arg_b", "arg_c"))
                text = f"{arg_a} {arg_b} {arg_c}"
                if opcode in ABX_OPCODES:
                    text = f'{arg_a} {instruction["arg_bx"]}'
                    if opcode != "CLOSURE":
                        text += "  " + constant_text(current, instruction["arg_bx"])
                elif opcode in ASBX_OPCODES:
                    text = f'{arg_a} {instruction["arg_sbx"]}  -> PC {pc + 1 + instruction["arg_sbx"]}'
                elif opcode in {"GETTABLE", "SELF"}:
                    text += "  " + operand(current, arg_c)
                elif opcode in {"SETTABLE", "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "EQ", "LT", "LE"}:
                    text += "  " + operand(current, arg_b) + ", " + operand(current, arg_c)
            line = current["lineinfo"][pc] if current["lineinfo"] else 0
            output.append(f'{pc:6} [{line:5}] {opcode:10} {text}')
        for index, child in enumerate(current["children"]):
            prototype(child, path + "." + str(index))

    prototype(root, "0")
    return "\n".join(output) + "\n"


def prototype_counts(root):
    prototypes = 1
    words = len(root["instructions"])
    for child in root["children"]:
        child_prototypes, child_words = prototype_counts(child)
        prototypes += child_prototypes
        words += child_words
    return prototypes, words


def load_scripts(input_path, library):
    if input_path.is_dir():
        manifest = json.loads((input_path / "manifest.json").read_text(encoding="utf-8"))
        for entry in manifest["scripts"]:
            relative = extractor.safe_name(entry["files"]["blob"])
            blob = (input_path / Path(*relative.parts)).read_bytes()
            unused, payload = extractor.unwrap_rsb1(blob)
            yield {**entry, "parsed": extractor.parse_payload(payload), "blob": blob}
    else:
        binary, unused = extractor.load_binary(input_path, library)
        yield from extractor.find_scripts(binary)


def find_tool(explicit, bundled, name):
    if explicit is not None:
        result = Path(explicit).expanduser().resolve()
        if not result.is_file():
            raise extractor.FormatError("Tool does not exist: " + str(result))
    elif bundled.is_file():
        result = bundled.resolve()
    else:
        located = shutil.which(name)
        return located
    if os.access(result, os.X_OK):
        return str(result)
    with tempfile.NamedTemporaryFile(prefix="corescript-" + name + "-", delete=False) as staged:
        with result.open("rb") as source:
            shutil.copyfileobj(source, staged)
        destination = Path(staged.name)
    destination.chmod(0o700)
    STAGED_TOOLS.append(destination)
    return str(destination)


def find_decompiler(explicit, java):
    jar = TOOL_ROOT / "unluac.jar"
    selected = Path(explicit).expanduser().resolve() if explicit else jar
    if selected.suffix.lower() == ".jar" and selected.is_file():
        java_executable = shutil.which(java)
        if not java_executable:
            raise extractor.FormatError("Java is required to run unluac; supply --java if it is not on PATH")
        return [java_executable, "-Xmx512m", "-jar", str(selected.resolve())]
    executable = find_tool(explicit, TOOL_ROOT / "luadec-source" / "luadec" / "luadec", "luadec")
    return [executable] if executable else None


def run_tool(command, timeout):
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        return completed.returncode, completed.stdout, completed.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return -1, b"", "Tool timed out"


def decode(args):
    output = args.output
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise extractor.FormatError("Decoding output directory must be empty")
    decompiler = None if args.no_decompile else find_decompiler(args.decompiler, args.java)
    validator = find_tool(args.luac, TOOL_ROOT / "lua-5.1.4" / "src" / "luac", "luac5.1")
    if not args.no_decompile and not decompiler:
        raise extractor.FormatError("A decompiler is required for readable Lua; supply --decompiler unluac.jar or a LuaDec executable, or use --no-decompile")
    output.mkdir(parents=True, exist_ok=True)
    reports = []
    for script in load_scripts(args.input, args.library):
        parsed = script["parsed"]
        root = decode_prototype(parsed["root"])
        relative = Path(script["kind"]) / Path(*extractor.safe_name(script["name"]).parts)
        bytecode_path = output / "bytecode" / Path(str(relative) + ".luac")
        bytecode_path.parent.mkdir(parents=True, exist_ok=True)
        bytecode = lua51_chunk(parsed, root, script["name"], args.size_t)
        bytecode_path.write_bytes(bytecode)
        assembly_path = output / "instructions" / Path(str(relative) + ".txt")
        assembly_path.parent.mkdir(parents=True, exist_ok=True)
        assembly_path.write_text(disassembly(parsed, root, script["name"]), encoding="utf-8")
        prototypes, words = prototype_counts(root)
        report = {
            "name": script["name"], "kind": script["kind"], "prototype_count": prototypes,
            "instruction_word_count": words, "bytecode_sha256": hashlib.sha256(bytecode).hexdigest(),
            "bytecode": bytecode_path.relative_to(output).as_posix(),
            "instructions": assembly_path.relative_to(output).as_posix(),
            "bytecode_valid": None, "lua_syntax_valid": None,
        }
        if validator:
            status, unused, errors = run_tool([validator, "-p", str(bytecode_path)], args.timeout)
            if status:
                raise extractor.FormatError(f'Lua 5.1 rejected decoded {script["name"]}: {errors.strip()}')
            report["bytecode_valid"] = True
        if decompiler:
            status, source, errors = run_tool(decompiler + [str(bytecode_path)], args.timeout)
            source_path = output / "lua" / Path(str(relative) + ".lua")
            source_path.parent.mkdir(parents=True, exist_ok=True)
            source_path.write_bytes(source)
            report["lua"] = source_path.relative_to(output).as_posix()
            report["decompiler_exit_code"] = status
            report["decompiler_stderr"] = errors.strip()
            report["decompiler_error_markers"] = source.count(b"DECOMPILER ERROR")
            if validator and source:
                syntax_status, unused, syntax_errors = run_tool([validator, "-p", str(source_path)], args.timeout)
                report["lua_syntax_valid"] = syntax_status == 0
                report["lua_syntax_error"] = syntax_errors.strip()
        reports.append(report)
        clean = report["lua_syntax_valid"] and not report.get("decompiler_error_markers") and not report.get("decompiler_exit_code")
        state = "decoded" if not decompiler else "Lua syntax OK" if clean else "Lua needs review"
        print(f'{state:16} {script["name"]:55} {words:6} words', flush=True)
    manifest = {
        "input": str(args.input), "decode_key": DECODE_KEY, "opcode_map": SECURE_OPCODES,
        "target_format": "stock Lua 5.1 little-endian chunks", "size_t": args.size_t,
        "decompiler": decompiler, "validator": validator, "scripts": reports,
        "note": "Lua is reconstructed from embedded instruction words, never copied from OBB sources. Syntax validation does not prove semantic equivalence. Review decompiler diagnostics.",
    }
    extractor.write_json(output / "manifest.json", manifest)
    words = sum(report["instruction_word_count"] for report in reports)
    prototypes = sum(report["prototype_count"] for report in reports)
    print(f"\nDecoded {words} instruction words across {prototypes} prototypes in {len(reports)} scripts.")
    if decompiler:
        good = sum(report["lua_syntax_valid"] is True for report in reports)
        print(f"Generated Lua: {good}/{len(reports)} files pass Lua 5.1 syntax checking; inspect manifest diagnostics.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", default=Path("client.apk"), help="APK, ELF32 library, PE32 executable, or extraction directory containing manifest.json")
    parser.add_argument("-o", "--output", type=Path, default=Path("decoded_lua"))
    parser.add_argument("--library", help="APK member when multiple engine ABIs exist")
    parser.add_argument("--decompiler", help="unluac.jar or Lua 5.1 LuaDec executable; bundled unluac is preferred")
    parser.add_argument("--java", default="java", help="Java executable for unluac")
    parser.add_argument("--luac", help="Lua 5.1 luac executable for chunk and source validation")
    parser.add_argument("--no-decompile", action="store_true", help="Export decoded instructions and stock bytecode without a decompiler")
    parser.add_argument("--size-t", type=int, choices=(4, 8), default=8, help="Target Lua 5.1 size_t width; must match decompiler platform")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout per tool invocation in seconds")
    args = parser.parse_args(argv)
    try:
        if args.timeout <= 0:
            raise extractor.FormatError("--timeout must be positive")
        decode(args)
    except (extractor.FormatError, OSError, ValueError, KeyError, struct.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    finally:
        for staged in STAGED_TOOLS:
            staged.unlink(missing_ok=True)
        STAGED_TOOLS.clear()
    return 0


if __name__ == "__main__":
    sys.exit(main())
