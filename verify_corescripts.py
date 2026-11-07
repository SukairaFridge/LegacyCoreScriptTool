#!/usr/bin/env python3
"""Verify exact extraction round trips separately from Lua recompilation."""

import argparse
import sys
import struct
from pathlib import Path

import decode_corescripts as decoder
import extract_corescripts as extractor
import legacy_bytecode as bytecode


def verify(args):
    scripts = list(decoder.load_scripts(args.input, args.library))
    other = {script["name"]: script for script in decoder.load_scripts(args.compare_client, None)} if args.compare_client else None
    luac = None
    if args.sources:
        luac = decoder.find_tool(args.luac, decoder.TOOL_ROOT / "lua-5.1.4" / "src" / "luac", "luac5.1")
        if not luac:
            raise extractor.FormatError("Lua 5.1 luac is required for --sources")
    reports = []
    failed = False
    for script in scripts:
        if "payload" not in script:
            unused, script["payload"] = extractor.unwrap_rsb1(script["blob"])
        report = {"name": script["name"], "kind": script["kind"], **bytecode.verify_roundtrip(script)}
        if not all(report[key] for key in ("instruction_roundtrip_equal", "payload_roundtrip_equal", "container_payload_equal")):
            failed = True
        if other is not None:
            candidate = other.get(script["name"])
            report["other_client_blob_equal"] = candidate is not None and script["blob"] == candidate["blob"]
            if candidate:
                report["other_client_prototypes"] = bytecode.compare_prototypes(script["parsed"], candidate["parsed"])
            if not report["other_client_blob_equal"]:
                failed = True
        if args.sources:
            relative = Path(script["kind"]) / Path(*extractor.safe_name(script["name"]).parts)
            source = args.sources / Path(str(relative) + ".lua")
            report["source"] = str(source)
            if not source.is_file():
                report["source_error"] = "Source is missing"
                failed = True
            else:
                try:
                    compiled = bytecode.compile_source(source, luac, args.timeout)
                    report["recompile"] = bytecode.compare_prototypes(script["parsed"], compiled)
                    report["recompile"]["serialized_payload_equal"] = bytecode.serialize_payload(compiled) == script["payload"]
                    if not report["recompile"]["code_and_constants_equal"] or not report["recompile"]["serialized_payload_equal"]:
                        failed = True
                except (extractor.FormatError, OSError, ValueError) as error:
                    report["source_error"] = str(error)
                    failed = True
        reports.append(report)
        state = "exact extraction" if report["payload_roundtrip_equal"] and report["instruction_roundtrip_equal"] else "ROUNDTRIP FAILURE"
        if "recompile" in report:
            state += "; source instruction mismatches=" + str(report["recompile"]["instruction_mismatches"])
        print(script["name"] + ": " + state, flush=True)
    if other is not None and set(other) != {script["name"] for script in scripts}:
        failed = True
    extractor.write_json(args.output, {"input": str(args.input), "compare_client": str(args.compare_client) if other is not None else None,
                                      "other_client_names_equal": set(other) == {script["name"] for script in scripts} if other is not None else None,
                                      "scripts": reports, "passed": not failed,
                                      "note": "Recompression need not reproduce identical compressed bytes. Code equality is not proof of runtime compatibility; source mismatches are not accepted as equivalence."})
    print("Report: " + str(args.output))
    return 1 if failed else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="APK, ELF32, PE32, or extraction directory")
    parser.add_argument("--compare-client", type=Path)
    parser.add_argument("--sources", type=Path, help="Lua root containing core/ and module/; recompiles every script")
    parser.add_argument("--library")
    parser.add_argument("--luac")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("-o", "--output", type=Path, default=Path("analysis/verification.json"))
    args = parser.parse_args(argv)
    try:
        if args.timeout <= 0:
            raise extractor.FormatError("--timeout must be positive")
        for input_path in (args.input, args.compare_client, args.sources):
            if input_path is not None and (args.output.resolve() == input_path.resolve() or
                                          (input_path.is_dir() and args.output.resolve().is_relative_to(input_path.resolve()))):
                raise extractor.FormatError("Verification report must be outside input files and directories")
        return verify(args)
    except (extractor.FormatError, OSError, ValueError, KeyError, struct.error) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    finally:
        for staged in decoder.STAGED_TOOLS:
            staged.unlink(missing_ok=True)
        decoder.STAGED_TOOLS.clear()


if __name__ == "__main__":
    sys.exit(main())
