#!/usr/bin/env python3
"""Apply verified CoreScript replacements to a separate Windows client copy."""

import argparse
import hashlib
import io
import json
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

import decode_corescripts as decoder
import extract_corescripts as extractor
import legacy_bytecode as bytecode
import prepare_web


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def validate_tree(root):
    if root.is_symlink() or not root.is_dir():
        raise extractor.FormatError("Expected a nonsymlink directory: " + str(root))
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise extractor.FormatError("Symlinks and special files are not supported: " + str(path))


def baseline_sources(path):
    if path.is_dir():
        validate_tree(path)
        return {file.relative_to(path).as_posix(): file.read_bytes() for file in path.rglob("*.lua")}
    if not zipfile.is_zipfile(path):
        raise extractor.FormatError("Baseline must be a Lua root or saved decoder ZIP")
    result = {}
    with zipfile.ZipFile(path) as archive:
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.startswith("lua/") or not entry.filename.endswith(".lua"):
                continue
            relative = extractor.safe_name(entry.filename[4:]).as_posix()
            if relative in result or entry.file_size > prepare_web.MAX_ENTRY_BYTES:
                raise extractor.FormatError("Duplicate or oversized baseline Lua entry")
            result[relative] = archive.read(entry)
    if not result:
        raise extractor.FormatError("Baseline ZIP has no lua/core or lua/module sources")
    return result


def select_patches(args, scripts):
    if args.patches:
        manifest = json.loads(args.patches.read_text(encoding="utf-8"))
        if set(manifest) - {"client_sha256", "patches"} or not isinstance(manifest.get("patches"), list):
            raise extractor.FormatError("Expected a manifest with patches and optional client_sha256")
        return manifest["patches"], args.patches.resolve().parent, manifest.get("client_sha256"), []
    sources = args.scripts or Path("decoded_lua/lua")
    baseline = args.baseline or Path("decoded_lua/extracted.zip")
    validate_tree(sources)
    originals = baseline_sources(baseline)
    names = {}
    for script in scripts:
        relative = script["kind"] + "/" + script["name"] + ".lua"
        names[relative] = script["name"]
    selected = []
    skipped = []
    for source in sorted(sources.rglob("*.lua")):
        relative = source.relative_to(sources).as_posix()
        if relative not in names:
            raise extractor.FormatError("Lua source does not identify an embedded script: " + relative)
        if relative not in originals:
            raise extractor.FormatError("Source has no unchanged baseline; use an explicit patch manifest: " + relative)
        if source.read_bytes() == originals[relative]:
            skipped.append(names[relative])
        else:
            selected.append({"script": names[relative], "source": str(source.resolve())})
    return selected, sources.resolve(), None, skipped


def build_replacements(args, patches, root, scripts):
    by_name = {script["name"]: script for script in scripts}
    replacements = {}
    reports = []
    luac = None
    for patch in patches:
        if not isinstance(patch, dict) or set(patch) - {"script", "source", "bytecode", "strings", "expected_sha256"}:
            raise extractor.FormatError("Unknown patch fields")
        name = patch.get("script")
        if name not in by_name or name in replacements:
            raise extractor.FormatError("Script name is missing, duplicated, or ambiguous: " + str(name))
        modes = [key for key in ("source", "bytecode", "strings") if key in patch]
        if len(modes) != 1:
            raise extractor.FormatError("Each patch requires exactly one of source, bytecode, or strings")
        script = by_name[name]
        if patch.get("expected_sha256", script["sha256"]) != script["sha256"]:
            raise extractor.FormatError("Original script hash mismatch: " + name)
        report = {"script": name, "mode": modes[0], "original_sha256": script["sha256"],
                  "original_size": script["blob_size"]}
        if modes[0] == "strings":
            changes = patch["strings"]
            if not isinstance(changes, list) or not changes:
                raise extractor.FormatError("strings must be a nonempty list")
            payload = script["payload"]
            for change in changes:
                if not isinstance(change, dict) or set(change) - {"old", "new", "string_index"}:
                    raise extractor.FormatError("Unknown string replacement fields")
                if not isinstance(change.get("old"), str) or not isinstance(change.get("new"), str):
                    raise extractor.FormatError("String old/new values must be UTF-8 text")
                index = change.get("string_index")
                if index is not None and (type(index) is not int or index <= 0):
                    raise extractor.FormatError("string_index must be a positive 1-based integer")
                payload, unused = extractor.replace_string(payload, change["old"].encode(), change["new"].encode(), index)
            replacement = script["blob"] if payload == script["payload"] else extractor.wrap_rsb1(payload)
        else:
            path = root / Path(patch[modes[0]])
            if not path.is_file():
                raise extractor.FormatError("Replacement file does not exist: " + str(path))
            report["file"] = str(path)
            report["file_sha256"] = extractor.file_hash(path)
            if modes[0] == "bytecode":
                replacement = path.read_bytes()
                unused, payload = extractor.unwrap_rsb1(replacement)
            else:
                if not args.allow_source_recompile:
                    raise extractor.FormatError("Source recompilation can change decompiler semantics and VM behavior; review verification and explicitly pass --allow-source-recompile")
                if luac is None:
                    luac = decoder.find_tool(args.luac, decoder.TOOL_ROOT / "lua-5.1.4" / "src" / "luac", "luac5.1")
                    if not luac:
                        raise extractor.FormatError("A Lua 5.1 compiler is required; supply --luac")
                compiled = bytecode.compile_source(path, luac, args.timeout)
                report["recompile_comparison"] = bytecode.compare_prototypes(script["parsed"], compiled)
                payload = bytecode.serialize_payload(compiled)
                replacement = script["blob"] if payload == script["payload"] else extractor.wrap_rsb1(payload)
                report["warning"] = "Stock Lua 5.1 compiler output is structurally validated, not proven semantically equivalent or runtime-tested."
        parsed = extractor.parse_payload(payload)
        decoder.decode_prototype(parsed["root"])
        unused, verified_payload = extractor.unwrap_rsb1(replacement)
        if verified_payload != payload:
            raise extractor.FormatError("Replacement container round trip failed: " + name)
        replacements[name] = replacement
        report.update({"replacement_sha256": sha256(replacement), "replacement_size": len(replacement),
                       "changed": replacement != script["blob"], "requires_relocation": len(replacement) > script["blob_size"]})
        reports.append(report)
    return replacements, reports


def content_entries(path):
    with zipfile.ZipFile(path) as archive:
        candidates = [entry for entry in archive.infolist() if entry.filename.lower().endswith(".obb")]
        if candidates:
            if len(candidates) != 1 or candidates[0].file_size > prepare_web.MAX_TOTAL_BYTES:
                raise extractor.FormatError("Expected one size-bounded nested OBB")
            data = io.BytesIO(archive.read(candidates[0]))
            with zipfile.ZipFile(data) as obb:
                for entry, relative in prepare_web.validate_assets(obb):
                    if relative.parts[0] == "content":
                        yield relative, obb.read(entry)
        else:
            for entry, relative in prepare_web.validate_assets(archive):
                if relative.parts[0] == "content":
                    yield relative, archive.read(entry)


def populate_content(source, destination=None):
    count = 0
    total = 0
    if source.is_dir():
        validate_tree(source)
        files = ((Path("content") / file.relative_to(source), file.read_bytes())
                 for file in sorted(source.rglob("*")) if file.is_file())
    else:
        files = content_entries(source)
    for relative, data in files:
        extractor.safe_name(relative.as_posix())
        count += 1
        total += len(data)
        if count > prepare_web.MAX_FILES or total > prepare_web.MAX_TOTAL_BYTES or len(data) > prepare_web.MAX_ENTRY_BYTES:
            raise extractor.FormatError("Content exceeds extraction limits")
        if destination is not None:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(data)
    if not count:
        raise extractor.FormatError("No content/ files found; for a directory, select the content directory itself")
    return {"source": str(source), "file_count": count, "total_bytes": total,
            "warning": "Android OBB content is reused; this is not a verified complete Windows content distribution. PC PlatformContent and shaders remain from Windows."}


def apply(args):
    if args.input.is_dir():
        client = args.input.resolve()
        validate_tree(client)
        executable = client / "RobloxPlayerBeta.exe"
    else:
        executable = args.input.resolve()
        client = None
    binary = executable.read_bytes()
    extractor.Pe32(binary)
    output = args.output.resolve()
    if output.exists() or output == executable or (client is not None and output.is_relative_to(client)):
        raise extractor.FormatError("Output must be a new directory outside the original client")
    scripts = extractor.find_scripts(binary)
    for script in scripts:
        checked = bytecode.verify_roundtrip(script)
        if not all(checked[key] for key in ("instruction_roundtrip_equal", "payload_roundtrip_equal", "container_payload_equal")):
            raise extractor.FormatError("Original bytecode verification failed: " + script["name"])
    patches, root, expected_hash, skipped = select_patches(args, scripts)
    if expected_hash is not None and expected_hash != sha256(binary):
        raise extractor.FormatError("Client executable hash does not match patch manifest")
    replacements, reports = build_replacements(args, patches, root, scripts)
    modified = extractor.replace_blobs(binary, scripts, replacements)
    if args.content_from and client is not None and (client / "content").exists():
        raise extractor.FormatError("Client already has content/; refused to overwrite it")
    content_report = populate_content(args.content_from) if args.content_from else None
    manifest = {"input": str(executable), "input_sha256": sha256(binary), "output_sha256": sha256(modified),
                "embedded_script_count": len(scripts), "patches": reports, "unchanged_sources_skipped": skipped,
                "content": content_report, "dry_run": args.dry_run,
                "note": "Original client is never modified. Unselected blobs are verified unchanged. Modifying a PE invalidates any Authenticode signature and may trigger client integrity checks. No integrity-check bypass is applied. Runtime behavior is untested."}
    print(f"Verified {len(scripts)} original scripts; {sum(report['changed'] for report in reports)} changed; {len(skipped)} unchanged sources skipped.")
    for report in reports:
        print(f"{report['script']}: {report['mode']}, {report['original_size']} -> {report['replacement_size']} bytes" +
              (" (new PE section)" if report["requires_relocation"] else ""))
    if args.dry_run:
        if args.report:
            extractor.write_json(args.report, manifest)
        print("Dry run complete; no client output written.")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".client-patch-", dir=output.parent) as temporary:
        staged = Path(temporary) / "client"
        if client is not None:
            shutil.copytree(client, staged)
        else:
            staged.mkdir()
        (staged / "RobloxPlayerBeta.exe").write_bytes(modified)
        if args.content_from:
            populate_content(args.content_from, staged)
        extractor.write_json(staged / "patch-report.json", {**manifest, "dry_run": False})
        if extractor.file_hash(executable) != manifest["input_sha256"]:
            raise extractor.FormatError("Input changed while patching; output not published")
        if output.exists():
            raise extractor.FormatError("Output appeared while patching; refused to replace it")
        staged.rename(output)
    if args.report:
        extractor.write_json(args.report, {**manifest, "dry_run": False})
    print("Patched client: " + str(output))
    if not args.content_from and (client is None or not (client / "content").is_dir()):
        print("Warning: content/ is still absent. Use --content-from client.apk to reuse bundled Android content.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, nargs="?", default=Path("windows"), help="Windows client directory or PE32 executable")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--patches", type=Path, help="JSON manifest; paths are relative to the manifest")
    modes.add_argument("--scripts", type=Path, help="Edited Lua root with core/ and module/ (default decoded_lua/lua)")
    parser.add_argument("--baseline", type=Path, help="Unedited Lua root or decoder ZIP (default decoded_lua/extracted.zip)")
    parser.add_argument("--allow-source-recompile", action="store_true", help="Explicitly accept stock-compiler/decompiler semantic risks")
    parser.add_argument("--luac", help="Lua 5.1 compiler, never Lua 5.4")
    parser.add_argument("--content-from", type=Path, help="APK, OBB/ZIP with content/, or a content directory; never overwrites existing Windows content")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--report", type=Path, help="Optional extra JSON report")
    parser.add_argument("-o", "--output", type=Path, default=Path("windows_patched"))
    args = parser.parse_args(argv)
    try:
        if args.timeout <= 0 or (args.patches and args.baseline):
            raise extractor.FormatError("Timeout must be positive; --baseline applies only to --scripts")
        original_directory = args.input.resolve() if args.input.is_dir() else args.input.resolve().parent
        if args.report and (args.report.resolve() == args.input.resolve() or
                            args.report.resolve().is_relative_to(args.output.resolve()) or
                            args.report.resolve().is_relative_to(original_directory)):
            raise extractor.FormatError("Extra report must be outside the original and output clients")
        apply(args)
    except (extractor.FormatError, OSError, ValueError, KeyError, TypeError, struct.error, zipfile.BadZipFile) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1
    finally:
        for staged in decoder.STAGED_TOOLS:
            staged.unlink(missing_ok=True)
        decoder.STAGED_TOOLS.clear()
    return 0


if __name__ == "__main__":
    sys.exit(main())
