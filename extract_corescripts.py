#!/usr/bin/env python3
"""Extract and size-safely patch legacy Roblox RSB1 CoreScripts."""

import argparse
import codecs
import copy
import hashlib
import io
import json
import math
import re
import struct
import sys
import zipfile
from pathlib import Path, PurePosixPath


MASK32 = 0xFFFFFFFF
MAX_PAYLOAD = 64 * 1024 * 1024
MAGIC = b"RSB1"
PRIMES = (2654435761, 2246822519, 3266489917, 668265263, 374761393)


class FormatError(ValueError):
    pass


def rotate_left(value, count):
    value &= MASK32
    return ((value << count) | (value >> (32 - count))) & MASK32


def xxhash32(data, seed=42):
    prime_one, prime_two, prime_three, prime_four, prime_five = PRIMES
    position = 0
    if len(data) >= 16:
        lanes = [seed + prime_one + prime_two, seed + prime_two, seed, seed - prime_one]
        while position <= len(data) - 16:
            words = struct.unpack_from("<4I", data, position)
            for index, word in enumerate(words):
                lanes[index] = rotate_left(lanes[index] + word * prime_two, 13) * prime_one & MASK32
            position += 16
        result = sum(rotate_left(lane, count) for lane, count in zip(lanes, (1, 7, 12, 18))) & MASK32
    else:
        result = (seed + prime_five) & MASK32
    result = (result + len(data)) & MASK32
    while position <= len(data) - 4:
        result = rotate_left(result + struct.unpack_from("<I", data, position)[0] * prime_three, 17)
        result = result * prime_four & MASK32
        position += 4
    while position < len(data):
        result = rotate_left(result + data[position] * prime_five, 11) * prime_one & MASK32
        position += 1
    result ^= result >> 15
    result = result * prime_two & MASK32
    result ^= result >> 13
    result = result * prime_three & MASK32
    return (result ^ (result >> 16)) & MASK32


def lz4_decompress(data, expected_size):
    output = bytearray()
    position = 0

    def extended_length(length):
        nonlocal position
        if length == 15:
            while True:
                if position >= len(data):
                    raise FormatError("Truncated LZ4 length")
                extra = data[position]
                position += 1
                length += extra
                if extra != 255:
                    break
        return length

    while position < len(data):
        token = data[position]
        position += 1
        literal_size = extended_length(token >> 4)
        if position + literal_size > len(data) or len(output) + literal_size > expected_size:
            raise FormatError("Invalid LZ4 literal size")
        output.extend(data[position:position + literal_size])
        position += literal_size
        if position == len(data):
            break
        if position + 2 > len(data):
            raise FormatError("Truncated LZ4 match offset")
        distance = struct.unpack_from("<H", data, position)[0]
        position += 2
        if not distance or distance > len(output):
            raise FormatError("Invalid LZ4 match offset")
        match_size = extended_length(token & 15) + 4
        if len(output) + match_size > expected_size:
            raise FormatError("LZ4 output exceeds declared size")
        pattern = bytes(output[-distance:])
        repeats, remainder = divmod(match_size, distance)
        output.extend(pattern * repeats + pattern[:remainder])
    if len(output) != expected_size:
        raise FormatError("LZ4 output size does not match header")
    return bytes(output)


def lz4_compress(data):
    output = bytearray()
    positions = {}
    position = 0
    anchor = 0

    def write_length(length):
        while length >= 255:
            output.append(255)
            length -= 255
        output.append(length)

    while position <= len(data) - 12:
        word = data[position:position + 4]
        previous = positions.get(word)
        positions[word] = position
        if previous is None or position - previous > 65535:
            position += 1
            continue
        match_end = position + 4
        while match_end < len(data) - 5 and data[previous + match_end - position] == data[match_end]:
            match_end += 1
        literal_size = position - anchor
        match_length = match_end - position - 4
        output.append((min(literal_size, 15) << 4) | min(match_length, 15))
        if literal_size >= 15:
            write_length(literal_size - 15)
        output.extend(data[anchor:position])
        output.extend(struct.pack("<H", position - previous))
        if match_length >= 15:
            write_length(match_length - 15)
        for skipped in range(position + 1, match_end):
            positions[data[skipped:skipped + 4]] = skipped
        position = match_end
        anchor = match_end
    literal_size = len(data) - anchor
    output.append(min(literal_size, 15) << 4)
    if literal_size >= 15:
        write_length(literal_size - 15)
    output.extend(data[anchor:])
    return bytes(output)


def unwrap_rsb1(blob):
    if len(blob) <= 8:
        raise FormatError("RSB1 blob is too short")
    key = bytes(((blob[index] ^ MAGIC[index]) - 41 * index) & 255 for index in range(4))
    header = bytes(blob[index] ^ ((key[index % 4] + 41 * index) & 255) for index in range(8))
    expected_size = struct.unpack_from("<I", header, 4)[0]
    if not 0 < expected_size <= MAX_PAYLOAD:
        raise FormatError("Implausible RSB1 decompressed size")
    if len(blob) > expected_size + expected_size // 255 + 24:
        raise FormatError("Implausible RSB1 compressed size")
    decoded = bytes(value ^ ((key[index % 4] + 41 * index) & 255) for index, value in enumerate(blob))
    if xxhash32(decoded) != int.from_bytes(key, "little"):
        raise FormatError("RSB1 XXH32 integrity check failed")
    return decoded, lz4_decompress(decoded[8:], expected_size)


def wrap_rsb1(payload):
    decoded = MAGIC + struct.pack("<I", len(payload)) + lz4_compress(payload)
    key = xxhash32(decoded).to_bytes(4, "little")
    return bytes(value ^ ((key[index % 4] + 41 * index) & 255) for index, value in enumerate(decoded))


class Reader:
    def __init__(self, data, position=0, limit=None):
        self.data = data
        self.position = position
        self.limit = len(data) if limit is None else limit

    def take(self, size):
        if size < 0 or self.position + size > self.limit:
            raise FormatError("Truncated serialized prototype")
        result = self.data[self.position:self.position + size]
        self.position += size
        return result

    def number(self, format_string):
        return struct.unpack(format_string, self.take(struct.calcsize(format_string)))[0]

    def count(self):
        count = self.number("<I")
        if count > len(self.data):
            raise FormatError("Implausible prototype count")
        return count


def read_string_table(payload):
    reader = Reader(payload)
    status = reader.number("<B")
    if status:
        raise FormatError("Embedded bytecode reports a compiler error")
    table_offset = 1 + reader.number("<I")
    if table_offset < 5 or table_offset > len(payload) - 4:
        raise FormatError("Invalid serialized string-table offset")
    reader.position = table_offset
    count = reader.count()
    lengths = [reader.count() for unused in range(count)]
    strings = [reader.take(length) for length in lengths]
    if reader.position != len(payload):
        raise FormatError("Unexpected bytes following the string table")
    return table_offset, strings


def parse_payload(payload):
    table_offset, strings = read_string_table(payload)
    reader = Reader(payload, 5, table_offset)

    def string_index():
        index = reader.count()
        if index > len(strings):
            raise FormatError("Prototype string index is out of bounds")
        return index

    def prototype(depth=0):
        if depth > 100:
            raise FormatError("Prototype nesting is too deep")
        child_count, constant_count, code_count, local_count, line_count, upvalue_count = (
            reader.count() for unused in range(6)
        )
        stack_size, vararg, upvalues, parameters = reader.take(4)
        constants = []
        for unused in range(constant_count):
            kind = reader.number("<B")
            constant = {"type": ("nil", "false", "true", "number", "string")[kind]} if kind <= 4 else None
            if constant is None:
                raise FormatError("Unknown serialized constant type")
            if kind == 3:
                raw_number = reader.take(8)
                value = struct.unpack("<d", raw_number)[0]
                constant["value"] = value if math.isfinite(value) else str(value)
                constant["number_hex"] = raw_number.hex()
            elif kind == 4:
                constant["string_index"] = string_index()
            constants.append(constant)
        encoded_lines = []
        last_line = 0
        for unused in range(line_count):
            last_line = (last_line + reader.number("<i")) & MASK32
            encoded_lines.append(last_line)
        locals_data = []
        for unused in range(local_count):
            locals_data.append({"start_pc": reader.count(), "end_pc": reader.count(), "string_index": string_index()})
        upvalue_names = [string_index() for unused in range(upvalue_count)]
        instructions = [reader.number("<I") for unused in range(code_count)]
        return {
            "stack_size": stack_size,
            "vararg": vararg,
            "upvalue_count": upvalues,
            "parameter_count": parameters,
            "constants": constants,
            "encoded_lineinfo": encoded_lines,
            "locals": locals_data,
            "upvalue_names": upvalue_names,
            "encoded_instructions": instructions,
            "children": [prototype(depth + 1) for unused in range(child_count)],
        }

    root = prototype()
    if reader.position != table_offset:
        raise FormatError("Prototype does not end at the string table")
    return {
        "format": "Roblox RSB1 serialized Lua prototype (not stock Lua bytecode)",
        "string_table_offset": table_offset,
        "strings": [value.decode("utf-8", "backslashreplace") for value in strings],
        "strings_hex": [value.hex() for value in strings],
        "root": root,
    }


class Elf32:
    def __init__(self, data):
        self.data = data
        if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01":
            raise FormatError("Expected a little-endian ELF32 library; newer clients are not supported")
        header = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
        self.machine = header[2]
        self.segments = []
        for index in range(header[10]):
            offset = header[5] + index * header[9]
            if offset + 32 > len(data):
                raise FormatError("Truncated ELF program headers")
            segment = struct.unpack_from("<8I", data, offset)
            if segment[0] == 1:
                self.segments.append((segment[1], segment[2], segment[4]))
        self.sections = []
        for index in range(header[12]):
            offset = header[6] + index * header[11]
            if offset + 40 > len(data):
                raise FormatError("Truncated ELF section headers")
            self.sections.append(struct.unpack_from("<10I", data, offset))

    def file_offset(self, address, size=1):
        for offset, virtual_address, file_size in self.segments:
            if virtual_address <= address and address + size <= virtual_address + file_size:
                result = offset + address - virtual_address
                if result + size <= len(self.data):
                    return result
        raise FormatError("ELF address is outside file-backed segments")

    def virtual_address(self, file_offset):
        for offset, virtual_address, file_size in self.segments:
            if offset <= file_offset < offset + file_size:
                return virtual_address + file_offset - offset
        raise FormatError("File offset is outside ELF load segments")


def safe_name(name):
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in (".", "..") for part in path.parts):
        raise FormatError("Unsafe script path")
    if "\\" in name or "\x00" in name or ":" in name:
        raise FormatError("Unsafe script path")
    return path


class Pe32:
    def __init__(self, data):
        self.data = data
        if len(data) < 64 or data[:2] != b"MZ":
            raise FormatError("Expected a PE32 executable")
        self.header = struct.unpack_from("<I", data, 60)[0]
        if self.header + 24 > len(data) or data[self.header:self.header + 4] != b"PE\0\0":
            raise FormatError("Invalid PE header")
        self.machine, count = struct.unpack_from("<HH", data, self.header + 4)
        optional_size = struct.unpack_from("<H", data, self.header + 20)[0]
        self.optional = self.header + 24
        if self.machine != 0x14C or optional_size < 224 or self.optional + optional_size > len(data):
            raise FormatError("Only little-endian x86 PE32 clients are supported")
        if struct.unpack_from("<H", data, self.optional)[0] != 0x10B:
            raise FormatError("Expected PE32, not PE32+")
        self.image_base = struct.unpack_from("<I", data, self.optional + 28)[0]
        self.section_alignment, self.file_alignment = struct.unpack_from("<II", data, self.optional + 32)
        if any(not value or value & (value - 1) for value in (self.section_alignment, self.file_alignment)):
            raise FormatError("Invalid PE alignment")
        self.section_table = self.optional + optional_size
        self.sections = []
        for index in range(count):
            offset = self.section_table + index * 40
            if offset + 40 > len(data):
                raise FormatError("Truncated PE section table")
            virtual_size, address, size, raw = struct.unpack_from("<4I", data, offset + 8)
            flags = struct.unpack_from("<I", data, offset + 36)[0]
            if raw + size > len(data):
                raise FormatError("PE section is outside the file")
            self.sections.append((raw, self.image_base + address, size, virtual_size, flags))

    def file_offset(self, address, size=1):
        for raw, virtual, file_size, unused, flags in self.sections:
            if virtual <= address and address + size <= virtual + file_size:
                return raw + address - virtual
        raise FormatError("PE address is outside file-backed sections")

    def virtual_address(self, file_offset):
        for raw, virtual, size, unused, flags in self.sections:
            if raw <= file_offset < raw + size:
                return virtual + file_offset - raw
        raise FormatError("File offset is outside PE sections")

    def relocations(self):
        directory_count = struct.unpack_from("<I", self.data, self.optional + 92)[0]
        if directory_count <= 5:
            return set()
        rva, size = struct.unpack_from("<II", self.data, self.optional + 96 + 5 * 8)
        if not size:
            return set()
        start = self.file_offset(self.image_base + rva, size)
        reader = Reader(self.data, start, start + size)
        result = set()
        while reader.position < reader.limit:
            page, block_size = reader.number("<I"), reader.number("<I")
            if block_size < 8 or block_size % 2 or block_size - 8 > reader.limit - reader.position:
                raise FormatError("Invalid PE relocation block")
            for unused in range((block_size - 8) // 2):
                entry = reader.number("<H")
                if entry >> 12 == 3:
                    result.add(page + (entry & 4095))
        return result


def binary_image(binary):
    return Pe32(binary) if binary[:2] == b"MZ" else Elf32(binary)


def find_scripts(binary):
    image = binary_image(binary)
    names = {}
    for match in re.finditer(rb"(?<=\x00)[A-Za-z][A-Za-z0-9_./-]{1,200}\x00", binary):
        encoded_name = match.group()[:-1].decode("ascii")
        try:
            name = codecs.decode(encoded_name, "rot13")
            safe_name(name)
            names[image.virtual_address(match.start())] = (name, encoded_name)
        except FormatError:
            continue
    found = {}
    if isinstance(image, Pe32):
        sections = [(raw, size) for raw, unused, size, virtual_size, flags in image.sections
                    if flags & 0x40000000 and not flags & 0x20000000]
    else:
        sections = [(section[4], section[5]) for section in image.sections
                    if section[1] == 1 and section[2] & 2 and not section[2] & 4]
    for offset, size in sections:
        if offset + size > len(binary):
            raise FormatError("ELF section is outside the file")
        for shift in (0, 4, 8):
            start = offset + shift
            stop = start + max(0, (size - shift) // 12) * 12
            entries = memoryview(binary)[start:stop]
            for index, (name_address, blob_address, blob_size) in enumerate(struct.iter_unpack("<III", entries)):
                if name_address not in names or not 8 < blob_size <= MAX_PAYLOAD:
                    continue
                try:
                    blob_offset = image.file_offset(blob_address, blob_size)
                    blob = binary[blob_offset:blob_offset + blob_size]
                    decoded, payload = unwrap_rsb1(blob)
                    parsed = parse_payload(payload)
                except FormatError:
                    continue
                name, encoded_name = names[name_address]
                table_offset = start + index * 12
                found[table_offset] = {
                    "name": name,
                    "encoded_name": encoded_name,
                    "kind": "core" if name.startswith(("CoreScripts/", "Libraries/")) or name in (
                        "LoadingScript", "StarterScript", "ServerStarterScript"
                    ) else "module",
                    "table_offset": table_offset,
                    "size_field_offset": table_offset + 8,
                    "blob_offset": blob_offset,
                    "blob_virtual_address": blob_address,
                    "blob_size": blob_size,
                    "payload_size": len(payload),
                    "sha256": hashlib.sha256(blob).hexdigest(),
                    "blob": blob,
                    "decoded": decoded,
                    "payload": payload,
                    "parsed": parsed,
                }
    if not found:
        raise FormatError("No valid RSB1 CoreScript tables found; this client may use another format")
    return sorted(found.values(), key=lambda entry: entry["table_offset"])


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def pe_checksum(binary, checksum_offset):
    total = 0
    for offset in range(0, len(binary), 2):
        if checksum_offset <= offset < checksum_offset + 4:
            continue
        total += int.from_bytes(binary[offset:offset + 2], "little")
        total = (total & 65535) + (total >> 16)
    return ((total & 65535) + (total >> 16)) + len(binary)


def replace_blobs(binary, scripts, replacements):
    by_name = {script["name"]: script for script in scripts}
    if len(by_name) != len(scripts) or not set(replacements) <= by_name.keys():
        raise FormatError("Replacement names are missing or ambiguous")
    for name, blob in replacements.items():
        unused, payload = unwrap_rsb1(blob)
        parse_payload(payload)
    changed = {name: blob for name, blob in replacements.items() if blob != by_name[name]["blob"]}
    if not changed:
        return binary
    image = binary_image(binary)
    modified = bytearray(binary)
    relocated = {name: blob for name, blob in changed.items() if len(blob) > by_name[name]["blob_size"]}
    if relocated and not isinstance(image, Pe32):
        raise FormatError("Larger ELF/APK replacements need relocation; only PE32 relocation is supported")
    section_rva = section_raw = 0
    appended = bytearray()
    if relocated:
        section_header = image.section_table + 40 * len(image.sections)
        header_limit = min(struct.unpack_from("<I", binary, image.optional + 60)[0],
                           min(raw for raw, unused, size, virtual_size, flags in image.sections if size))
        if section_header + 40 > header_limit or any(binary[section_header:section_header + 40]):
            raise FormatError("No spare PE section-header space; refused to shift existing sections")
        if len(image.sections) >= 96:
            raise FormatError("PE section limit reached")
        section_rva = align(max(virtual - image.image_base + max(size, virtual_size)
                                for raw, virtual, size, virtual_size, flags in image.sections), image.section_alignment)
        section_raw = align(len(binary), image.file_alignment)
        relocations = image.relocations()
        dynamic_base = struct.unpack_from("<H", binary, image.optional + 70)[0] & 0x40
        for name in relocated:
            field_rva = image.virtual_address(by_name[name]["table_offset"] + 4) - image.image_base
            if (dynamic_base or relocations) and field_rva not in relocations:
                raise FormatError("Missing base relocation for script pointer: " + name)
    for name, blob in changed.items():
        script = by_name[name]
        if name in relocated:
            appended.extend(bytes(align(len(appended), 4) - len(appended)))
            address = image.image_base + section_rva + len(appended)
            if address + len(blob) > MASK32:
                raise FormatError("PE replacement address overflows 32 bits")
            struct.pack_into("<I", modified, script["table_offset"] + 4, address)
            appended.extend(blob)
        else:
            offset, size = script["blob_offset"], script["blob_size"]
            modified[offset:offset + size] = blob + bytes(size - len(blob))
        struct.pack_into("<I", modified, script["size_field_offset"], len(blob))
    if appended:
        raw_size = align(len(appended), image.file_alignment)
        modified.extend(bytes(section_raw - len(modified)))
        modified.extend(appended)
        modified.extend(bytes(raw_size - len(appended)))
        struct.pack_into("<8s8I", modified, section_header, b".rbxcs\0\0", len(appended),
                         section_rva, raw_size, section_raw, 0, 0, 0, 0x40000040)
        struct.pack_into("<H", modified, image.header + 6, len(image.sections) + 1)
        struct.pack_into("<I", modified, image.optional + 56,
                         align(section_rva + len(appended), image.section_alignment))
        initialized = struct.unpack_from("<I", modified, image.optional + 8)[0]
        struct.pack_into("<I", modified, image.optional + 8, initialized + raw_size)
    if isinstance(image, Pe32):
        struct.pack_into("<I", modified, image.optional + 64, pe_checksum(modified, image.optional + 64))
    verified = find_scripts(modified)
    if {(script["name"], script["table_offset"]) for script in verified} != {(script["name"], script["table_offset"]) for script in scripts}:
        raise FormatError("Script tables changed unexpectedly after patching")
    for script in verified:
        expected = replacements.get(script["name"], by_name[script["name"]]["blob"])
        if script["blob"] != expected:
            raise FormatError("Post-patch verification failed: " + script["name"])
    return bytes(modified)


def load_binary(input_path, library=None):
    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path) as archive:
            candidates = [name for name in archive.namelist() if name.startswith("lib/") and name.endswith("/libroblox.so")]
            if library is None:
                if len(candidates) != 1:
                    raise FormatError("Specify --library; found: " + ", ".join(candidates))
                library = candidates[0]
            if library not in candidates:
                raise FormatError("Requested libroblox.so is not present in APK")
            return archive.read(library), library
    if library:
        raise FormatError("--library applies only to APK input")
    return input_path.read_bytes(), None


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_sources(input_path, output):
    result = []

    def collect(archive, container):
        for entry in archive.infolist():
            if entry.is_dir() or not entry.filename.lower().endswith((".lua", ".rbxmx")):
                continue
            relative = safe_name(entry.filename)
            destination = output / "sources" / Path(*relative.parts)
            if destination.exists():
                raise FormatError("Conflicting bundled source path: " + entry.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(entry)
            destination.write_bytes(data)
            result.append({"container": container, "path": entry.filename, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    if zipfile.is_zipfile(input_path):
        with zipfile.ZipFile(input_path) as apk:
            collect(apk, "APK")
            for entry in apk.infolist():
                if not entry.filename.lower().endswith(".obb"):
                    continue
                buffer = io.BytesIO(apk.read(entry))
                if zipfile.is_zipfile(buffer):
                    with zipfile.ZipFile(buffer) as obb:
                        collect(obb, entry.filename)
    return result


def extract(args):
    binary, library = load_binary(args.input, args.library)
    scripts = find_scripts(binary)
    output = args.output
    if output.exists() and any(output.iterdir()):
        raise FormatError("Extraction directory must be empty to avoid overwriting files")
    output.mkdir(parents=True, exist_ok=True)
    manifest_entries = []
    for script in scripts:
        relative = Path(script["kind"]) / Path(*safe_name(script["name"]).parts)
        destination = output / "embedded" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        paths = {}
        for extension, key in ((".rbxb", "blob"), (".rsb", "decoded"), (".payload", "payload")):
            target = Path(str(destination) + extension)
            target.write_bytes(script[key])
            paths[key] = target.relative_to(output).as_posix()
        target = Path(str(destination) + ".json")
        write_json(target, script["parsed"])
        paths["parsed"] = target.relative_to(output).as_posix()
        entry = {key: value for key, value in script.items() if key not in ("blob", "decoded", "payload", "parsed")}
        entry["files"] = paths
        manifest_entries.append(entry)
        print(f'{script["kind"]:6} {script["name"]:55} {script["blob_size"]:7} bytes @ 0x{script["blob_offset"]:08x}')
    sources = extract_sources(args.input, output)
    write_json(output / "manifest.json", {
        "input": str(args.input),
        "input_sha256": file_hash(args.input),
        "library": library,
        "library_sha256": hashlib.sha256(binary).hexdigest(),
        "scripts": manifest_entries,
        "bundled_sources": sources,
        "note": "Bundled Lua sources are copied from assets, not decompiled. Instructions in JSON remain encoded.",
    })
    print(f"\nExtracted {len(scripts)} embedded scripts and {len(sources)} bundled source/model files into {output}")


def replace_string(payload, old, new, selected_index):
    table_offset, strings = read_string_table(payload)
    matches = [index for index, value in enumerate(strings) if value == old]
    if selected_index is not None:
        index = selected_index - 1
        if index not in matches:
            raise FormatError("--string-index does not identify the requested old string (indices are 1-based)")
        matches = [index]
    if not matches:
        raise FormatError("Old string is not an exact string-table entry; inspect the extracted JSON")
    for index in matches:
        strings[index] = new
    table = struct.pack("<I", len(strings))
    table += b"".join(struct.pack("<I", len(value)) for value in strings)
    return payload[:table_offset] + table + b"".join(strings), [index + 1 for index in matches]


def rebuild_apk(input_path, output_path, library, binary):
    signature = re.compile(r"^META-INF/(?:MANIFEST\.MF|[^/]+\.(?:SF|RSA|DSA|EC))$", re.IGNORECASE)
    with zipfile.ZipFile(input_path) as source, zipfile.ZipFile(output_path, "x") as target:
        if len(set(source.namelist())) != len(source.namelist()):
            raise FormatError("Cannot safely rebuild an APK with duplicate ZIP entries")
        target.comment = source.comment
        for entry in source.infolist():
            if signature.match(entry.filename):
                continue
            data = binary if entry.filename == library else source.read(entry)
            target.writestr(copy.copy(entry), data)


def patch(args):
    if args.output.exists() or args.input.resolve() == args.output.resolve():
        raise FormatError("Patch output must be a new file; the original is never overwritten")
    binary, library = load_binary(args.input, args.library)
    scripts = find_scripts(binary)
    matches = [script for script in scripts if script["name"] == args.script]
    if len(matches) != 1:
        raise FormatError("Script name is missing or ambiguous; use the exact manifest name")
    script = matches[0]
    if args.bytecode:
        if args.old is not None or args.new is not None or args.string_index is not None:
            raise FormatError("--bytecode cannot be combined with string replacement")
        replacement = args.bytecode.read_bytes()
        unused, payload = unwrap_rsb1(replacement)
    else:
        if args.old is None or args.new is None:
            raise FormatError("Supply --bytecode, or both --old and --new")
        payload, indices = replace_string(script["payload"], args.old.encode("utf-8"), args.new.encode("utf-8"), args.string_index)
        replacement = wrap_rsb1(payload)
        print("Changed string-table indices:", ", ".join(map(str, indices)))
    parse_payload(payload)
    unused, verified_payload = unwrap_rsb1(replacement)
    if verified_payload != payload:
        raise FormatError("Replacement round-trip verification failed")
    modified = replace_blobs(binary, scripts, {script["name"]: replacement})
    verified_scripts = find_scripts(modified)
    verified = next((entry for entry in verified_scripts if entry["table_offset"] == script["table_offset"]), None)
    if verified is None or verified["blob"] != replacement or len(verified_scripts) != len(scripts):
        raise FormatError("Patched library failed table verification")
    if library:
        rebuild_apk(args.input, args.output, library, modified)
    else:
        with args.output.open("xb") as stream:
            stream.write(modified)
    print(f'Patched {args.script}: {script["blob_size"]} -> {len(replacement)} bytes in {args.output}')
    if library:
        print("APK is unsigned. Align and sign it before installing; runtime compatibility has not been tested.")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments:
        arguments = ["extract", "client.apk"]
    elif arguments[0] not in ("extract", "patch", "-h", "--help"):
        arguments.insert(0, "extract")
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    extract_parser = commands.add_parser("extract", help="Extract embedded bytecode and bundled source files")
    patch_parser = commands.add_parser("patch", help="Replace embedded bytecode or exact string-table entries")
    for command in (extract_parser, patch_parser):
        command.add_argument("input", type=Path, help="Legacy APK, ELF32 libroblox.so, or PE32 RobloxPlayerBeta.exe")
        command.add_argument("--library", help="APK library member when several ABIs exist")
    extract_parser.add_argument("-o", "--output", type=Path, default=Path("corescripts"))
    extract_parser.set_defaults(action=extract)
    patch_parser.add_argument("--script", required=True, help="Exact decoded script name from manifest")
    patch_parser.add_argument("--bytecode", type=Path, help="Client-compatible encrypted .rbxb replacement")
    patch_parser.add_argument("--old", help="Exact UTF-8 string-table value to replace")
    patch_parser.add_argument("--new", help="Replacement UTF-8 string-table value")
    patch_parser.add_argument("--string-index", type=int, help="Optional 1-based string-table index")
    patch_parser.add_argument("-o", "--output", type=Path, required=True)
    patch_parser.set_defaults(action=patch)
    args = parser.parse_args(arguments)
    try:
        args.action(args)
    except (FormatError, OSError, zipfile.BadZipFile, KeyError, struct.error) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
