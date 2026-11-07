"""Lossless payload serialization and legacy Lua 5.1 compiler verification."""

import struct
import tempfile
from pathlib import Path

import decode_corescripts as decoder
import extract_corescripts as extractor


ENCODE_KEY = pow(decoder.DECODE_KEY, -1, 1 << 32)


def encode_word(word, extra=False):
    if extra:
        return word * ENCODE_KEY & extractor.MASK32
    opcode_index = word & 63
    if opcode_index >= len(decoder.OPCODES):
        raise extractor.FormatError("Invalid stock Lua 5.1 opcode")
    opcode = decoder.OPCODES[opcode_index]
    arg_a = word >> 6 & 255
    if opcode in decoder.ABX_OPCODES | decoder.ASBX_OPCODES:
        secure = decoder.SECURE_OPCODES.index(opcode) << 26 | arg_a << 18 | word >> 14
    else:
        arg_b, arg_c = word >> 23 & 511, word >> 14 & 511
        secure = decoder.SECURE_OPCODES.index(opcode) << 26 | arg_a << 18 | arg_c << 9 | arg_b
    return secure * ENCODE_KEY & extractor.MASK32


def serialize_payload(parsed):
    output = bytearray(b"\0\0\0\0\0")
    strings = [bytes.fromhex(value) for value in parsed["strings_hex"]]

    def integer(value):
        output.extend(struct.pack("<I", value & extractor.MASK32))

    def prototype(current):
        for values in (current["children"], current["constants"], current["encoded_instructions"],
                       current["locals"], current["encoded_lineinfo"], current["upvalue_names"]):
            integer(len(values))
        output.extend(bytes(current[key] for key in ("stack_size", "vararg", "upvalue_count", "parameter_count")))
        for constant in current["constants"]:
            kind = constant["type"]
            output.append(("nil", "false", "true", "number", "string").index(kind))
            if kind == "number":
                output.extend(bytes.fromhex(constant["number_hex"]) if "number_hex" in constant
                              else struct.pack("<d", float(constant["value"])))
            elif kind == "string":
                integer(constant["string_index"])
        previous = 0
        for line in current["encoded_lineinfo"]:
            integer(line - previous)
            previous = line
        for local in current["locals"]:
            for key in ("start_pc", "end_pc", "string_index"):
                integer(local[key])
        for index in current["upvalue_names"]:
            integer(index)
        for word in current["encoded_instructions"]:
            integer(word)
        for child in current["children"]:
            prototype(child)

    prototype(parsed["root"])
    struct.pack_into("<I", output, 1, len(output) - 1)
    integer(len(strings))
    for value in strings:
        integer(len(value))
    output.extend(b"".join(strings))
    payload = bytes(output)
    extractor.parse_payload(payload)
    return payload


def parse_lua51(chunk):
    if len(chunk) < 12 or chunk[:8] != b"\x1bLua\x51\0\x01\x04" or chunk[9:12] != b"\x04\x08\0":
        raise extractor.FormatError("Require little-endian Lua 5.1 bytecode with 32-bit instructions and doubles")
    size_t = chunk[8]
    if size_t not in (4, 8):
        raise extractor.FormatError("Unsupported Lua 5.1 size_t width")
    reader = extractor.Reader(chunk, 12)
    strings = []
    indices = {}

    def string():
        length = reader.number("<Q" if size_t == 8 else "<I")
        if not length:
            return None
        value = reader.take(length)
        if value[-1:] != b"\0":
            raise extractor.FormatError("Lua string lacks its terminator")
        return value[:-1]

    def string_index(value):
        if value is None:
            return 0
        if value not in indices:
            strings.append(value)
            indices[value] = len(strings)
        return indices[value]

    def prototype(depth=0):
        if depth > 100:
            raise extractor.FormatError("Lua prototype nesting is too deep")
        string()
        reader.number("<I")
        reader.number("<I")
        upvalues, parameters, vararg, stack = reader.take(4)
        stock_words = [reader.number("<I") for unused in range(reader.count())]
        constants = []
        for unused in range(reader.count()):
            kind = reader.number("<B")
            if kind == 0:
                constant = {"type": "nil"}
            elif kind == 1:
                boolean = reader.number("<B")
                if boolean not in (0, 1):
                    raise extractor.FormatError("Invalid Lua boolean")
                constant = {"type": "true" if boolean else "false"}
            elif kind == 3:
                raw = reader.take(8)
                constant = {"type": "number", "value": struct.unpack("<d", raw)[0], "number_hex": raw.hex()}
            elif kind == 4:
                value = string()
                if value is None:
                    raise extractor.FormatError("Null Lua string constant")
                constant = {"type": "string", "string_index": string_index(value)}
            else:
                raise extractor.FormatError("Unknown Lua constant type")
            constants.append(constant)
        children = [prototype(depth + 1) for unused in range(reader.count())]
        lines = [reader.number("<I") ^ pc << 8 for pc in range(reader.count())]
        locals_data = []
        for unused in range(reader.count()):
            index = string_index(string())
            locals_data.append({"string_index": index, "start_pc": reader.number("<I"), "end_pc": reader.number("<I")})
        names = [string_index(string()) for unused in range(reader.count())]
        encoded = []
        extra = False
        for word in stock_words:
            encoded.append(encode_word(word, extra))
            extra = not extra and (word & 63) == decoder.OPCODES.index("SETLIST") and (word >> 14 & 511) == 0
        if extra:
            raise extractor.FormatError("Missing Lua SETLIST extra word")
        return {"stack_size": stack, "vararg": vararg, "upvalue_count": upvalues,
                "parameter_count": parameters, "constants": constants, "children": children,
                "encoded_instructions": encoded, "encoded_lineinfo": lines,
                "locals": locals_data, "upvalue_names": names}

    root = prototype()
    if reader.position != len(chunk):
        raise extractor.FormatError("Unexpected bytes after Lua chunk")
    parsed = {"root": root, "strings_hex": [value.hex() for value in strings],
              "strings": [value.decode("utf-8", "backslashreplace") for value in strings]}
    decoder.decode_prototype(root)
    return parsed


def compile_source(source, luac, timeout=60):
    with tempfile.TemporaryDirectory(prefix="corescript-compile-") as directory:
        output = Path(directory) / "script.luac"
        status, unused, errors = decoder.run_tool([luac, "-o", str(output), "--", str(source.resolve())], timeout)
        if status:
            raise extractor.FormatError("Lua 5.1 compilation failed for " + str(source) + ": " + errors.strip())
        chunk = output.read_bytes()
    return parse_lua51(chunk)


def constant_values(parsed, root):
    values = []
    for constant in root["constants"]:
        kind = constant["type"]
        value = None
        if kind == "string":
            value = parsed["strings_hex"][constant["string_index"] - 1] if constant["string_index"] else None
        elif kind == "number":
            value = constant.get("number_hex") or struct.pack("<d", float(constant["value"])).hex()
        values.append((kind, value))
    return values


def compare_prototypes(original, candidate):
    result = {"prototype_count": 0, "instruction_word_count": 0, "instruction_mismatches": 0,
              "constant_mismatches": 0, "structure_mismatches": 0, "debug_mismatches": 0, "examples": []}

    def example(value):
        if len(result["examples"]) < 20:
            result["examples"].append(value)

    def compare(left, right, path):
        result["prototype_count"] += 1
        left_decoded, right_decoded = decoder.decode_prototype(left), decoder.decode_prototype(right)
        left_code = left_decoded["instructions"]
        right_code = right_decoded["instructions"]
        result["instruction_word_count"] += len(left_code)
        for pc in range(max(len(left_code), len(right_code))):
            old = left_code[pc] if pc < len(left_code) else None
            new = right_code[pc] if pc < len(right_code) else None
            if old is None or new is None or old["word"] != new["word"]:
                result["instruction_mismatches"] += 1
                example({"prototype": path, "pc": pc, "original": old, "candidate": new})
        if constant_values(original, left) != constant_values(candidate, right):
            result["constant_mismatches"] += 1
        fields = ("stack_size", "vararg", "upvalue_count", "parameter_count")
        if any(left[key] != right[key] for key in fields) or len(left["children"]) != len(right["children"]):
            result["structure_mismatches"] += 1
        def debug_values(parsed, current):
            strings = parsed["strings_hex"]
            return (current["encoded_lineinfo"],
                    [(value["start_pc"], value["end_pc"], strings[value["string_index"] - 1] if value["string_index"] else None)
                     for value in current["locals"]],
                    [strings[index - 1] if index else None for index in current["upvalue_names"]])
        if debug_values(original, left) != debug_values(candidate, right):
            result["debug_mismatches"] += 1
        for index in range(max(len(left["children"]), len(right["children"]))):
            if index < len(left["children"]) and index < len(right["children"]):
                compare(left["children"][index], right["children"][index], path + "." + str(index))
            else:
                result["structure_mismatches"] += 1

    compare(original["root"], candidate["root"], "0")
    result["code_and_constants_equal"] = not any(result[key] for key in
                                                ("instruction_mismatches", "constant_mismatches", "structure_mismatches"))
    result["debug_equal"] = result["debug_mismatches"] == 0
    return result


def verify_roundtrip(script):
    parsed = script["parsed"]
    root = decoder.decode_prototype(parsed["root"])
    mismatches = []

    def verify(current, path):
        for instruction, raw in zip(current["instructions"], current["encoded_instructions"]):
            word = instruction["word"]
            if instruction["opcode"] == "MOVE":
                secure_c = (raw * decoder.DECODE_KEY & extractor.MASK32) >> 9 & 511
                word |= secure_c << 14
            if encode_word(word, instruction["opcode"] == "EXTRA") != raw:
                mismatches.append({"prototype": path, "pc": instruction["pc"]})
        for index, child in enumerate(current["children"]):
            verify(child, path + "." + str(index))

    verify(root, "0")
    serialized = serialize_payload(parsed)
    wrapped = extractor.wrap_rsb1(serialized)
    unused, unwrapped = extractor.unwrap_rsb1(wrapped)
    return {"instruction_roundtrip_equal": not mismatches, "instruction_mismatches": mismatches[:20],
            "payload_roundtrip_equal": serialized == script["payload"],
            "container_payload_equal": unwrapped == script["payload"],
            "recompressed_blob_equal": wrapped == script["blob"],
            "prototype_count": decoder.prototype_counts(root)[0],
            "instruction_word_count": decoder.prototype_counts(root)[1]}
