# Legacy CoreScript extractor
hi this is vibecoded don't blame me so

### Verify and extract Windows scripts

```sh
python3 verify_corescripts.py windows/RobloxPlayerBeta.exe --compare-client client.apk -o analysis/windows_android_verification.json
python3 verify_corescripts.py windows/RobloxPlayerBeta.exe --sources decoded_lua/lua -o analysis/decompiled_recompile_verification.json
python3 extract_corescripts.py windows/RobloxPlayerBeta.exe -o windows_corescripts
```

The second command deliberately exits **1** when recompiled source differs;
it still writes the complete diagnostic report. Exit 0 means all requested
comparisons pass. Extraction needs an empty destination. The existing decoder
also accepts the executable directly:
`python3 decode_corescripts.py windows/RobloxPlayerBeta.exe -o windows_lua`.

### Apply a batch without recompiling unchanged scripts

`apply_client_patches.py` creates a **separate client directory**, keeps the
original untouched, and checks every original and replacement container and
instruction tree. Afterwards it re-extracts the modified executable, verifies
every selected blob, and proves all unselected blobs unchanged. Run a dry run
first:

```sh
python3 apply_client_patches.py windows --dry-run --content-from client.apk --report analysis/current_patches_dry_run.json
```

For reviewed source edits under `decoded_lua/lua/`, compare against an unedited
baseline; only changed files are selected. Source compilation requires an
explicit acknowledgement because stock Lua 5.1 and decompiler output are not
proven compatible with the original compiler:

```sh
python3 apply_client_patches.py windows --scripts decoded_lua/lua \
  --baseline decoded_lua/extracted.zip --allow-source-recompile \
  --content-from client.apk -o windows_patched --dry-run
```

Remove `--dry-run` to publish the copy. With the current unedited tree, this
copies the executable unchanged and populates content; it does not claim to
apply source modifications. `--luac /path/to/luac5.1` selects an external
compiler. The bundled compiler is a native Termux build; Windows users must
supply a Windows Lua **5.1**, not Lua 5.4 or Luau, compiler for source mode.
String/blob patch modes require only Python 3.9+ and the standard library.

Prefer explicit constant-only patches when appropriate: they preserve the
encoded instructions and prototype/debug layout. `client_patches.example.json`
is an **optional demonstration**, not an automatically applied patch set:

```sh
python3 apply_client_patches.py windows --patches client_patches.example.json --content-from client.apk -o windows_example --dry-run
```

Each JSON patch names an exact manifest `script` and specifies exactly one of:
`strings` (a list of exact `old`/`new` values and optional 1-based
`string_index`), `bytecode` (path to a client-compatible `.rbxb`), or `source`
(path to reviewed `.lua`, requiring `--allow-source-recompile`). File paths
are relative to the JSON manifest. Optional per-patch `expected_sha256` pins
the original blob; optional top-level `client_sha256` pins the executable.
These are SHA-256 values from the extraction/patch reports. The output
includes `patch-report.json` with original/replacement hashes, sizes, source
comparisons, content provenance, and warnings.

Replacements fitting their allocation are patched in place in the **copy**.
Larger Windows replacements are placed in a new read-only `.rbxcs` PE section;
the original table pointer's existing base relocation remains applicable.
The tool checks spare section-header space and relocation coverage, updates
section count, image/data sizes, and PE checksum, and refuses unsupported
layouts. It does not overwrite adjacent data or disable integrity checks.
The single-script `extract_corescripts.py patch` command supports this too.
ELF/APK replacements remain restricted to their existing allocations.

### Missing Windows content and runtime limits

`--content-from client.apk` copies only the nested OBB's **634 `content/`
files (9,734,036 bytes)**. It does not copy Android shaders or platform assets,
and preserves the supplied Windows `PlatformContent/`, shaders, DLLs, and
configuration. You can instead supply an OBB/ZIP or a local `content` directory.
Existing Windows content is never overwritten. **Android content is a reuse
candidate, not a verified complete Windows content distribution.**

Binary verification, dry runs, batch patching, oversized PE relocation,
checksums, corruption rejection, and content copying have been exercised
locally. The Windows client has **not been executed or runtime-tested** here.
Authenticode signatures become invalid after executable changes; VMProtect or
other integrity checks may reject modifications. No such checks are bypassed.

## Browser-port preparation

`web/index.html` previews the original OBB assets and provides a launch scaffold
for a **separately supplied, real Emscripten engine port**. Run
`python3 -m http.server 8000 --bind 127.0.0.1 --directory web` and open
<http://127.0.0.1:8000/>. The assets have been prepared with `prepare_web.py`.

**This is not a functional Roblox WASM conversion.** The APK's ARM Android
`libroblox.so` cannot be recompiled into WASM without engine source or a full
Android emulation environment. No placeholder engine WASM is included. See
`web/README.md` for exact binary findings, extraction instructions, and port
requirements.

## CoreScript extraction

`extract_corescripts.py` extracts the **actual embedded bytecode** from this
`client.apk`, unwraps its container, parses its prototypes and string tables,
and also copies the readable scripts bundled in the APK's nested OBB. It uses
Python 3's standard library only. The original APK is never modified.

**Readable Lua decompilation is now available through
`decode_corescripts.py`.** It decodes the embedded instruction words, converts
them to stock Lua 5.1 bytecode, and runs unluac. The 40 reconstructed Lua files
have already been generated under `decoded_lua/lua/`; they are not copied from
the OBB. See the next section.

## Decode instruction words into readable Lua

```sh
python3 decode_corescripts.py client.apk -o recovered_lua
```

You can also use the existing extraction as input, without reopening the APK:

```sh
python3 decode_corescripts.py corescripts -o recovered_lua
```

Choose an empty output directory. With no arguments, the decoder reads
`client.apk` and targets `decoded_lua/`, which is already populated here.

Decoder output:

- `lua/core/CoreScripts/*.lua`: reconstructed CoreScript source.
- `lua/core/Libraries/*.lua`: reconstructed library source.
- `lua/core/LoadingScript.lua` and starter scripts: reconstructed entry points.
- `lua/module/`: reconstructed core modules, including Settings pages.
- `bytecode/`: decoded, stock Lua 5.1 `.luac` chunks.
- `instructions/`: readable opcode/operand disassembly with decoded line data.
- `manifest.json`: counts, hashes, tool diagnostics, and validation results.

For this APK, instruction decoding consists of multiplication by **6700417
modulo 2^32**, reversing the engine's shuffled opcode numbers, and moving its
operand fields into standard Lua 5.1 positions. The decoder handles nested
prototypes, closure bindings, SETLIST extra words, constants, local/upvalue
names, and encoded line numbers. It does not apply the later 2016 DAX scheme
to this older client's instructions.

Results verified locally:

- **118,824 instruction words in 2,672 prototypes** decode and re-encode with
  no mismatches.
- All **40 exported bytecode chunks** pass the stock Lua 5.1 loader's checks.
- All **40 decompiled Lua files** pass Lua 5.1 syntax validation, with no
  unluac error diagnostics.
- Compiling the bundled source copies with stock Lua 5.1 gives matching
  prototype trees, code lengths, and constant tables across all 2,672
  prototypes. 118,423 instruction words match exactly; differences include
  stock tail-call generation and legacy vararg register allocation.
  Comparison details are retained in `analysis/bundled_source_comparison.json`
  and `analysis/compiler_differences.json`.

The output is reconstructed Lua, not the original source text: comments and
formatting cannot be recovered, and
some expressions may be structured differently. **Syntax checks do not prove
semantic equivalence or Roblox runtime compatibility.** The decoder never
uses the bundled Lua as a substitute for decompilation.

### Decompiler dependencies

The decoder uses the locally built `analysis/tools/unluac.jar` and Java;
OpenJDK 21 was installed with approval. It uses
`analysis/tools/lua-5.1.4/src/luac` for validation, not the system Lua 5.4
compiler. On Termux shared storage, non-executable native tools are staged
temporarily in the executable temporary directory and cleaned up afterward.

To use other tool locations:

```sh
python3 decode_corescripts.py client.apk -o recovered_lua \
  --decompiler /path/to/unluac.jar --java java --luac /path/to/luac5.1
```

`--no-decompile` exports bytecode and disassembly without Java. An explicit
LuaDec executable is also supported, but its reconstructions were unreliable
for this client; unluac is preferred. `--size-t 4` targets a 32-bit decompiler;
the default is 8 for the current 64-bit tools.

Tool sources were downloaded as pinned archives, not cloned:

- Lua 5.1.4: <https://www.lua.org/ftp/lua-5.1.4.tar.gz>.
- unluac: <https://github.com/viruscamp/unluac>, commit
  `9c59af46483a932a47224bf2ac84ad8a63094da5` (version `1.2.3.561`).
- LuaDec: <https://github.com/viruscamp/luadec>, commit
  `895d92313fabaee260121c758c8320d1b21dd741` (retained only as an alternative).

Extracted tool sources and their upstream license files are retained under
`analysis/tools/`. To rebuild the supplied tools with a C compiler and JDK:

```sh
make -C analysis/tools/lua-5.1.4/src generic CC=clang
mkdir -p analysis/tools/unluac-classes
find analysis/tools/unluac-source/src -name '*.java' > analysis/tools/java-sources.txt
javac -d analysis/tools/unluac-classes @analysis/tools/java-sources.txt
jar --create --file analysis/tools/unluac.jar --main-class unluac.Main \
  -C analysis/tools/unluac-classes .
```

## Findings for this APK

- ZIP timestamps indicate a July 24, 2015 build. The 2016 reference is useful,
  but does not by itself establish this APK's version or exact VM behavior.
- Engine library: `lib/armeabi/libroblox.so`, 20,051,408 bytes, ELF32 ARM.
- The engine contains **40 valid embedded scripts**: 25 CoreScript/library/
  starter entries and 15 module entries. Of the first 25, 19 are under
  `CoreScripts/`, three are libraries, and three are loading/starter scripts.
- The first table starts at library file offset `0x0120c8fc`; the module table
  starts at `0x0120ca28`. These are file offsets, not APK offsets or runtime
  addresses. Each entry is three little-endian 32-bit words:
  `{name_pointer, bytecode_pointer, bytecode_size}`.
- Names are ROT13 encoded, e.g. `PberFpevcgf/Gbcone` means `CoreScripts/Topbar`.
- Each blob uses RSB1: recover a four-byte XOR key using the known magic,
  undo XOR with `(key[position % 4] + position * 41) & 255`, verify XXH32
  with seed 42, then decompress the raw LZ4 block following its 8-byte header.
- The resulting payload is a Roblox-specific serialized Lua prototype tree
  with a shared string table. **Its instruction words are still VM encoded.**
  It is not a stock `luac` chunk and is not a Lua source decompilation.
- `assets/main.1.com.roblox.client.obb` is itself a ZIP containing 41 readable
  `.lua` files and two `.rbxmx` models. These are bundled source copies, not
  decompiled output; source-to-bytecode equivalence has not been established.

## Extract

```sh
python3 extract_corescripts.py client.apk
```

With no arguments, the same command defaults to `client.apk`. Use `-o another`
to choose a different, empty output directory. Direct ELF32 `libroblox.so`
and PE32 `RobloxPlayerBeta.exe` input also work. If an APK contains multiple libraries, select its ZIP member
using `--library lib/armeabi/libroblox.so`.

Output in `corescripts/`:

- `manifest.json`: script names, categories, offsets, sizes, hashes, and paths.
- `embedded/core/` and `embedded/module/`: one set of files per script.
- `*.rbxb`: original encrypted, compressed bytes suitable for same-client
  bytecode replacement.
- `*.rsb`: decrypted `RSB1` header plus the compressed LZ4 block.
- `*.payload`: fully decompressed serialized prototype data.
- `*.json`: string values, exact string bytes in hex, constants, debug data,
  prototype trees, and **encoded** instruction words.
- `sources/content/scripts/`: readable bundled Lua; additional files are
  extracted under `sources/content/fonts/`.

Existing nonempty extraction directories are rejected to prevent overwrites.

## Change embedded scripts

The reference client's `CoreScript::fetchSource` uses embedded bytecode when
`LuaVM::canCompileScripts()` is false. Its client VM disables source compilation
and reads the generated CoreScript/module tables. The matching embedded tables
in this APK make **binary bytecode replacement** the practical path to test;
merely editing OBB Lua should not be assumed to change executed CoreScripts.

### Change a string without recompiling Lua

```sh
python3 extract_corescripts.py patch client.apk \
  --script LoadingScript --old 'Loading...' --new 'Custom...' \
  -o client.modified-unsigned.apk
```

This replaces an exact string-table entry, rebuilds its string lengths,
recompresses the payload, regenerates its XXH32/XOR wrapper, overwrites only
the original blob's allocated bytes, and updates that table entry's size.
Prototype layout and encoded instructions are preserved.

Inspect the extracted JSON first. Optional `--string-index 163` restricts the
replacement to a 1-based table index (the loading text is index 163 in this
APK). String entries can be shared by several constants or debug names, so
changing an entry changes **all references to that entry**.

For ELF/APK input the replacement must fit the original blob size. The script
refuses larger blobs rather than overwriting adjacent binary data; PE32 input
supports the checked section relocation described above. Recompression alone can
change size, so even an equal-length edit is not guaranteed to fit. The
dependency-free compressor fits 33 of the 40 original allocations when
recompressing their unchanged payloads; the loading-text example fits.

### Replace an entire compiled script

```sh
python3 extract_corescripts.py patch client.apk \
  --script CoreScripts/Topbar --bytecode replacement.rbxb \
  -o client.modified-unsigned.apk
```

The replacement must already use this client's RSB1 payload/VM conventions.
Wrapper integrity and prototype structure are checked, **not instruction
semantics**. A normal `.lua` file, stock Lua 5.1/5.4 bytecode, modern Luau
bytecode, or bytecode from another client version is not a safe substitute.
Arbitrary Lua-source edits require a compatible compiler and instruction
encoder. `legacy_bytecode.py` implements stock Lua 5.1 import, legacy instruction
encoding, payload serialization, and independent comparisons. Use
`apply_client_patches.py` for the explicitly opt-in source pipeline described
above; the single-script extractor still expects an already encoded `.rbxb`.

## Installation and verification limits

APK rebuilding removes obsolete JAR signatures and produces an **unsigned**
APK. Align and sign the result with Android SDK tools before installing it.
No signing key or Android SDK signing tools are included. Using a different
signing identity may prevent upgrading an existing installation. Binary
integrity checks and server/client incompatibilities may also prevent a
modified client from running. Do not rely on an old client for sensitive use.

Validation performed locally:

- All 40 blobs pass XXH32 verification, LZ4 decompression, and complete
  prototype/string-table parsing.
- Python XXH32 and LZ4 implementations were checked against installed native
  libraries using synthetic inputs and all 40 real blobs.
- The loading-text replacement was rebuilt into a temporary APK, extracted
  again, and checked to preserve every other script and non-signature member.
- Corrupted and oversized ELF/APK replacements are rejected, and the input APK hash
  remains unchanged.

**A patched APK has not been installed or runtime-tested.**

## Reference used without cloning

Only individual source files were fetched from
<https://github.com/Artifaqt/ROBLOX2016>; no repository was cloned. Relevant
downloaded files are retained under `analysis/reference/`:

- `App/script/CoreScript.cpp`: source-versus-bytecode selection.
- `App/script/LuaVMClient.cpp`: disabled compiler and generated table lookup.
- `App/script/LuaSerializer.inl`: RSB1 wrapping and prototype serialization.
- `CoreScriptConverter2/cscmain.cpp`: ROT13 table generation and module naming.
- `App/include/script/LuaVM.h`: secure instruction/line conventions.

The tool discovers entries from ELF/PE tables rather than hardcoding offsets.
It intentionally supports legacy little-endian ELF32 and x86 PE32 RSB1 clients,
not PE32+ or modern Roblox formats.
