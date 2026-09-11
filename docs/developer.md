## Build

Install CMake 3.25+, Ninja, and a C/C++ toolchain with C++23 support, then run:

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

On every platform, fresh builds prefer `clang`/`clang++` and fall back to
`gcc`/`g++` if Clang is absent. Apple Clang is supported. MSVC and `clang-cl`
are rejected; use Ninja rather than a Visual Studio generator on Windows.
Clang's normal GNU-style driver can still use the Windows SDK/runtime.

Explicit `CMAKE_C_COMPILER`/`CMAKE_CXX_COMPILER`, `CC`/`CXX`, toolchain files,
and compilers already selected by a parent project or build cache are respected,
but must pass the same compiler checks. Use a new build directory (or
`cmake --fresh -S . -B build -G Ninja` for an existing Ninja build) to discard
cached compiler choices and apply the new defaults.

## Private keyvault crypto test

The keyvault test reads a CPU key text file (32 hexadecimal characters, with optional
surrounding whitespace), an encrypted keyvault, and an independently decrypted reference.
Both keyvault files must be exactly 16,384 bytes. It exercises `keyvault_decrypt` and
`Keyvault::decrypt`, comparing the complete result, including the 16-byte header.
Authentication failures and byte mismatches fail the test; it never generates its own
expected plaintext or prints CPU keys/keyvault contents.

Place private fixtures in the Git-ignored `_temp/` directory as `cpukey.txt`,
`KV_en.bin`, and `KV_dec.bin`, then run:

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build --target gxbuild3_keyvault_crypto_tests
ctest --test-dir build -R '^gxbuild3_keyvault_crypto_tests$' --output-on-failure
```

CTest skips this test when all three fixtures are absent. A partially installed fixture
set fails. Override the paths with the CMake cache variables
`GXBUILD3_KEYVAULT_CPU_KEY_FILE`, `GXBUILD3_KEYVAULT_ENCRYPTED_FILE`, and
`GXBUILD3_KEYVAULT_DECRYPTED_FILE`, or pass three file paths directly:

```sh
./build/gxbuild3_keyvault_crypto_tests _temp/cpukey.txt _temp/KV_en.bin _temp/KV_dec.bin
```

Direct invocation fails on missing files. Keep all console-specific fixtures out of Git.

## Command-line build UI

`gxbuild` builds by default, so `build` is optional:

```text
gxbuild [build] -b <build.ini> -s <section> -t <buildtype>[:<blocktype>] -d <source-dir>
```

`-b` selects the build INI, `-s` selects its motherboard section stem, `-t` selects the build
and (when necessary) image layout, and `-d` supplies one or more source roots. All four are
required. Build types are `retail`, `jtag`, `glitch`, `glitch2`, `glitch2m`, `glitch3`, and
`devkit`; `glitch1` and `gg` are aliases for `glitch`. Block types are `xsb` (small block),
`psb` (new small block), `bb` (big block), and `emmc`.

Repeat `-d`, `-c`, and `-a` as needed. A single `-d`, `-c`, or `-a` value may use comma or
semicolon separators; colon is never a list separator because it separates `buildtype` from
`blocktype`. This keeps Windows drive paths intact. Source roots keep their declared order:
earlier roots win over later roots for the same asset.

The resolver loads `<working-directory>/options.ini` first, then applies every `-c` item in its
command-line order; later repeated `-c` values override earlier ones. For donor metadata, the
effective precedence is `options.ini`, donor NAND, then CLI configuration. `-p` overrides CPU-key
discovery; without it gxbuild uses the first `cpukey.txt` found in the ordered roots and fails if
none is available. Similarly, `-i` overrides NAND discovery; otherwise gxbuild uses the first
`nanddump.bin`. Without a donor NAND, a complete loose donor is required: `kv.bin`, `smc.bin`,
`cbldv`, `cfldv`, and `pairing_data`, as well as an explicit block type.

The selected build INI is read with `[<section>bl]`. Assets, including user overrides, are looked
up through the source roots in order. Automatic patchsets and add-ons are searched only in
`<source-dir>/bin`. Automatic patch names use
`patches_<stem>[_<suffix>].bin`, where `-e <suffix>` supplies the optional suffix:

| Build type | Patch stem |
| --- | --- |
| `retail`, `devkit` | none |
| `jtag` | `fat` |
| `glitch` | section stem |
| `glitch2` | `g2<section>` |
| `glitch2m` | `g2m<section>` |
| `glitch3` | `g3<section>`, then `g2<section>` after every root lacks `g3` |

Each `-a <addon>` resolves as `<source-dir>/bin/<addon>.bin` and retains command-line order.

`-o` selects an output path; the default is `updflash.bin` in the current working directory, and
an existing output is overwritten. Exit codes are `0` for success/help/version, `2` for
command-line errors, `3` for input-resolution errors, `4` for NAND build errors, and `5` for
output-write errors. `-x` xeBuild compatibility mode is not implemented; it is rejected as an
unknown command-line argument.

## File lookup

`FileManager` accepts scan options and ordered search directories:

```cpp
FileManager::ScanOptions options{.nosu = false, .nosusecurity = true};
std::vector<std::filesystem::path> roots{"mydata", "17559", "common"};
auto paths = FileManager::FindFiles({"cf_17559.bin", "dash.xex"}, roots, options);
auto files = FileManager::ReadIniFiles(
    std::filesystem::path{"17559/_retail.ini"}, "jasper", roots, options);
```

Earlier directories always take priority, including their STFS contents over
loose files in later directories. Within one directory, loose files win over
STFS entries, which win over CF/CG parts split from `xboxupd.bin`. If several
extensionless `su*` packages exist in one directory, the lexicographically first
is selected. Equal-ranked filename aliases keep their first match.

Results contain one entry per lowercase basename. INI payload names are also
returned as lowercase basenames, while separate bootloader chain slots are
preserved. `FindFiles` returns the container path for STFS matches and throws
when a requested file cannot be located.

Both options default to `false`. `nosu` disables STFS discovery entirely.
`nosusecurity` skips extracting STFS security contents while leaving loose
security files eligible. Security names are `crl.bin`, `dae.bin`, `odd.bin`,
`extended.bin`, `fcrt.bin`, and `secdata.bin`, plus any names in the INI's
`[security]` section when using `ReadIniFiles`.

The existing `ReadIniFiles(version, type, section, fw_dir, options)` convenience
overload searches `fw_dir` (or `mydata`), the version directory, then `common`.
Existing calls may omit the options argument.