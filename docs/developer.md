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
required. Build types are `retail`, `jtag`, `glitch`, `glitch2`, `glitch2m`, `glitch3`, `devkit`
and `devgl`; `glitch1` and `gg` are aliases for `glitch`. Block types are `xsb` (small block),
`psb` (new small block), `bb` (big block), and `emmc`.

A devkit image is 64 MB, as xeBuild 1.21 builds it: `devkit:psb` or `devkit:xsb` gives the 64 MB
small-block shape with that spare layout, and `devkit:bb` the big-block shape with the larger
filesystem. A 16 MB donor gives such an image its nonces and console data only. For example, from
a directory holding the release `17489`, `common` and `data/xell-gggggg.bin`:

```text
gxbuild -b 17489/_devkit.ini -s jasper -t devkit:psb -d 17489 -d common -d . -i nanddump.bin -o out.bin
```

A devgl image keeps the console's own shape (`devgl:psb` on a 16 MB Jasper, `devgl:bb` on a big
block Jasper, `devgl:emmc` on a Corona 4 GB) and runs the development chain with the glitch2m
patches: the SD takes the CD section of `patches_g2m<section>.bin` and is then signed again with
the SB private key, the SB is zero-paired, and the fuses and KHV patches go to the second update
slot (0xE0000, or 0x100000 on big block); XeLL stays a FlashFS file. gxbuild3 never ships that
key: put `SB_priv.bin` (or `SB_prv.bin`) in a source root or a `keys` folder inside one. A file
of another size or CRC-32 is passed over, and without the key a devgl build is refused.

```text
gxbuild -b 17489/_devgl.ini -s jasper -t devgl:psb -d 17489 -d common -d . -i nanddump.bin -o out.bin
```

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

A `kv.bin` sealed under the CPU key is opened. One that does not open is taken as the console's
keyvault in the clear, with a warning, as xeBuild 1.21 takes it: 0x4000 bytes whose first 0x10
bytes are a stale nonce, or 0x3FF0 bytes without the nonce, which get sixteen zero bytes in
front. A `kv.bin` of any other length is refused.

The selected build INI is read with `[<section>bl]`. Assets, including user overrides, are looked
up through the source roots in order. Automatic patchsets and add-ons are searched only in
`GXBUILD3_KEYVAULT_DECRYPTED_FILE`, or pass three file paths directly:

```sh
./build/gxbuild3_keyvault_crypto_tests _temp/cpukey.txt _temp/KV_en.bin _temp/KV_dec.bin
```
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

Direct invocation fails on missing files. Keep all console-specific fixtures out of Git.

## Command-line build UI

`gxbuild` builds by default, so `build` is optional:

```text
gxbuild [build] -b <build.ini> -s <section> -t <buildtype>[:<blocktype>] -d <source-dir>
```
`<source-dir>/bin`. Automatic patch names use
`patches_<stem>[_<suffix>].bin`, where `-e <suffix>` supplies the optional suffix:

| Build type | Patch stem |
| --- | --- |
| `retail`, `devkit` | none |
| `jtag` | `fat` |
| `glitch` | section stem |
| `glitch2` | `g2<section>` |
| `glitch2m`, `devgl` | `g2m<section>` |
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
gxbuild3::utils::ScanOptions options{.nosu = false, .nosusecurity = true};
std::vector<std::filesystem::path> roots{"mydata", "17559", "common"};
auto paths = gxbuild3::utils::find_files({"cf_17559.bin", "dash.xex"}, roots, options);
auto files = gxbuild3::utils::read_ini_files(
    std::filesystem::path{"17559/_retail.ini"}, "jasper", roots, options);
```

Earlier directories always take priority, including their STFS contents over
loose files in later directories. Within one directory, loose files win over
STFS entries, which win over CF/CG parts split from `xboxupd.bin`. If several
extensionless `su*` packages exist in one directory, the lexicographically first
is selected. Equal-ranked filename aliases keep their first match.

Results contain one entry per lowercase basename. INI payload names are also
returned as lowercase basenames, while separate bootloader chain slots are
preserved. `find_files` returns the container path for STFS matches and throws
when a requested file cannot be located.

Both options default to `false`. `nosu` disables STFS discovery entirely.
`nosusecurity` skips extracting STFS security contents while leaving loose
security files eligible. Security names are `crl.bin`, `dae.bin`, `odd.bin`,




`extended.bin`, `fcrt.bin`, and `secdata.bin`, plus any names in the INI's
`[security]` section when using `read_ini_files`.

A name an INI states is looked up exactly first and then without regard to case, so
`sc_17489.bin` finds `SC_17489.bin`. A payload named outside its release
(`..\data\xell-gggggg.bin`) is looked for as a loose file under the rest of its
path in each root, then by its basename, and is skipped with a warning when no
root has it. `[rawpatch]` lines (`file,offset`) are written into the image as
they are, last; a file no root supplies is skipped with a warning.

The existing `read_ini_files(version, type, section, fw_dir, options)` convenience
overload searches `fw_dir` (or `mydata`), the version directory, then `common`.
Existing calls may omit the options argument.
## FlashFS layout and timestamps

A built FlashFS is laid as xeBuild 1.21 lays it. The CG tails (`sysupdate.xexpN`, in slot
order) come first, on the first block past the update slots and every payload after them
(block 0x24 on a 16 MB retail image, the filesystem's base on big block). The INI's
`[flashfs]` files follow in INI order, then its `[security]` files, then any of the
console's secured files the INI does not name, all back to back. The settings blobs and the
root follow the last file.

Every directory entry is stamped with the build's time plus two seconds, as a FAT date and
time on the build machine's local clock, as xeBuild stamps them: the zone `TZ` names when it is
set, the system's zone otherwise. The build's time is the clock, or `SOURCE_DATE_EPOCH`
(seconds since the Unix epoch) when it is set. A reproducible build pins both
`SOURCE_DATE_EPOCH` and `TZ` (for example `TZ=UTC0`); the same epoch in another zone gives other
directory stamps.

## All-zero CPU key

`-p 00000000000000000000000000000000` builds an image bound to no console, for a console whose
CPU key is unknown (J-Runner passes zeros for glitch2m). The key is accepted though it has no
ECC. The donor's keyvault does not open under it, so `decrypt_all` leaves the keyvault sealed,
`ExtractAll` returns no keyvault, and the build needs the console's keyvault as a `kv.bin` in the
clear; without one the resolver refuses the build. The donor still gives its nonces, its CF LDV
and the rest of its console data. As xeBuild 1.21 builds it:

- a chain with a CB_B is zero-paired: the CB_B per-box block (pairing, LDV and SMC digest) is
  zero and the CFs state no pairing;
- every CF states LDV 0 and its MAC is computed under the zero key;
- crl.bin, dae.bin and secdata.bin state LDV 0; the donor's copies do not open under the zero
  key, so crl.bin and dae.bin are the update package's sealed under drawn material, and
  extended.bin and secdata.bin are made up clean (secdata.bin under a drawn head);
- the virtual fuses state the zero CPU key and still the donor's CF LDV (xeBuild 1.21 writes the
  donor's LDV into fuse lines 7 and 8, not 0);
- the keyvault and every file under the CPU key are sealed under the zero key.

xeBuild 1.21 fills the values gxbuild3 draws here (crl.bin's vector and file key, dae.bin's head
and field, secdata.bin's head) and the keyvault's eight-byte head at 0x10 from constants compiled
into it, because it draws nothing when it walks a donor's chain; gxbuild3 draws them, and keeps
the `kv.bin`'s own head.

## Secured FlashFS files

`crl.bin`, `dae.bin`, `extended.bin` and `secdata.bin` are sealed for the console on every
build, as xeBuild 1.21 seals them (`src/nand/objects/SecuredFiles.cpp`). The content is the
file the build carries (an update package's crl/dae, or the donor's), opened in the clear or
under the CPU key, the retail XEX key or the all-zero development XEX key. The sealing comes
from the console's own copies, which `ExtractAll` keeps in `InputMetadata::console_secured_files`:
crl.bin's vector and file key, dae.bin's head and header field (from its first record), and
secdata.bin's head. extended.bin's head is the keyvault's. With no console copy that opens under
the CPU key, crl/dae sealing is drawn from the system's random source.

crl.bin, dae.bin and secdata.bin state the build's lockdown value (the CF LDV) and the build's
time as a big-endian FILETIME in UTC: the build time plus two seconds, down to the even second.
extended.bin and secdata.bin take the nonce their plaintext derives. A crl.bin or dae.bin that
opens under no key is written back as supplied with a warning.

A clean `extended.bin` or `secdata.bin` is made up, as xeBuild 1.21 makes one up ("Making up an
clean/empty extended.bin!"), for a copy that is not 0x4000 (extended.bin) or 0x400 (secdata.bin)
bytes long, for an extended.bin that opens under no key, for the console's own secdata.bin when it
does not open under the CPU key, and for an extended.bin or secdata.bin the INI's `[security]`
names and nothing supplies (the resolver carries it empty). A clean extended.bin is 0x4000 bytes
whose plaintext is zero but for the keyvault's eight-byte head; it is deterministic. A clean
secdata.bin is 0x400 bytes whose plaintext is zero but for the head at 0x00, 1 at 0x08, the CF
LDV at 0x09 and the stamp at 0x10. Its head is the console's own secdata.bin's when that opens
under the CPU key, and otherwise drawn from the system's random source (logged without the
value). A supplied secdata.bin of the right length that does not open, other than the console's
own copy, is written as it stands. The generators are `clean_extended` and `clean_secdata` in
`SecuredFiles`.

`fcrt.bin` is sealed when it is handed over in the clear: when the SHA-1 of its part from the
offset its header keeps at 0x11C (0x140 in every copy seen) is the 20 bytes at 0x12C, that part
is sealed under AES-128-CBC with the CPU key and the vector at 0x100, which makes the result
deterministic. A copy that is already sealed under the CPU key (it opens and its hash holds) is
carried byte for byte. A copy that is not 0x4000 bytes, whose header puts the sealed part past
0x3FFF, or that neither is in the clear nor opens under the CPU key is written as supplied with a
warning. xeBuild writes a copy that does not open as its failed decryption leaves it; gxbuild3
keeps it as supplied.

The FILETIME is UTC, so it does not depend on the zone. To reproduce a xeBuild reference image,
set `SOURCE_DATE_EPOCH` to its build time in UTC (the FILETIME inside its crl.bin, less two
seconds) and `TZ` to the zone it was built in (unset, the system's zone, for a reference built on
the same machine); the directory stamps and the secured files then match together.
