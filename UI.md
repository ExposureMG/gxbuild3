# gxbuild command-line UI

The only implemented command is the gxbuild build command. `build` is optional:

```text
gxbuild [build] -b <build.ini> -s <section> -t <buildtype>[:<blocktype>] -d <source-dir>
```

The required options are:

| Option | Meaning |
| --- | --- |
| `-b`, `--buildini` | Build INI path |
| `-s`, `--section` | Motherboard section stem; gxbuild reads `[<section>bl]` |
| `-t`, `--buildtype` | Build type, optionally followed by `:<blocktype>` |
| `-d`, `--dir` | Ordered source root or roots |

Build types are `retail`, `jtag`, `glitch`, `glitch2`, `glitch2m`, `glitch3`, and `devkit`.
`glitch1` and `gg` normalize to `glitch`. Block types are `xsb`, `psb`, `bb`, and `emmc` for
small-block, new-small-block, big-block, and eMMC images respectively.

## Lists and lookup order

`-d`, `-c`, and `-a` are repeatable. Each accepts a comma-separated or semicolon-separated list;
colon is reserved for `buildtype[:blocktype]` and is not a list separator. For example, a Windows
path such as `C:\\firmware` remains one source root. Source roots retain their command-line order:
the first root containing an asset wins.

`<working-directory>/options.ini` is the lowest configuration layer. Each `-c`, `--config` entry
is then applied in command-line order, so a later repeated `-c` value wins. Donor metadata sits
above `options.ini`, and CLI configuration overrides donor metadata.

CPU-key lookup is `-p`, `--cpukey` first, then the first `cpukey.txt` found in the ordered roots;
gxbuild fails when neither supplies a key. NAND lookup is `-i`, `--input` first, then the first
`nanddump.bin` in the ordered roots. Without a NAND donor, gxbuild requires a complete loose donor:
`kv.bin`, `smc.bin`, `cbldv`, `cfldv`, `pairing_data`, and an explicit block type.

## Patches and add-ons

Automatic patchsets and add-ons are searched as `<source-dir>/bin/<name>`. `-e`, `--ext` inserts
an optional suffix before `.bin` in automatic patchset names:

| Build type | Automatic patch stem |
| --- | --- |
| `retail`, `devkit` | none |
| `jtag` | `fat` |
| `glitch` | section stem |
| `glitch2` | `g2<section>` |
| `glitch2m` | `g2m<section>` |
| `glitch3` | `g3<section>`; after every root misses it, `g2<section>` |

The resulting filename is `patches_<stem>[_<suffix>].bin`. Each `-a`, `--addon <name>` resolves
as `<source-dir>/bin/<name>.bin`; repeated add-ons stay in command-line order. Retail and devkit
builds have no automatic patchset and do not accept add-ons.

## Other options and outcomes

`-o`, `--output` chooses the output file. Its default is `updflash.bin` in the current working
directory, and gxbuild overwrites an existing file. `-v`, `--verbose` enables verbose logging;
`-h`, `--help` and `--version` exit successfully without build arguments.

Exit codes are:

| Code | Meaning |
| --- | --- |
| `0` | Success, help, or version |
| `2` | Command-line error |
| `3` | Input-resolution error |
| `4` | NAND build error |
| `5` | Output-write error |

xeBuild compatibility mode (`-x`) is not implemented and is rejected as an unknown command-line
argument.
