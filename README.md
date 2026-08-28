# gxbuild3

C++ 23 Cross-Platform Xbox 360 Image Builder, Patcher and Extractor

Available standalone or built-in to Genexis

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

## Credits
* ExposureMG - Bootloaders, Patchers, and NAND parsing / building
* erorn - Project Base, STFS, XConfig
---
**References**
* Free60Project - The best documentation on the Xbox 360 NAND
* XorLoser - The original XeCrypt
* [c0z] - Patching Format, Filetree format, INI format, CLI design; Basically the entire UX
* Visual Studio / GoobyCorp - SMC and Keyvault Crypto, Shadowboots
* emoose - Filesystems, FlashBlockDriver and Keyvault (Via RGBuildPP)
* InvoxiPlayGames - Header Types and Reversing of xeBuild patches (Via xenon-bltool and x360-research)
