# gxbuild3

Cross-Platform Xbox 360 Image Builder

## Licensing

gxbuild3 is brought to you under the GNU General Public License Version 2.0.

See [LICENSE](LICENSE) for more information.

## Build (CLI)

Requirements:

- CMake 3.29+
- C++23
- Clang, MSVC, or GCC
- Qt 6.12+

Linux, MacOS, Android (clang):

```sh
cmake -B build -S . -DCMAKE_CXX_COMPILER=clang++
cmake --build build
```

Linux (GCC):

```sh
cmake -B build -S . -DCMAKE_CXX_COMPILER=g++
cmake --build build
```

Windows (MSVC):

```sh
cmake -B build -S . -DCMAKE_CXX_COMPILER=cl
cmake --build build
```

## Credits

Big thanks to all contributors and all those who release their Xbox 360 projects FOSS.

### Developers

- **ExposureMG** - Bootloaders, Patching, UI, NAND Parsing / Building

- **erorn** - STFS, XConfig, and GxCrypt

### Dependencies and References

Have tried to include everyone here.

- **emoose** - ExCrypt, Filesystems, FlashBlockDriver and Keyvault (Via RGBuildPP)

- **InvoxiPlayGames** - Header Types (Via xenon-bltool)

- **[c0z]**, **Redline99**, **Ikari** - FreeBOOT Rebooter, Patches, and much more.

- **Visual Studio** - SMC and Keyvault Crypto, Shadowboots

- **Free60Project** - The best documentation on the Xbox 360 NAND