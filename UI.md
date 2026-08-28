Build Subcommand

## Input Categories:

### User Main
- NAND Image
- CPU Key

### User Files:
- SMC
- vFuses
- Mobiles
- Security
- Keyvault

### User Metadata:
- CF LDV
- CB LDV
- Pairing Data

### INI Main
- CB / CB_A
- CB_X
- CB_B
- CD
- CE
- CF0
- CG0
- CF1
- CG1

### INI Other
- Security
- FlashFS
- Patchset


## INI

Seperated into sections per motherboard in a format:

<motherboard>bl[+"_<EXTENSION>"]

common security and flashfs section for all motherboards


## Load Files

### Folders

- userdata
- firmware
- common

### Sequence

userdata from <userdata> arg
  fallback to cwd/mydata

firmware from <firmware> arg
  fail if none

common from cwd/common
  override with <common> arg

INI:
  <firmware>/"_<type>.ini"
    fail if none

User Main:
  <userdata>/nanddump.bin
    override with <image> arg
    fail if none

  <userdata>/cpukey.bin
    override with <cpukey> arg

User Other:
  <userdata>

Patchset:
  key = switch <type>:
    case retail return;
    case jtag:
      return fat;
    case glitch1/glitch/gg:
      return <motherboard>;
    case glitch2:
      return g2<motherboard>;
    case glitch2m:
      return g2m<motherboard>;
    case glitch3:
      return g3<motherboard>;
      fallback to g2<motherboard>;

  patchset = <firmware>/bin/patches_$key.bin

  none if retail

INI Main:
  1. <firmware>
  2. <common>

INI FlashFS:
  dirs:
  1. <firmware>
  2. <common>
  files:
  1. loose
  2. STFS

INI Security:
  Use NAND first (disable with nosecurity option)
  dirs:
  1. <userdata>
  2. <firmware>
  3. <common>
  files:
  1. loose
  2. STFS (disable with nosusecurity option)



xeBuild commands:

-f <firmware dir>
-d <userdata dir>
-t <type>
-c <motherboard>
-p <cpukey>