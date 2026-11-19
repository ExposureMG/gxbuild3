#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::NAND {

#pragma pack(push, 1)

typedef struct _KV_CONTROLLER_DATA {
    uint32_t dwKey1Idx;
    uint32_t dwKey2Idx;
    uint8_t dwKey1Data[0x10];
    uint8_t dwKey2Data[0x10];
} KV_CONTROLLER_DATA, *PKV_CONTROLLER_DATA;

typedef struct _CONSOLE_PUBLIC_KEY {
    uint32_t PublicExponent;
    uint8_t Modulus[0x80];
} CONSOLE_PUBLIC_KEY, *PCONSOLE_PUBLIC_KEY;

typedef struct _XE_CONSOLE_CERTIFICATE {
    uint16_t CertSize;
    uint8_t ConsoleId[0x5];
    char ConsolePartNumber[0xB];
    uint8_t Reserved[0x4];
    uint16_t Privileges;
    uint32_t ConsoleType;
    char ManufacturingDate[8];
    CONSOLE_PUBLIC_KEY ConsolePublicKey;
    uint8_t Signature[0x100];
} XE_CONSOLE_CERTIFICATE, *PXE_CONSOLE_CERTIFICATE;

typedef struct _XE_KEYVAULT_DATA {
    uint8_t bKeyVaultNonce[0x10];
    uint8_t bKeyVaultPairData[0x8];
    uint8_t b0ManufacturingMode;
    uint8_t b1AlternativeKeyVault;
    uint8_t b2RestrictedPrivilegesFlags;
    uint8_t b3ReservedByte3;
    uint16_t w4OddFeatures;
    uint16_t w5OddAuthType;
    uint32_t dw6RestrictedHvExtLoader;
    uint32_t dw7PolicyFlashSize;
    uint32_t dw8PolicyBuiltInUsbMuSize;
    uint32_t dw9ReservedDword4;
    uint64_t qwARestrictedPrivileges;
    uint64_t qwBReservedQword2;
    uint64_t qwCReservedQword3;
    uint64_t qwDReservedQword4;
    uint8_t bEReservedKey1[0x10];
    uint8_t bFReservedKey2[0x10];
    uint8_t b10ReservedKey3[0x10];
    uint8_t b11ReservedKey4[0x10];
    uint8_t b12ReservedRandomKey1[0x10];
    uint8_t b13ReservedRandomKey2[0x10];
    char sz14ConsoleSerialNumber[0xC];
    uint32_t dw14Padding;
    uint8_t b15MoboSerialNumber[0x8];
    uint16_t w16GameRegion;
    uint8_t b16Padding[6];
    uint8_t b17ConsoleObfuscationKey[0x10];
    uint8_t b18KeyObfuscationKey[0x10];
    uint8_t b19RoamableObfuscationKey[0x10];
    uint8_t b1ADvdKey[0x10];
    uint8_t b1BPrimaryActivationKey[0x18];
    uint8_t b1CSecondaryActivationKey[0x10];
    uint8_t b1DGlobalDevice2DesKey1[0x10];
    uint8_t b1EGlobalDevice2DesKey2[0x10];
    uint8_t b1FWirelessControllerMS2DesKey1[0x10];
    uint8_t b20WirelessControllerMS2DesKey2[0x10];
    uint8_t b21WiredWebcamMS2DesKey1[0x10];
    uint8_t b22WiredWebcamMS2DesKey2[0x10];
    uint8_t b23WiredControllerMS2DesKey1[0x10];
    uint8_t b24WiredControllerMS2DesKey2[0x10];
    uint8_t b25MemoryUnitMS2DesKey1[0x10];
    uint8_t b26MemoryUnitMS2DesKey2[0x10];
    uint8_t b27OtherXSM3DeviceMS2DesKey1[0x10];
    uint8_t b28OtherXSM3DeviceMS2DesKey2[0x10];
    uint8_t b29WirelessController3P2DesKey1[0x10];
    uint8_t b2AWirelessController3P2DesKey2[0x10];
    uint8_t b2BWiredWebcam3P2DesKey1[0x10];
    uint8_t b2CWiredWebcam3P2DesKey2[0x10];
    uint8_t b2DWiredController3P2DesKey1[0x10];
    uint8_t b2EWiredController3P2DesKey2[0x10];
    uint8_t b2FMemoryUnit3P2DesKey1[0x10];
    uint8_t b30MemoryUnit3P2DesKey2[0x10];
    uint8_t b31OtherXSM3Device3P2DesKey1[0x10];
    uint8_t b32OtherXSM3Device3P2DesKey2[0x10];
    uint8_t b33ConsolePrivateKey[0x1D0];
    uint8_t b34XeikaPrivateKey[0x390];
    uint8_t b35CardeaPrivateKey[0x1D0];
    XE_CONSOLE_CERTIFICATE b36ConsoleCertificate;
    uint8_t b37XeikaCertificate[0x142];
    uint8_t b37Padding[0x1146];
    uint8_t b39SpecialKeyVaultSignature[0x100];
    uint8_t b38CardeaCertificate[0x2108];
} XE_KEYVAULT_DATA, *PXE_KEYVAULT_DATA;

typedef struct _XE_FCRT_DATA {
    uint8_t bSignature[0x100];
    uint8_t bAesIv[0x10];
    uint32_t dwUnknown;
    uint32_t dwUnknown2;
    uint32_t dwDataLength;
    uint32_t dwDataOffset;
    uint8_t bUnknown[0xC];
    uint8_t bDigest[0x14];
    uint8_t bData[0x3ec0];
} XE_FCRT_DATA, *PXE_FCRT_DATA;

typedef struct _XE_CERTIFICATE_REVOCATION_DATA {
    uint32_t dwLength;
    uint32_t dwVersion;
    uint32_t dwCount;
    uint8_t bRevokedDigests[0x884];
} XE_CERTIFICATE_REVOCATION_DATA, *PXE_CERTIFICATE_REVOCATION_DATA;

typedef struct _XE_CERTIFICATE_REVOCATION_BOX_DATA {
    uint8_t bFileTimestamp[0x8];
    uint8_t bUnknown[0x7];
    uint8_t bLockDownValue;
} XE_CERTIFICATE_REVOCATION_BOX_DATA, *PXE_CERTIFICATE_REVOCATION_BOX_DATA;

typedef struct _XE_CRL_DATA {
    uint32_t dwMagic;
    uint8_t bConsoleId[0x5];
    uint8_t bPadding[0x3];
    uint8_t bDigest[0x14];
    uint8_t bSignature[0x100];
    uint8_t bAesNonce[0x10];
    uint8_t bAesKey1[0x10];
    XE_CERTIFICATE_REVOCATION_BOX_DATA xeBoxData;
    XE_CERTIFICATE_REVOCATION_DATA xeData;
} XE_CRL_DATA, *PXE_CRL_DATA;

typedef struct _XE_SEC_DATA {
    uint8_t bPairingData[0x3];
    uint8_t bPadding[0x3];
    uint8_t bSecurityInitialised;
    uint8_t bLockDownValue;
    uint8_t bFileTimestamp[0x8];
    uint8_t bDetectedViolations;
    uint64_t qwSecurityActivated;
    uint64_t qwDvdDisconnectedCount;
    uint64_t qwLockSystemUpdateCount;
    uint8_t WhateverMan[0x4000];
} XE_SEC_DATA, *PXE_SEC_DATA;

typedef struct _XE_EXTENDED_KV_DATA {
    uint8_t WhateverMan[0x4000];
} XE_EXTENDED_KV_DATA, *PXE_EXTENDED_KV_DATA;

typedef struct _XE_DAE_DATA {
    uint8_t WhateverMan[0x4000];
} XE_DAE_DATA, *PXE_DAE_DATA;

#pragma pack(pop)

class CXeKeyVault {
  public:
    XE_KEYVAULT_DATA xeData;
    uint8_t* pbCPUKey;
    uint8_t bRc4Key[0x10];
    uint8_t* pbHmacShaNonce;
    uint16_t* pwKeyVaultVersion;
    bool bIsDecrypted;

    [[nodiscard]] int RandomizeKeys();
    [[nodiscard]] int RepairDesKeys();
    [[nodiscard]] int Crypt(bool isDecrypting);
    [[nodiscard]] int Load(bool isEncrypted);
    [[nodiscard]] int Save(bool saveEncrypted);
    [[nodiscard]] int CalculateNonce(uint8_t* pbNonceBuff, uint32_t cbNonceBuff);
    CXeKeyVault() {
        pbCPUKey = nullptr;
        pbHmacShaNonce = nullptr;
    };
};

class CXeFlashSecuredFiles {
  public:
    XE_FCRT_DATA xeFcrtData;
    XE_SEC_DATA xeSecData;
    XE_EXTENDED_KV_DATA xeExtKVData;
    XE_DAE_DATA xeDaeData;
    XE_CRL_DATA xeCrlData;
    uint8_t* pbCPUKey;
};

enum class CpuKeyStatus {
    Valid,
    Corrected,
    Invalid
};

struct CpuKeyResult {
    CpuKeyStatus status = CpuKeyStatus::Invalid;
    std::vector<uint8_t> key;
    std::string message;
};

CpuKeyResult validate_cpu_key(std::span<const uint8_t> cpu_key);
CpuKeyResult validate_cpu_key_hex(std::string_view hex);

bool cpukey_valid(std::span<const uint8_t> cpu_key);
void ExCryptRandom(uint8_t* dest, size_t size);
bool crypt_secfile(std::span<const uint8_t> cpu_key, std::span<uint8_t> data);

struct Keyvault {
    static constexpr size_t kSize = 0x4000;

    XE_KEYVAULT_DATA data{};
    bool encrypted{true};
    std::vector<uint8_t> raw_data;

    static std::optional<Keyvault> parse(std::span<const uint8_t> bytes);
    static std::optional<Keyvault> parse(const std::vector<uint8_t>& bytes);

    bool is_encrypted(std::span<const uint8_t> cpu_key) const;
    bool decrypt(std::span<const uint8_t> cpu_key);
    bool encrypt(std::span<const uint8_t> cpu_key);
    bool verify(std::span<const uint8_t> cpu_key, std::span<const uint8_t> pub_key) const;
    [[nodiscard]] std::vector<uint8_t> serialize() const;
};

std::vector<uint8_t> keyvault_decrypt(std::span<const uint8_t> cpu_key,
                                      std::span<const uint8_t> data,
                                      uint16_t kv_version = 0x0712);
std::vector<uint8_t> keyvault_encrypt(std::span<const uint8_t> cpu_key,
                                      std::span<const uint8_t> data,
                                      uint16_t kv_version = 0x0712);
bool keyvault_verify(std::span<const uint8_t> cpu_key, std::span<const uint8_t> data,
                     std::span<const uint8_t> pub_key);

} // namespace gxbuild3::NAND

using gxbuild3::NAND::CpuKeyStatus;
using gxbuild3::NAND::CpuKeyResult;
using gxbuild3::NAND::validate_cpu_key;
using gxbuild3::NAND::validate_cpu_key_hex;
using gxbuild3::NAND::Keyvault;
using gxbuild3::NAND::keyvault_decrypt;
using gxbuild3::NAND::keyvault_encrypt;
using gxbuild3::NAND::keyvault_verify;
