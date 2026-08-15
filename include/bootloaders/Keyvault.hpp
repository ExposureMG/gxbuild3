#pragma once

#include <cstdint>
#include <vector>

#pragma pack(push, 1)

typedef struct _KV_CONTROLLER_DATA {
    uint32_t dwKey1Idx;
    uint32_t dwKey2Idx;
    uint8_t dwKey1Data[0x10];
    uint8_t dwKey2Data[0x10];
} KV_CONTROLLER_DATA, *PKV_CONTROLLER_DATA;

typedef struct _CONSOLE_PUBLIC_KEY {
    uint32_t PublicExponent;                // 0x00-0x04
    uint8_t Modulus[0x80];                  // 0x04-0x84
} CONSOLE_PUBLIC_KEY, *PCONSOLE_PUBLIC_KEY; // 0x84

typedef struct _XE_CONSOLE_CERTIFICATE {
    uint16_t CertSize;           // 0x00-0x02
    uint8_t ConsoleId[0x5];      // 0x02-0x07
    char ConsolePartNumber[0xB]; // 0x07-0x12
    uint8_t Reserved[0x4];       // 0x12-0x16
    uint16_t Privileges;         // 0x16-0x18
    uint32_t ConsoleType;        // 0x18-0x1C
    // unsigned int       ManufacturingDate[2];         // 0x1C-0x24
    char ManufacturingDate[8];
    CONSOLE_PUBLIC_KEY ConsolePublicKey;            // 0x24-0xA8
    uint8_t Signature[0x100];                       // 0xA8-0x1A8
} XE_CONSOLE_CERTIFICATE, *PXE_CONSOLE_CERTIFICATE; // 0x1A8

typedef struct _XE_KEYVAULT_DATA {
    uint8_t bKeyVaultNonce[0x10]; // 0x0
    uint8_t
        bKeyVaultPairData[0x8]; // 0x10 - not sure what this really is, seems to be first 8 bytes of
                                // bootloader/secured hmacsha-rc4 file nonces which on stock are all
                                // equal to each other and have the pairing data from CB as first 3
                                // bytes (observed on stock trinity nand) could just be random data,
                                // and MS got lazy with randomizing stuff on newer models?

    uint8_t b0ManufacturingMode;                   // 0x18
    uint8_t b1AlternativeKeyVault;                 // 0x19
    uint8_t b2RestrictedPrivilegesFlags;           // 0x1A
    uint8_t b3ReservedByte3;                       // 0x1B
    uint16_t w4OddFeatures;                        // 0x1C
    uint16_t w5OddAuthType;                        // 0x1E
    uint32_t dw6RestrictedHvExtLoader;             // 0x20
    uint32_t dw7PolicyFlashSize;                   // 0x24
    uint32_t dw8PolicyBuiltInUsbMuSize;            // 0x28
    uint32_t dw9ReservedDword4;                    // 0x2C
    uint64_t qwARestrictedPrivileges;              // 0x30
    uint64_t qwBReservedQword2;                    // 0x38
    uint64_t qwCReservedQword3;                    // 0x40
    uint64_t qwDReservedQword4;                    // 0x48
    uint8_t bEReservedKey1[0x10];                  // 0x50
    uint8_t bFReservedKey2[0x10];                  // 0x60
    uint8_t b10ReservedKey3[0x10];                 // 0x70
    uint8_t b11ReservedKey4[0x10];                 // 0x80
    uint8_t b12ReservedRandomKey1[0x10];           // 0x90
    uint8_t b13ReservedRandomKey2[0x10];           // 0xA0
    char sz14ConsoleSerialNumber[0xC];             // 0xB0
    uint32_t dw14Padding;                          // 0xBC
    uint8_t b15MoboSerialNumber[0x8];              // 0xC0
    uint16_t w16GameRegion;                        // 0xC8
    uint8_t b16Padding[6];                         // 0xCA
    uint8_t b17ConsoleObfuscationKey[0x10];        // 0xD0
    uint8_t b18KeyObfuscationKey[0x10];            // 0xE0
    uint8_t b19RoamableObfuscationKey[0x10];       // 0xF0
    uint8_t b1ADvdKey[0x10];                       // 0x100
    uint8_t b1BPrimaryActivationKey[0x18];         // 0x110
    uint8_t b1CSecondaryActivationKey[0x10];       // 0x128
    uint8_t b1DGlobalDevice2DesKey1[0x10];         // 0x138
    uint8_t b1EGlobalDevice2DesKey2[0x10];         // 0x148
    uint8_t b1FWirelessControllerMS2DesKey1[0x10]; // 0x158
    uint8_t b20WirelessControllerMS2DesKey2[0x10]; // 0x168
    uint8_t b21WiredWebcamMS2DesKey1[0x10];        // 0x178
    uint8_t b22WiredWebcamMS2DesKey2[0x10];        // 0x188
    uint8_t b23WiredControllerMS2DesKey1[0x10];    // 0x198
    uint8_t b24WiredControllerMS2DesKey2[0x10];    // 0x1A8
    uint8_t b25MemoryUnitMS2DesKey1[0x10];         // 0x1B8
    uint8_t b26MemoryUnitMS2DesKey2[0x10];         // 0x1C8
    uint8_t b27OtherXSM3DeviceMS2DesKey1[0x10];    // 0x1D8
    uint8_t b28OtherXSM3DeviceMS2DesKey2[0x10];    // 0x1E8
    uint8_t b29WirelessController3P2DesKey1[0x10]; // 0x1F8
    uint8_t b2AWirelessController3P2DesKey2[0x10]; // 0x208
    uint8_t b2BWiredWebcam3P2DesKey1[0x10];        // 0x218
    uint8_t b2CWiredWebcam3P2DesKey2[0x10];        // 0x228
    uint8_t b2DWiredController3P2DesKey1[0x10];    // 0x238
    uint8_t b2EWiredController3P2DesKey2[0x10];    // 0x248
    uint8_t b2FMemoryUnit3P2DesKey1[0x10];         // 0x258
    uint8_t b30MemoryUnit3P2DesKey2[0x10];         // 0x268
    uint8_t b31OtherXSM3Device3P2DesKey1[0x10];    // 0x278
    uint8_t b32OtherXSM3Device3P2DesKey2[0x10];    // 0x288
    uint8_t b33ConsolePrivateKey[0x1D0];           // 0x298
    uint8_t b34XeikaPrivateKey[0x390];             // 0x468
    uint8_t b35CardeaPrivateKey[0x1D0];            // 0x7F8
    XE_CONSOLE_CERTIFICATE b36ConsoleCertificate;  // 0x9C8
    uint8_t b37XeikaCertificate[0x142];            // 0xB72
    uint8_t b37Padding[0x1146];                    // 0xCB2
    uint8_t b39SpecialKeyVaultSignature[0x100];    // 0x1DF8
    uint8_t b38CardeaCertificate[0x2108];          // 0x1EF8
} XE_KEYVAULT_DATA, *PXE_KEYVAULT_DATA;

typedef struct _XE_FCRT_DATA {
    uint8_t bSignature[0x100];
    // signature is made from hmac sha of next 0x40 bytes
    uint8_t bAesIv[0x10];
    uint32_t dwUnknown;    // this & 0x7ffffffe must be 0
    uint32_t dwUnknown2;   // must be 1
    uint32_t dwDataLength; // can't be 0 or higher than 0x3ec0
    uint32_t dwDataOffset; // must be higher than 0x140
    uint8_t bUnknown[0xC];
    uint8_t bDigest[0x14];
    uint8_t bData[0x3ec0];
} XE_FCRT_DATA, *PXE_FCRT_DATA;

typedef struct _XE_CERTIFICATE_REVOCATION_DATA {
    uint32_t dwLength;
    uint32_t dwVersion;
    uint32_t dwCount;
    uint8_t bRevokedDigests[0x884]; // each 0x14 is another entry, digest is sha1 of console
                                    // security cert?
} XE_CERTIFICATE_REVOCATION_DATA, *PXE_CERTIFICATE_REVOCATION_DATA;

typedef struct _XE_CERTIFICATE_REVOCATION_BOX_DATA {
    uint8_t bFileTimestamp[0x8]; // should match crl.bin timestamp/meta in nand
    uint8_t bUnknown[0x7];
    uint8_t bLockDownValue;
} XE_CERTIFICATE_REVOCATION_BOX_DATA, *PXE_CERTIFICATE_REVOCATION_BOX_DATA;

typedef struct _XE_CRL_DATA {
    uint32_t dwMagic; // CRLP / CRLL
    uint8_t bConsoleId[0x5];
    uint8_t bPadding[0x3];
    uint8_t bDigest[0x14];
    uint8_t bSignature[0x100]; // CRLP = XEKEY_CONSTANT_PIRS_KEY, CRLL = XEKEY_CONSTANT_LIVE_KEY
    uint8_t bAesNonce[0x10];
    uint8_t bAesKey1[0x10]; // decrypt using AesEcb with CPU key
    // decrypt following with AesCbc using bAesNonce
    XE_CERTIFICATE_REVOCATION_BOX_DATA xeBoxData;
    // decrypt with AesCbc and updated IV? TODO: check this shit out
    XE_CERTIFICATE_REVOCATION_DATA xeData;
} XE_CRL_DATA, *PXE_CRL_DATA;

typedef struct _XE_SEC_DATA {
    uint8_t bPairingData[0x3];
    uint8_t bPadding[0x3];
    uint8_t bSecurityInitialised;
    uint8_t bLockDownValue;
    uint8_t bFileTimestamp[0x8]; // should match crl.bin timestamp/meta in nand
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
    uint16_t* pwKeyVaultVersion; // pointer to KeyVaultVersion field in flash header
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

#include <span>

bool cpukey_valid(const std::vector<uint8_t>& cpu_key);
void ExCryptRandom(uint8_t* dest, size_t size);
bool crypt_secfile(std::span<const uint8_t> cpu_key, std::span<uint8_t> data);
bool keyvault_is_encrypted(const std::vector<uint8_t>& cpu_key, const std::vector<uint8_t>& data,
                           uint16_t kv_version = 0x0712);
std::vector<uint8_t> keyvault_decrypt(const std::vector<uint8_t>& cpu_key,
                                      const std::vector<uint8_t>& data,
                                      uint16_t kv_version = 0x0712);
std::vector<uint8_t> keyvault_encrypt(const std::vector<uint8_t>& cpu_key,
                                      const std::vector<uint8_t>& data,
                                      uint16_t kv_version = 0x0712);
bool keyvault_verify(const std::vector<uint8_t>& cpu_key, const std::vector<uint8_t>& data,
                     const std::vector<uint8_t>& pub_key);
