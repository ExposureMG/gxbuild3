#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"
#include "core/Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild::nand {

    struct CONSOLE_PUBLIC_KEY {
        wire::be32 PublicExponent;
        uint8_t Modulus[0x80];
    };

    struct XE_CONSOLE_CERTIFICATE {
        wire::be16 CertSize;
        uint8_t ConsoleId[0x5];
        char ConsolePartNumber[0xB];
        uint8_t Reserved[0x4];
        wire::be16 Privileges;
        wire::be32 ConsoleType;
        char ManufacturingDate[8];
        CONSOLE_PUBLIC_KEY ConsolePublicKey;
        uint8_t Signature[0x100];
    };

    struct XE_KEYVAULT_DATA {
        uint8_t bKeyVaultNonce[0x10];
        uint8_t bKeyVaultPairData[0x8];
        uint8_t b0ManufacturingMode;
        uint8_t b1AlternativeKeyVault;
        uint8_t b2RestrictedPrivilegesFlags;
        uint8_t b3ReservedByte3;
        wire::be16 w4OddFeatures;
        wire::be16 w5OddAuthType;
        wire::be32 dw6RestrictedHvExtLoader;
        wire::be32 dw7PolicyFlashSize;
        wire::be32 dw8PolicyBuiltInUsbMuSize;
        wire::be32 dw9ReservedDword4;
        wire::be64 qwARestrictedPrivileges;
        wire::be64 qwBReservedQword2;
        wire::be64 qwCReservedQword3;
        wire::be64 qwDReservedQword4;
        uint8_t bEReservedKey1[0x10];
        uint8_t bFReservedKey2[0x10];
        uint8_t b10ReservedKey3[0x10];
        uint8_t b11ReservedKey4[0x10];
        uint8_t b12ReservedRandomKey1[0x10];
        uint8_t b13ReservedRandomKey2[0x10];
        char sz14ConsoleSerialNumber[0xC];
        wire::be32 dw14Padding;
        uint8_t b15MoboSerialNumber[0x8];
        wire::be16 w16GameRegion;
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
    };

    static_assert(wire::WireLayout<CONSOLE_PUBLIC_KEY> && sizeof(CONSOLE_PUBLIC_KEY) == 0x84);
    static_assert(wire::WireLayout<XE_CONSOLE_CERTIFICATE> &&
                  sizeof(XE_CONSOLE_CERTIFICATE) == 0x1A8);
    static_assert(wire::WireLayout<XE_KEYVAULT_DATA> && sizeof(XE_KEYVAULT_DATA) == 0x4000);
    static_assert(offsetof(XE_KEYVAULT_DATA, w4OddFeatures) == 0x1C);
    static_assert(offsetof(XE_KEYVAULT_DATA, sz14ConsoleSerialNumber) == 0xB0);
    static_assert(offsetof(XE_KEYVAULT_DATA, w16GameRegion) == 0xC8);
    static_assert(offsetof(XE_KEYVAULT_DATA, b36ConsoleCertificate) == 0x9C8);
    static_assert(offsetof(XE_KEYVAULT_DATA, b37XeikaCertificate) == 0xB70);
    static_assert(offsetof(XE_KEYVAULT_DATA, b39SpecialKeyVaultSignature) == 0x1DF8);
    static_assert(offsetof(XE_KEYVAULT_DATA, b38CardeaCertificate) == 0x1EF8);

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

    bool is_zero_cpu_key(std::span<const uint8_t> cpu_key);

    CpuKeyResult validate_cpu_key(std::span<const uint8_t> cpu_key);
    CpuKeyResult validate_cpu_key_hex(std::string_view hex);

    bool cpukey_valid(std::span<const uint8_t> cpu_key);

    [[nodiscard]] Result<> crypt_secfile(std::span<const uint8_t> cpu_key, std::span<uint8_t> data);

    struct Keyvault {
        static constexpr size_t kSize = 0x4000;
        static constexpr size_t kOsigOffset =
            offsetof(XE_KEYVAULT_DATA, b37XeikaCertificate) + 0x122;
        static constexpr size_t kOsigLength = 28;
        static_assert(kOsigOffset == 0xC92 && sizeof(XE_KEYVAULT_DATA) == kSize);

        XE_KEYVAULT_DATA data{};
        bool encrypted{true};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        [[nodiscard]] static Result<Keyvault> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<Keyvault> parse(const std::vector<uint8_t>& bytes);

        [[nodiscard]] Result<> decrypt(std::span<const uint8_t> cpu_key);
        [[nodiscard]] Result<> encrypt(std::span<const uint8_t> cpu_key);
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    [[nodiscard]] KeyvaultSummaryInfo summarize_keyvault(const Keyvault& kv);

    [[nodiscard]] Result<std::vector<uint8_t>> keyvault_decrypt(std::span<const uint8_t> cpu_key,
                                                                std::span<const uint8_t> data,
                                                                uint16_t kv_version = 0x0712);
    [[nodiscard]] Result<std::vector<uint8_t>> keyvault_encrypt(std::span<const uint8_t> cpu_key,
                                                                std::span<const uint8_t> data,
                                                                uint16_t kv_version = 0x0712);

    struct LooseKeyvault {
        enum class Form {
            Sealed,
            Clear,
            StaleNonce,
            Unopened,
        };
        std::vector<uint8_t> plain;
        Form form{Form::Clear};
    };
    [[nodiscard]] Result<LooseKeyvault> open_loose_keyvault(std::span<const uint8_t> cpu_key,
                                                            std::span<const uint8_t> data);

} // namespace gxbuild::nand
