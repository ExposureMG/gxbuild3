#pragma once

#include "Error.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    struct CrlSealing {
        std::array<uint8_t, 16> iv{};
        std::array<uint8_t, 16> file_key{};
    };

    struct DaeSealing {
        std::array<uint8_t, 7> head{};
        std::array<uint8_t, 16> field{};
    };

    struct SecuredFileBuild {
        int64_t build_seconds{0};
        uint8_t lockdown_value{0};
    };

    [[nodiscard]] std::array<uint8_t, 8> secured_file_stamp(int64_t build_seconds);

    [[nodiscard]] Result<CrlSealing> crl_sealing(std::span<const uint8_t> own,
                                                 std::span<const uint8_t> cpu_key);
    [[nodiscard]] Result<DaeSealing> dae_sealing(std::span<const uint8_t> own,
                                                 std::span<const uint8_t> cpu_key);

    [[nodiscard]] CrlSealing random_crl_sealing();
    [[nodiscard]] DaeSealing random_dae_sealing();

    [[nodiscard]] Result<std::vector<uint8_t>> reseal_crl(std::span<const uint8_t> content,
                                                          std::span<const uint8_t> cpu_key,
                                                          const CrlSealing& sealing,
                                                          const SecuredFileBuild& build);

    [[nodiscard]] Result<std::vector<uint8_t>> reseal_dae(std::span<const uint8_t> content,
                                                          std::span<const uint8_t> cpu_key,
                                                          const DaeSealing& sealing,
                                                          const SecuredFileBuild& build);

    [[nodiscard]] bool extended_opened(std::span<const uint8_t> clear,
                                       std::span<const uint8_t> cpu_key);
    [[nodiscard]] bool secdata_opened(std::span<const uint8_t> clear,
                                      std::span<const uint8_t> cpu_key);

    [[nodiscard]] Result<std::vector<uint8_t>>
    reseal_extended(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key,
                    std::span<const uint8_t, 8> keyvault_head);

    [[nodiscard]] Result<std::vector<uint8_t>>
    reseal_secdata(std::span<const uint8_t> clear, std::span<const uint8_t> cpu_key,
                   std::optional<std::array<uint8_t, 8>> head, const SecuredFileBuild& build);

    inline constexpr size_t kExtendedSize = 0x4000;
    inline constexpr size_t kSecdataSize = 0x400;

    [[nodiscard]] Result<std::vector<uint8_t>>
    clean_extended(std::span<const uint8_t> cpu_key, std::span<const uint8_t, 8> keyvault_head);

    [[nodiscard]] Result<std::vector<uint8_t>> clean_secdata(std::span<const uint8_t> cpu_key,
                                                             std::span<const uint8_t, 8> head,
                                                             const SecuredFileBuild& build);

    [[nodiscard]] std::array<uint8_t, 8> random_secdata_head();

    [[nodiscard]] Result<std::vector<uint8_t>>
    open_loose_extended(std::span<const uint8_t> blob, std::span<const uint8_t> cpu_key);
    [[nodiscard]] Result<std::vector<uint8_t>> open_loose_secdata(std::span<const uint8_t> blob,
                                                                  std::span<const uint8_t> cpu_key);

    enum class FcrtSealing {
        Sealed,
        Carried,
        InvalidSize,
        InvalidOffset,
        Damaged,
    };

    struct SealedFcrt {
        std::vector<uint8_t> data;
        FcrtSealing sealing{FcrtSealing::Carried};
    };

    [[nodiscard]] SealedFcrt seal_fcrt(std::span<const uint8_t> content,
                                       std::span<const uint8_t> cpu_key);

    enum class FcrtRequirement {
        NotRequired,
        Required,
        RequiredByDrive,
    };

    [[nodiscard]] FcrtRequirement fcrt_requirement(std::span<const uint8_t> clear_keyvault);

    [[nodiscard]] Result<std::array<uint8_t, 8>> secdata_head(std::span<const uint8_t> clear);

} // namespace gxbuild3::nand
