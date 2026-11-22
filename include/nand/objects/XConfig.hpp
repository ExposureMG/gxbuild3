#pragma once

#include "Error.hpp"
#include "Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::nand {

    struct nand_temperature_constant {
        wire::be16 gain;
        wire::be16 offset;
    };

    struct nand_thermal_limits {
        uint8_t cpu;
        uint8_t gpu;
        uint8_t edram;
    };

    struct nand_viper {
        uint8_t flags;
        uint8_t gpu_target;
        uint8_t memory_target;
        uint8_t checksum;
    };

    struct nand_smc_block {
        uint8_t structure_version;
        uint8_t config_source;
        uint8_t clock_select;
        uint8_t cpu_fan;
        uint8_t gpu_fan;
        uint8_t pad1;
        uint8_t flags;
        uint8_t pad2[3];
        nand_temperature_constant temp_cal[4];
        uint8_t ana_fuse_value;
        nand_thermal_limits setpoint;
        nand_thermal_limits overload;
        uint8_t pad3;
        nand_viper viper;
        uint8_t pad4[190];
        uint8_t backup_thermal_cal_data[23];
        uint8_t pad5[3];
        uint8_t do_not_use[2];
    };

    struct nand_xconfig_static {
        wire::le16 checksum;
        uint8_t checksum_reserved[2];
        wire::be32 version;
        uint8_t first_power_on_date[5];
        uint8_t reserved;
        nand_smc_block smc;
    };

    struct nand_xconfig_secured {
        wire::be32 checksum;
        wire::be32 version;
        uint8_t online_network_id[4];
        uint8_t reserved1[8];
        uint8_t reserved2[12];
        uint8_t mac_address[6];
        uint8_t reserved3[2];
        wire::be32 av_region;
        wire::be16 game_region;
        uint8_t reserved4[6];
        wire::be32 dvd_region;
        char reset_key[4];
        wire::be32 system_flags;
        wire::be16 power_mode;
        wire::be16 power_vcs_control;
        uint8_t reserved_region[444];
    };

    struct nand_xconfig_statistic {
        wire::be32 checksum;
        wire::be32 version;
        uint8_t xuid_mac_address[6];
        uint8_t reserved[2];
        wire::be32 xuid_count;
        uint8_t odd_failures[32];
        uint8_t bug_check_data[101];
        uint8_t temperature_data[200];
        uint8_t unused[467];
        uint8_t hdd_smart_data[512];
        uint8_t uem_errors[100];
        uint8_t fpm_errors[96];
        wire::be64 last_report_time;
    };

    struct nand_manufacturing_data {
        uint8_t bytes[0x1000];
    };

    static_assert(wire::WireLayout<nand_temperature_constant> &&
                  sizeof(nand_temperature_constant) == 4);
    static_assert(wire::WireLayout<nand_thermal_limits> && sizeof(nand_thermal_limits) == 3);
    static_assert(wire::WireLayout<nand_viper> && sizeof(nand_viper) == 4);
    static_assert(wire::WireLayout<nand_smc_block> && sizeof(nand_smc_block) == 0x100);
    static_assert(wire::WireLayout<nand_xconfig_static> && sizeof(nand_xconfig_static) == 0x10E);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, clock_select) ==
                  0x10);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, cpu_fan) == 0x11);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, gpu_fan) == 0x12);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, setpoint) == 0x29);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, overload) == 0x2C);
    static_assert(offsetof(nand_xconfig_static, smc) + offsetof(nand_smc_block, do_not_use) ==
                  0x10C);

    static_assert(wire::WireLayout<nand_xconfig_secured> && sizeof(nand_xconfig_secured) == 0x200);
    static_assert(offsetof(nand_xconfig_secured, mac_address) == 0x20);
    static_assert(offsetof(nand_xconfig_secured, av_region) == 0x28);
    static_assert(offsetof(nand_xconfig_secured, game_region) == 0x2C);
    static_assert(offsetof(nand_xconfig_secured, dvd_region) == 0x34);
    static_assert(offsetof(nand_xconfig_secured, reset_key) == 0x38);

    static_assert(wire::WireLayout<nand_xconfig_statistic> &&
                  sizeof(nand_xconfig_statistic) == 0x600);
    static_assert(offsetof(nand_xconfig_statistic, version) == 0x04);
    static_assert(offsetof(nand_xconfig_statistic, xuid_count) == 0x10);
    static_assert(offsetof(nand_xconfig_statistic, hdd_smart_data) == 0x334);
    static_assert(offsetof(nand_xconfig_statistic, fpm_errors) == 0x598);
    static_assert(offsetof(nand_xconfig_statistic, last_report_time) == 0x5F8);

    static_assert(wire::WireLayout<nand_manufacturing_data> &&
                  sizeof(nand_manufacturing_data) == 0x1000);

    struct SmcConfigBlock {
        static constexpr size_t kSize = 0x400;
        static constexpr size_t kStaticOffset = 0x000;
        static constexpr size_t kSecuredOffset = 0x200;
        static constexpr size_t kSumStart = 0x10;
        static constexpr size_t kSumEnd = 0x10C;

        nand_xconfig_static static_settings{};
        nand_xconfig_secured secured_settings{};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        [[nodiscard]] static uint16_t compute_checksum(std::span<const uint8_t> bytes) noexcept;
        [[nodiscard]] static bool checksum_valid(std::span<const uint8_t> bytes) noexcept;

        [[nodiscard]] static Result<SmcConfigBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<SmcConfigBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    struct StatisticsBlock {
        static constexpr size_t kSize = 0x1000;

        nand_xconfig_statistic data{};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        [[nodiscard]] static Result<StatisticsBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<StatisticsBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] bool erased() const noexcept;
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    struct ManufacturingBlock {
        static constexpr size_t kSize = 0x1000;

        nand_manufacturing_data data{};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        [[nodiscard]] static Result<ManufacturingBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<ManufacturingBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] bool erased() const noexcept;
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
