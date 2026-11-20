#pragma once

#include "Error.hpp"
#include "Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace gxbuild3::nand {

#pragma pack(push, 1)

    enum xconfig_category {
        XCONFIG_STATIC_CATEGORY = 0x0,
        XCONFIG_STATISTIC_CATEGORY = 0x1,
        XCONFIG_SECURED_CATEGORY = 0x2,
        XCONFIG_USER_CATEGORY = 0x3,
        XCONFIG_XNET_MACHINE_ACCOUNT_CATEGORY = 0x4,
        XCONFIG_XNET_PARAMETERS_CATEGORY = 0x5,
        XCONFIG_MEDIA_CENTER_CATEGORY = 0x6,
        XCONFIG_CONSOLE_CATEGORY = 0x7,
        XCONFIG_DVD_CATEGORY = 0x8,
        XCONFIG_IPTV_CATEGORY = 0x9,
        XCONFIG_SYSTEM_CATEGORY = 0xA,
    };

    struct fan_override_t {
        unsigned char Speed : 7;
        unsigned char Enable : 1;
    };

    struct fan_override_block_t {
        fan_override_t cpu;
        fan_override_t gpu;
    };

    struct temperature_constant_t {
        unsigned short gain;
        unsigned short offset;
    };

    struct temperature_constant_block_t {
        temperature_constant_t cpu;
        temperature_constant_t gpu;
        temperature_constant_t edram;
        temperature_constant_t board;
    };

    union union_temperature_t {
        unsigned short TempCalData[8];
        temperature_constant_block_t Constant;
    };

    struct thermal_set_point_t {
        unsigned char cpu;
        unsigned char gpu;
        unsigned char edram;
    };

    struct thermal_overload_t {
        unsigned char cpu;
        unsigned char gpu;
        unsigned char edram;
    };

    struct thermal_t {
        thermal_set_point_t setpoint;
        thermal_overload_t overload;
    };

    struct viper_as_flags_t {
        unsigned char unused : 6;
        unsigned char MemoryVoltageNotSetting : 1;
        unsigned char GpuVoltageNotSetting : 1;
    };

    union viper_flags_t {
        unsigned char AsUCHAR;
        viper_as_flags_t AsFlags;
    };

    struct viper_t {
        viper_flags_t flags;
        unsigned char gpu_target;
        unsigned char memory_target;
        unsigned char checksum;
    };

    union backup_thermal_cal_data_t {
        unsigned char raw[23];
        struct {
            union_temperature_t Temperature;
            char AnaFuseValue;
            thermal_t Thermal;
        } fields;
    };

    struct smc_flags_t {
        unsigned char RadioEnable : 1;
        unsigned char UseTempCalDefaults : 1;
        unsigned char ScreenToolStarted : 1;
        unsigned char ScreenToolFinished : 1;
        unsigned char ScreenToolExecutionCount : 2;
        unsigned char unused : 2;
    };

    union union_smc_block_t {
        unsigned char raw[256];
        struct {
            unsigned char structure_version;
            unsigned char config_source;
            char clock_select;
            fan_override_block_t fan_override;
            char pad1[1];
            smc_flags_t flags;
            char pad2[3];
            union_temperature_t temperature;
            char ana_fuse_value;
            thermal_t thermal;
            unsigned char pad3[1];
            viper_t viper;
            unsigned char pad4[190];
            backup_thermal_cal_data_t backup_thermal_cal_data;
            unsigned char pad5[3];
            unsigned char do_not_use[2];
        } fields;
    };

    struct xconfig_static_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        char FirstPowerOnDate[5];
        char Reserved;
        union_smc_block_t SMCBlock;
    };

    struct xconfig_statistic_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        char XUIDMACAddress[6];
        char Reserved[2];
        unsigned int XUIDCount;
        unsigned char ODDFailures[32];
        unsigned char BugCheckData[101];
        unsigned char TemperatureData[200];
        char Unused[467];
        char HDDSmartData[512];
        char UEMErrors[100];
        char FPMErrors[56];
        unsigned long long LastReportTime;
    };

    struct xconfig_power_mode_t {
        unsigned char VIDDelta : 1;
        unsigned char Reserved : 7;
    };

    struct xconfig_power_vcs_control_t {
        unsigned short Fuse : 4;
        unsigned short Quiet : 4;
        unsigned short Full : 4;
        unsigned short Reserved : 3;
        unsigned short Configured : 1;
    };

    struct xconfig_secured_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        char OnlineNetworkID[4];
        char Reserved1[8];
        char Reserved2[12];
        unsigned char MACAddress[6];
        char Reserved3[2];
        unsigned int AVRegion;
        unsigned short GameRegion;
        char Reserved4[6];
        unsigned int DVDRegion;
        unsigned int ResetKey;
        unsigned int SystemFlags;
        unsigned short PowerMode;
        unsigned short PowerVcsControl;
        char ReservedRegion[444];
    };

    struct xconfig_timezone_date_t {
        unsigned char Month;
        unsigned char Day;
        unsigned char DayOfWeek;
        unsigned char Hour;
    };

    struct xconfig_user_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        unsigned int TimeZoneBias;
        char TimeZoneStdName[4];
        char TimeZoneDltName[4];
        xconfig_timezone_date_t TimeZoneStdDate;
        xconfig_timezone_date_t TimeZoneDltDate;
        unsigned int TimeZoneStdBias;
        unsigned int TimeZoneDltBias;
        unsigned long long DefaultProfile;
        unsigned int Language;
        unsigned int VideoFlags;
        unsigned int AudioFlags;
        unsigned int RetailFlags;
        unsigned int DevkitFlags;
        char Country;
        char ParentalControlFlags;
        unsigned char ReservedFlag[2];
        char SMBConfig[256];
        unsigned long long LivePUID;
        char LiveCredentials[16];
        short AVPackHDMIScreenSz[2];
        short AVPackComponentScreenSz[2];
        short AVPackVGAScreenSz[2];
        unsigned int ParentalControlGame;
        unsigned int ParentalControlPassword;
        unsigned int ParentalControlMovie;
        unsigned int ParentalControlGameRating;
        unsigned int ParentalControlMovieRating;
        char ParentalControlHint;
        char ParentalControlHintAnswer[32];
        char ParentalControlOverride[32];
        unsigned int MusicPlaybackMode;
        float MusicVolume;
        unsigned int MusicFlags;
        unsigned int ArcadeFlags;
        unsigned int ParentalControlVersion;
        unsigned int ParentalControlTv;
        unsigned int ParentalControlTvRating;
        unsigned int ParentalControlExplicitVideo;
        unsigned int ParentalControlExplicitVideoRating;
        unsigned int ParentalControlUnratedVideo;
        unsigned int ParentalControlUnratedVideoRating;
        unsigned int VideoOutputBlackLevels;
        unsigned char VideoPlayerDisplayMode;
        unsigned int AlternativeVideoTimingIDs;
        unsigned int VideoDriverOptions;
        unsigned int MusicUIFlags;
        char VideoMediaSourceType;
        char MusicMediaSourceType;
        char PhotoMediaSourceType;
    };

    struct xconfig_xnet_machine_account_t {
        unsigned int Version;
        unsigned char Data[492];
    };

    struct xconfig_xnet_parameters_t {
        unsigned char cfgSizeOfStruct;
        unsigned char cfgFlags;
        unsigned char cfgSockMaxDgramSockets;
        unsigned char cfgSockMaxStreamSockets;
        unsigned char cfgSockDefaultRecvBufsizeInK;
        unsigned char cfgSockDefaultSendBufsizeInK;
        unsigned char cfgKeyRegMax;
        unsigned char cfgSecRegMax;
        unsigned char cfgQosDataLimitDiv4;
        unsigned char cfgQosProbleTimeoutInSeconds;
        unsigned char cfgQosProbeEntries;
        unsigned char cfgQosSrvMaxSimultaneousResponses;
        unsigned char cfgQosPairWaitTimeInSeconds;
    };

    struct xconfig_media_center_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        char MediaPlayer[20];
        unsigned char xeSledVersion[10];
        unsigned char xeSledTrustSecret[20];
        unsigned char xeSledTrustCode[8];
        unsigned char xeSledHostID[20];
        unsigned char xeSledKey[1628];
        unsigned char xeSledHostMACAddress[6];
        char ServerUUID[16];
        char ServerName[128];
        char ServerFlags[4];
    };

    struct xconfig_play_timer_data_t {
        unsigned long long uliResetDate;
        unsigned int dwPlayTimerFrequency;
        unsigned int dwTotalPlayTime;
        unsigned int dwRemainingPlayTime;
    };

    struct xconfig_console_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        short ScreenSaver;
        short AutoShutOff;
        unsigned char WirelessSettings[256];
        unsigned int CameraSettings;
        unsigned char CameraSettingsReserved[28];
        xconfig_play_timer_data_t PlayTimerData;
        short MediaDisableAutoLaunch;
        short KeyboardLayout;
    };

    struct xconfig_dvd_settings_t {
        unsigned int Version;
        unsigned char VolumeID[20];
        unsigned char Data[640];
    };

    struct xconfig_iptv_settings_t {
        unsigned int CheckSum;
        unsigned int Version;
        unsigned short ServiceProviderName[60];
        unsigned short ProvisioningServerURL[64];
        unsigned short SupportInfo[64];
        unsigned short BootstrapServerURL[64];
    };

    struct xconfig_system_settings_t {
        unsigned int Version;
        unsigned long long AlarmTime;
        unsigned int PreviousFlashVersion;
    };

#pragma pack(pop)

    struct SmcConfig {
        xconfig_static_settings_t Static{};
        xconfig_statistic_settings_t Statistic{};
        xconfig_secured_settings_t Secured{};
        xconfig_user_settings_t User{};
        xconfig_xnet_machine_account_t XnetMachineAccount{};
        xconfig_xnet_parameters_t XnetParameters{};
        xconfig_media_center_settings_t MediaCenter{};
        xconfig_console_settings_t Console{};
        xconfig_dvd_settings_t Dvd{};
        xconfig_iptv_settings_t Iptv{};
        xconfig_system_settings_t System{};

        // Refuses a buffer too short to hold every settings region past base_offset
        // (Truncated).
        [[nodiscard]] static Result<SmcConfig> parse(std::span<const uint8_t> bytes,
                                                     size_t base_offset = 0);
        [[nodiscard]] static Result<SmcConfig> parse(const std::vector<uint8_t>& bytes,
                                                     size_t base_offset = 0);
        [[nodiscard]] std::vector<uint8_t> serialize(size_t total_size = 0x10000,
                                                     size_t base_offset = 0) const;
    };

    using xconfig_master_t = SmcConfig;

    // The same model at the offset an XConfig region sits at inside a 64 KiB config blob.
    namespace xconfig {

        [[nodiscard]] Result<SmcConfig> parse(std::span<const uint8_t> buf,
                                              size_t base_offset = 0xC000);

        [[nodiscard]] std::vector<uint8_t>
        serialize(const SmcConfig& cfg, size_t total_size = 0x10000, size_t base_offset = 0xC000);

    } // namespace xconfig

    // ---- Split NAND settings, statistics and manufacturing blocks (wire layout) ---------------

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
        // Speed in percent with bit 7 (0x80) enabling override; 0x7F leaves control to the SMC.
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

    // The 0x400-byte settings block on NAND: static settings at +0x000, secured settings at +0x200.
    // serialize() emits raw_data untouched unless reserialize is set, in which case both records
    // are encoded back and the LE16 checksum over [kSumStart, kSumEnd) is recomputed.
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

        // Refuses any buffer whose size is not kSize (Truncated / Malformed) or whose checksum fails
        // (Malformed).
        [[nodiscard]] static Result<SmcConfigBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<SmcConfigBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    // The 0x1000-byte statistics block on NAND (Statistics.settings): nand_xconfig_statistic at
    // +0x000, rest erased (0xFF). serialize() emits raw_data untouched unless reserialize is set.
    struct StatisticsBlock {
        static constexpr size_t kSize = 0x1000;

        nand_xconfig_statistic data{};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        // Refuses any buffer whose size is not kSize (Truncated / Malformed).
        [[nodiscard]] static Result<StatisticsBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<StatisticsBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] bool erased() const noexcept;
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

    // The 0x1000-byte manufacturing block on NAND (Manufacturing.data). serialize() emits raw_data
    // untouched unless reserialize is set.
    struct ManufacturingBlock {
        static constexpr size_t kSize = 0x1000;

        nand_manufacturing_data data{};
        bool reserialize{false};
        std::vector<uint8_t> raw_data;

        // Refuses any buffer whose size is not kSize (Truncated / Malformed).
        [[nodiscard]] static Result<ManufacturingBlock> parse(std::span<const uint8_t> bytes);
        [[nodiscard]] static Result<ManufacturingBlock> parse(const std::vector<uint8_t>& bytes);
        [[nodiscard]] bool erased() const noexcept;
        [[nodiscard]] std::vector<uint8_t> serialize() const;
    };

} // namespace gxbuild3::nand
