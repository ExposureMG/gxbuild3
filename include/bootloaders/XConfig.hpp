#pragma once

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>

#pragma pack(push, 1)

typedef enum _xconfig_category {
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
} xconfig_category;

typedef struct _fan_override {
    unsigned char Speed : 7;
    unsigned char Enable : 1;
} fan_override_t;

typedef struct _fan_override_block {
    fan_override_t cpu;
    fan_override_t gpu;
} fan_override_block_t;

typedef struct _temperature_constant {
    unsigned short gain;
    unsigned short offset;
} temperature_constant_t;

typedef struct _temperature_constant_block {
    temperature_constant_t cpu;
    temperature_constant_t gpu;
    temperature_constant_t edram;
    temperature_constant_t board;
} temperature_constant_block_t;

typedef union _union_temperature {
    unsigned short TempCalData[8];
    temperature_constant_block_t Constant;
} union_temperature_t;

typedef struct _thermal_set_point {
    unsigned char cpu;
    unsigned char gpu;
    unsigned char edram;
} thermal_set_point_t;

typedef struct _thermal_overload {
    unsigned char cpu;
    unsigned char gpu;
    unsigned char edram;
} thermal_overload_t;

typedef struct _thermal {
    thermal_set_point_t setpoint;
    thermal_overload_t overload;
} thermal_t;

typedef struct _viper_as_flags {
    unsigned char unused : 6;
    unsigned char MemoryVoltageNotSetting : 1;
    unsigned char GpuVoltageNotSetting : 1;
} viper_as_flags_t;

typedef union _viper_flags {
    unsigned char AsUCHAR;
    viper_as_flags_t AsFlags;
} viper_flags_t;

typedef struct _viper {
    viper_flags_t flags;
    unsigned char gpu_target;
    unsigned char memory_target;
    unsigned char checksum;
} viper_t;

typedef union _backup_thermal_cal_data {
    unsigned char raw[23];
    struct {
        union_temperature_t Temperature;
        char AnaFuseValue;
        thermal_t Thermal;
    } fields;
} backup_thermal_cal_data_t;

typedef struct _smc_flags {
    unsigned char RadioEnable : 1;
    unsigned char UseTempCalDefaults : 1;
    unsigned char ScreenToolStarted : 1;
    unsigned char ScreenToolFinished : 1;
    unsigned char ScreenToolExecutionCount : 2;
    unsigned char unused : 2;
} smc_flags_t;

typedef union _union_smc_block {
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
} union_smc_block_t;

typedef struct _xconfig_static_settings {
    unsigned int CheckSum;
    unsigned int Version;
    char FirstPowerOnDate[5];
    char Reserved;
    union_smc_block_t SMCBlock;
} xconfig_static_settings_t;

typedef struct _xconfig_statistic_settings {
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
} xconfig_statistic_settings_t;

typedef struct _xconfig_power_mode {
    unsigned char VIDDelta : 1;
    unsigned char Reserved : 7;
} xconfig_power_mode_t;

typedef struct _xconfig_power_vcs_control {
    unsigned short Fuse : 4;
    unsigned short Quiet : 4;
    unsigned short Full : 4;
    unsigned short Reserved : 3;
    unsigned short Configured : 1;
} xconfig_power_vcs_control_t;

typedef struct _xconfig_secured_settings {
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
} xconfig_secured_settings_t;

typedef struct _xconfig_timezone_date {
    unsigned char Month;
    unsigned char Day;
    unsigned char DayOfWeek;
    unsigned char Hour;
} xconfig_timezone_date_t;

typedef struct _xconfig_user_settings {
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
} xconfig_user_settings_t;

typedef struct _xconfig_xnet_machine_account {
    unsigned int Version;
    unsigned char Data[492];
} xconfig_xnet_machine_account_t;

typedef struct _xconfig_xnet_parameters {
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
} xconfig_xnet_parameters_t;

typedef struct _xconfig_media_center_settings {
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
} xconfig_media_center_settings_t;

typedef struct _xconfig_play_timer_data {
    unsigned long long uliResetDate;
    unsigned int dwPlayTimerFrequency;
    unsigned int dwTotalPlayTime;
    unsigned int dwRemainingPlayTime;
} xconfig_play_timer_data_t;

typedef struct _xconfig_console_settings {
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
} xconfig_console_settings_t;

typedef struct _xconfig_dvd_settings {
    unsigned int Version;
    unsigned char VolumeID[20];
    unsigned char Data[640];
} xconfig_dvd_settings_t;

typedef struct _xconfig_iptv_settings {
    unsigned int CheckSum;
    unsigned int Version;
    unsigned short ServiceProviderName[60];
    unsigned short ProvisioningServerURL[64];
    unsigned short SupportInfo[64];
    unsigned short BootstrapServerURL[64];
} xconfig_iptv_settings_t;

typedef struct _xconfig_system_settings {
    unsigned int Version;
    unsigned long long AlarmTime;
    unsigned int PreviousFlashVersion;
} xconfig_system_settings_t;

typedef struct _xconfig_master {
    xconfig_static_settings_t Static;
    xconfig_statistic_settings_t Statistic;
    xconfig_secured_settings_t Secured;
    xconfig_user_settings_t User;
    xconfig_xnet_machine_account_t XnetMachineAccount;
    xconfig_xnet_parameters_t XnetParameters;
    xconfig_media_center_settings_t MediaCenter;
    xconfig_console_settings_t Console;
    xconfig_dvd_settings_t Dvd;
    xconfig_iptv_settings_t Iptv;
    xconfig_system_settings_t System;
} xconfig_master_t;

#pragma pack(pop)

namespace XConfig {

    enum class ParseError {
        NullBuffer,
        BufferTooSmall,
    };

    [[nodiscard]] std::string_view ParseErrorString(ParseError e) noexcept;

    [[nodiscard]] std::expected<xconfig_master_t, ParseError>
    Parse(std::span<const uint8_t> buf, size_t base_offset = 0xC000) noexcept;

} // namespace XConfig