typedef struct _smc_patch {
    std::string addr;
    std::string value;
} smc_patch_t;

inline smc_patch_t Glitch{"05 ?? E5 ?? B4 05", "00 00 ?? ?? ?? ??"};

inline smc_patch_t NoDriveBlink{"E4 A2 CF 92 E0 A2 CE 22", "E4 D3 22 00 00 00 00 00"};

inline smc_patch_t NoDriveBlink_KSB{"E4 A2 C3 92 E0 A2 C0 22", "E4 D3 22 00 00 00 00 00"};

inline smc_patch_t EjectDisable{"A2 90 B3 22", "00 00 C3 22"};

inline smc_patch_t EjectDisable_KSB{"A2 93 B3 22", "00 00 C3 22"};

