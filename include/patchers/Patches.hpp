#pragma once

#include <string>

namespace gxbuild::patchers {
    typedef struct _smc_patch {
        std::string addr;
        std::string value;
    } smc_patch_t;

    // smc byte signature patch applied to retail smcs on glitch1 and glitch2 builds
    inline const smc_patch_t Glitch{"05 ?? E5 ?? B4 05", "00 00 ?? ?? ?? ??"};

    // unused smc patches kept around for no-blink and eject-disable options
    inline const smc_patch_t NoDriveBlink{"E4 A2 CF 92 E0 A2 CE 22", "E4 D3 22 00 00 00 00 00"};

    inline const smc_patch_t NoDriveBlink_KSB{"E4 A2 C3 92 E0 A2 C0 22", "E4 D3 22 00 00 00 00 00"};

    inline const smc_patch_t EjectDisable{"A2 90 B3 22", "00 00 C3 22"};

    inline const smc_patch_t EjectDisable_KSB{"A2 93 B3 22", "00 00 C3 22"};
} // namespace gxbuild::patchers
