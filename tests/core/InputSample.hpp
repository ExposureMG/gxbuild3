#pragma once

// The input shared by the validate_input and OptionsManager tests: a retail small-block build
// with a 16-byte CPU key, an SMC, a keyvault and the CB and CD bootloaders, which
// validate_input accepts.

#include "Args.hpp"

#include <cstdint>
#include <vector>

namespace gxbuild3::core {

    inline Input valid_input() {
        Input input{};
        input.build_type = BuildType::Retail;
        input.image_type = ImageType::SmallBlock;
        input.metadata.cpu_key.assign(16, 0x11);
        input.metadata.smc = std::vector<uint8_t>(0x100, 0x22);
        input.metadata.keyvault = std::vector<uint8_t>(0x4000, 0x33);
        input.bootloaders.cb_or_a = {0x43, 0x42};
        input.bootloaders.cd = {0x43, 0x44};
        return input;
    }

} // namespace gxbuild3::core
