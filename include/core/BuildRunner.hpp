#pragma once

#include "core/Args.hpp"
#include "core/NandExtractor.hpp"
#include "gxbuild/Error.hpp"

#include <cstdint>
#include <vector>

namespace gxbuild {

    [[nodiscard]] Result<std::vector<uint8_t>> run_build(const Input& input);

} // namespace gxbuild
