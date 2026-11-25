#pragma once

#include "core/Args.hpp"
#include "gxbuild/Error.hpp"

namespace gxbuild {

    [[nodiscard]] Result<void> validate_input(const Input& input);

} // namespace gxbuild
