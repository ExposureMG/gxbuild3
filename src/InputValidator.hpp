#pragma once

#include "Args.hpp"

#include <expected>
#include <string>

namespace gxbuild3 {

    enum class InputErrorCode {
        InvalidCpuKey,
        MissingSmc,
        MissingKeyvault,
        MissingCb,
        MissingCd,
        MissingPatchset,
        UnexpectedPatchset,
        UnsupportedMobileData,
        UnsupportedCustomPayload,
        InvalidPayloadSize,
        InvalidRebooterSize,
        InvalidFusesSize,
        InvalidSettingsBlockSize,
        InvalidOption,
        MissingSigningKey,
    };

    struct InputError {
        InputErrorCode code;
        std::string message;
    };

    std::expected<void, InputError> validate_input(const Input& input);

} // namespace gxbuild3
