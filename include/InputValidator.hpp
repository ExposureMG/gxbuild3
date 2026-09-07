#pragma once

#include "Args.hpp"

#include <expected>
#include <string>

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
    InvalidRebooterSize,
    InvalidFusesSize,
};

struct InputError {
    InputErrorCode code;
    std::string message;
};

std::expected<void, InputError> ValidateInput(const Input& input);
