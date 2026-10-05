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

std::expected<void, InputError> ValidateInput(const GxBuild::Input& input);
