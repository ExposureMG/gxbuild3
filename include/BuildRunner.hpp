#pragma once

#include "Args.hpp"

#include <cstdint>
#include <optional>
#include <vector>

// Executes a full NAND build from a populated GxArgs struct.
// Handles key parsing, options.ini loading, INI parsing, bootloader loading,
// patching, and image assembly. Returns the assembled image bytes on success,
// or std::nullopt on failure (errors are emitted via Log::Error).
//
// The following GxArgs fields control library-specific behaviour:
//   ini_content      — inline INI string, skips loading from data_dir
//   source_nand_bytes — inline source NAND bytes, skips path discovery
//   kv_path          — explicit keyvault file path override
//   smc_path         — explicit SMC file path override
//   smc_config_path  — explicit SMC config file path override
std::optional<std::vector<uint8_t>> RunBuild(GxArgs args);
