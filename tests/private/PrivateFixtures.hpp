#pragma once

// The private keyvault fixtures of gxbuild3_private_tests: a console's CPU key, its encrypted
// keyvault and an independently decrypted copy. They are never committed; CMake passes their
// paths as compile definitions (cache variables
// GXBUILD3_KEYVAULT_{CPU_KEY,ENCRYPTED,DECRYPTED}_FILE, _temp/ by default). Nothing here reads a
// fixture's contents: fixture_state only asks whether each path exists.

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::test {

    // A private fixture set is used whole or not at all: all absent skips, some absent fails.
    enum class PrivateFixtureState : uint8_t {
        AllAbsent,
        Partial,
        Complete,
    };

    struct PrivateFixture {
        std::string_view role;
        std::filesystem::path path;
    };

    struct PrivateFixtureSet {
        PrivateFixtureState state = PrivateFixtureState::AllAbsent;
        // "<role> (<path>)" of every absent fixture, in the given order.
        std::vector<std::string> missing;
    };

    [[nodiscard]] PrivateFixtureSet fixture_state(std::span<const PrivateFixture> fixtures);

    // The missing entries joined with ", ".
    [[nodiscard]] std::string describe_missing(const PrivateFixtureSet& set);

    // The configured CPU key, encrypted keyvault and decrypted keyvault paths, in that order.
    [[nodiscard]] std::span<const PrivateFixture, 3> keyvault_fixtures();

} // namespace gxbuild3::test
