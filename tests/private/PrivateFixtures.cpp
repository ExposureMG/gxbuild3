#include "PrivateFixtures.hpp"

#include <format>
#include <system_error>

namespace gxbuild3::test {

    PrivateFixtureSet fixture_state(std::span<const PrivateFixture> fixtures) {
        PrivateFixtureSet set;
        size_t present = 0;
        for (const auto& fixture : fixtures) {
            std::error_code error;
            if (std::filesystem::exists(fixture.path, error)) {
                ++present;
            } else {
                set.missing.push_back(std::format("{} ({})", fixture.role, fixture.path.string()));
            }
        }
        if (present == 0) {
            set.state = PrivateFixtureState::AllAbsent;
        } else if (present == fixtures.size()) {
            set.state = PrivateFixtureState::Complete;
        } else {
            set.state = PrivateFixtureState::Partial;
        }
        return set;
    }

    std::string describe_missing(const PrivateFixtureSet& set) {
        std::string text;
        for (const auto& missing : set.missing) {
            if (!text.empty()) {
                text += ", ";
            }
            text += missing;
        }
        return text;
    }

    std::span<const PrivateFixture, 3> keyvault_fixtures() {
        static const std::array<PrivateFixture, 3> fixtures{{
            {"CPU key", GXBUILD3_KEYVAULT_CPU_KEY_FILE},
            {"encrypted keyvault", GXBUILD3_KEYVAULT_ENCRYPTED_FILE},
            {"decrypted keyvault", GXBUILD3_KEYVAULT_DECRYPTED_FILE},
        }};
        return fixtures;
    }

} // namespace gxbuild3::test
