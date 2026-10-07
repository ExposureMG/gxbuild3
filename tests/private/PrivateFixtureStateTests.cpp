// fixture_state (PrivateFixtures.hpp) over dummy files in a scratch directory, so the skip and
// partial-failure rules of the private keyvault cases are checked on every clone, fixtures or
// not. The dummies hold placeholder text, never key material.

#include "PrivateFixtures.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <array>
#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::private_tests {
    namespace {

        struct StateRow {
            const char* name;
            // Which of the CPU key, encrypted and decrypted keyvault dummies exist.
            std::array<bool, 3> present;
            test::PrivateFixtureState expected;
            // The roles fixture_state must report missing, in order.
            std::vector<std::string_view> missing;
        };
        GX_PRINT_ROW_AS_NAME(StateRow)

        constexpr std::array<std::string_view, 3> kRoles{"CPU key", "encrypted keyvault",
                                                         "decrypted keyvault"};
        constexpr std::array<std::string_view, 3> kFiles{"cpukey.txt", "KV_en.bin", "KV_dec.bin"};

        class PrivateFixtureState : public test::ScratchTest,
                                    public ::testing::WithParamInterface<StateRow> {};

        TEST_P(PrivateFixtureState, ClassifiesTheFixtureSet) {
            const auto& row = GetParam();
            std::vector<test::PrivateFixture> fixtures;
            for (size_t i = 0; i < kRoles.size(); ++i) {
                const auto path = root() / kFiles[i];
                if (row.present[i]) {
                    write(kFiles[i], std::string_view{"placeholder"});
                }
                fixtures.push_back({kRoles[i], path});
            }

            const auto set = test::fixture_state(fixtures);
            EXPECT_EQ(set.state, row.expected);

            std::vector<std::string> expected_missing;
            for (size_t i = 0; i < kRoles.size(); ++i) {
                if (!row.present[i]) {
                    expected_missing.push_back(std::string{kRoles[i]} + " (" +
                                               (root() / kFiles[i]).string() + ")");
                }
            }
            ASSERT_EQ(set.missing.size(), row.missing.size());
            EXPECT_EQ(set.missing, expected_missing);
            for (size_t i = 0; i < row.missing.size(); ++i) {
                EXPECT_TRUE(set.missing[i].starts_with(row.missing[i])) << set.missing[i];
            }

            std::string joined;
            for (const auto& missing : expected_missing) {
                joined += (joined.empty() ? "" : ", ") + missing;
            }
            EXPECT_EQ(test::describe_missing(set), joined);
        }

        INSTANTIATE_TEST_SUITE_P(
            State, PrivateFixtureState,
            ::testing::Values(
                StateRow{"AllAbsent",
                         {false, false, false},
                         test::PrivateFixtureState::AllAbsent,
                         {"CPU key", "encrypted keyvault", "decrypted keyvault"}},
                StateRow{"Partial",
                         {true, false, false},
                         test::PrivateFixtureState::Partial,
                         {"encrypted keyvault", "decrypted keyvault"}},
                StateRow{"Complete", {true, true, true}, test::PrivateFixtureState::Complete, {}}),
            test::RowName{});

    } // namespace
} // namespace gxbuild3::private_tests
