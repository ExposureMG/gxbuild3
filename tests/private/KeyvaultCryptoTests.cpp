// keyvault_decrypt and Keyvault::decrypt against a console's private fixtures
// (PrivateFixtures.hpp): both must reproduce the independently decrypted reference byte for byte.
// The expected bytes come only from that reference file, never from keyvault_encrypt, so matching
// bugs cannot cancel each other out.
//
// Every case skips when all three fixtures are absent (a clean clone, CI) and fails, naming the
// missing roles and paths, when only some are present. Nothing here prints a CPU key, keyvault
// bytes or a validate_cpu_key_hex message (which may hold a corrected key): byte comparisons
// report sizes and the first differing offset only.

#include "PrivateFixtures.hpp"
#include "nand/objects/Keyvault.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::private_tests {
    namespace {

        using nand::CpuKeyStatus;
        using nand::Keyvault;

        // The CPU key fixture holds 32 hex characters plus whitespace; anything larger is not one.
        constexpr size_t kMaxCpuKeyFileSize = 1024;

        constexpr std::string_view kInvalidCpuKey =
            "CPU key fixture must contain a valid, uncorrected 32-character hexadecimal CPU key";

        struct KeyvaultFixtures {
            std::string cpu_key_hex;
            test::Bytes encrypted;
            test::Bytes expected;
        };

        std::string trimmed(std::string_view text) {
            const auto first = text.find_first_not_of(" \t\r\n");
            if (first == std::string_view::npos) {
                return {};
            }
            const auto last = text.find_last_not_of(" \t\r\n");
            return std::string{text.substr(first, last - first + 1)};
        }

        Result<KeyvaultFixtures> load_fixtures() {
            const auto fixtures = test::keyvault_fixtures();
            auto key_file = test::read_file(fixtures[0].path);
            if (!key_file) {
                return std::unexpected(std::move(key_file.error()));
            }
            if (key_file->size() > kMaxCpuKeyFileSize) {
                return fail(ErrorCode::InvalidArgument,
                            "{}: the CPU key fixture is larger than {} bytes",
                            fixtures[0].path.string(), kMaxCpuKeyFileSize);
            }
            auto encrypted = test::read_file(fixtures[1].path);
            if (!encrypted) {
                return std::unexpected(std::move(encrypted.error()));
            }
            auto expected = test::read_file(fixtures[2].path);
            if (!expected) {
                return std::unexpected(std::move(expected.error()));
            }
            return KeyvaultFixtures{
                .cpu_key_hex = trimmed(std::string_view{
                    reinterpret_cast<const char*>(key_file->data()), key_file->size()}),
                .encrypted = std::move(*encrypted),
                .expected = std::move(*expected),
            };
        }

        // Read once per process, on the first case that finds the whole set present.
        const Result<KeyvaultFixtures>& loaded_fixtures() {
            static const Result<KeyvaultFixtures> fixtures = load_fixtures();
            return fixtures;
        }

        class KeyvaultCrypto : public ::testing::Test {
          protected:
            void SetUp() override {
                const auto set = test::fixture_state(test::keyvault_fixtures());
                if (set.state == test::PrivateFixtureState::AllAbsent) {
                    GTEST_SKIP() << "private keyvault fixtures are not installed";
                }
                if (set.state == test::PrivateFixtureState::Partial) {
                    FAIL() << "partial private fixture set, missing: "
                           << test::describe_missing(set);
                }
                const auto& loaded = loaded_fixtures();
                ASSERT_OK(loaded);
                fixtures_ = &*loaded;
                ASSERT_EQ(fixtures_->encrypted.size(), Keyvault::kSize)
                    << "the encrypted keyvault fixture must be exactly 16384 bytes";
                ASSERT_EQ(fixtures_->expected.size(), Keyvault::kSize)
                    << "the decrypted keyvault fixture must be exactly 16384 bytes";
                cpu_key_ = nand::validate_cpu_key_hex(fixtures_->cpu_key_hex);
            }

            [[nodiscard]] const KeyvaultFixtures& fixtures() const { return *fixtures_; }
            [[nodiscard]] bool cpu_key_is_valid() const {
                return cpu_key_.status == CpuKeyStatus::Valid;
            }
            [[nodiscard]] const std::vector<uint8_t>& cpu_key() const { return cpu_key_.key; }

          private:
            const KeyvaultFixtures* fixtures_ = nullptr;
            nand::CpuKeyResult cpu_key_;
        };

        TEST_F(KeyvaultCrypto, CpuKeyFixtureIsValidUncorrected) {
            // The status only: the validation message can contain a corrected CPU key.
            EXPECT_TRUE(cpu_key_is_valid()) << kInvalidCpuKey;
        }

        TEST_F(KeyvaultCrypto, KeyvaultDecryptMatchesReference) {
            ASSERT_TRUE(cpu_key_is_valid()) << kInvalidCpuKey;
            ASSERT_OK_AND_ASSIGN(const auto decrypted,
                                 nand::keyvault_decrypt(cpu_key(), fixtures().encrypted));
            EXPECT_BYTES_EQ(fixtures().expected, decrypted);
        }

        TEST_F(KeyvaultCrypto, KeyvaultObjectDecryptMatchesReference) {
            ASSERT_TRUE(cpu_key_is_valid()) << kInvalidCpuKey;
            ASSERT_OK_AND_ASSIGN(auto keyvault, Keyvault::parse(fixtures().encrypted));
            ASSERT_OK(keyvault.decrypt(cpu_key()));
            EXPECT_BYTES_EQ(fixtures().expected, keyvault.serialize());
        }

        TEST_F(KeyvaultCrypto, DecryptClearsEncryptedFlag) {
            ASSERT_TRUE(cpu_key_is_valid()) << kInvalidCpuKey;
            ASSERT_OK_AND_ASSIGN(auto keyvault, Keyvault::parse(fixtures().encrypted));
            ASSERT_TRUE(keyvault.encrypted);
            ASSERT_OK(keyvault.decrypt(cpu_key()));
            EXPECT_FALSE(keyvault.encrypted);
        }

    } // namespace
} // namespace gxbuild3::private_tests
