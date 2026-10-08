// src/cli/BuildInputResolver.hpp: the CPU key. An explicit -p key (trimmed) beats every root,
// else the first root holding a cpukey.txt supplies it; uppercase hex is accepted and a
// correctable ECC error is corrected. A missing, invalid or unreadable key fails with its own
// code and, for a discovered key, the file it came from; a cpukey.txt that cannot be inspected
// stops the search instead of falling through to a later root.

#include "ResolverTest.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Keys.hpp"

#include <algorithm>
#include <cctype>
#include <expected>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <system_error>

namespace gxbuild3::cli {
    namespace {

        std::string uppercase(std::string value) {
            std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
                return static_cast<char>(std::toupper(character));
            });
            return value;
        }

        class ResolverCpuKey : public ResolverTest {};

        TEST_F(ResolverCpuKey, FirstRootIsDiscoveredAndAnExplicitKeyOverridesEveryRoot) {
            const auto first_key = test::valid_cpu_key();
            const auto second_key = test::different_valid_cpu_key();
            write("first/cpukey.txt", " \r\n" + test::hex(first_key) + "\t\n");
            write("second/cpukey.txt", test::hex(second_key));
            auto args = minimum_args();
            args.source_dirs = {path("first"), path("second")};
            args.cpu_key.reset();
            const auto discovered = resolve_foundations(args);
            ASSERT_OK(discovered) << "the first source root supplies the discovered CPU key";
            ASSERT_BYTES_EQ(first_key, discovered->cpu_key)
                << "the first source root supplies the discovered CPU key";

            args.cpu_key = "  " + test::hex(second_key) + "\r\n";
            const auto explicit_key = resolve_foundations(args);
            ASSERT_OK(explicit_key) << "an explicit trimmed CPU key overrides every source root";
            EXPECT_BYTES_EQ(second_key, explicit_key->cpu_key)
                << "an explicit trimmed CPU key overrides every source root";
        }

        TEST_F(ResolverCpuKey, UppercaseAndCorrectedCpuKeysAreAccepted) {
            const auto key = test::valid_cpu_key();
            auto args = minimum_args();
            args.cpu_key = uppercase(test::hex(key));
            const auto uppercase_result = resolve_foundations(args);
            ASSERT_OK(uppercase_result) << "uppercase hexadecimal CPU keys are accepted";
            ASSERT_BYTES_EQ(key, uppercase_result->cpu_key)
                << "uppercase hexadecimal CPU keys are accepted";

            auto correctable = key;
            correctable.front() ^= 0x01;
            args.cpu_key = test::hex(correctable);
            const auto corrected_result = resolve_foundations(args);
            ASSERT_OK(corrected_result)
                << "correctable CPU-key ECC errors return the corrected 16-byte key";
            EXPECT_BYTES_EQ(key, corrected_result->cpu_key)
                << "correctable CPU-key ECC errors return the corrected 16-byte key";
        }

        TEST_F(ResolverCpuKey, ErrorsArePrecise) {
            auto args = minimum_args();
            args.cpu_key.reset();
            ASSERT_ERROR(resolve_foundations(args), ResolutionErrorCode::CpuKeyNotFound)
                << "missing CPU key is reported distinctly";

            write("first/cpukey.txt", "0123xyz\n");
            const auto invalid_file = resolve_foundations(args);
            ASSERT_ERROR(invalid_file, ResolutionErrorCode::InvalidCpuKey)
                << "invalid discovered CPU key identifies its file";
            ASSERT_EQ(invalid_file.error().path, path("first/cpukey.txt"))
                << "invalid discovered CPU key identifies its file";

            args.cpu_key = "not-a-cpu-key";
            const auto invalid_explicit = resolve_foundations(args);
            ASSERT_ERROR(invalid_explicit, ResolutionErrorCode::InvalidCpuKey)
                << "invalid explicit CPU key is not attributed to a file";
            EXPECT_TRUE(invalid_explicit.error().path.empty())
                << "invalid explicit CPU key is not attributed to a file";
        }

        TEST_F(ResolverCpuKey, LookupFailureDoesNotFallThrough) {
            std::error_code error;
            ASSERT_TRUE(std::filesystem::create_directory(path("first/cpukey.txt"), error))
                << "a directory stands in the first root's cpukey.txt: " << error.message();
            write("second/cpukey.txt", test::hex(test::valid_cpu_key()));
            auto args = minimum_args();
            args.cpu_key.reset();
            args.source_dirs = {path("first"), path("second")};

            std::expected<ResolvedFoundations, ResolutionError> result;
            ASSERT_NO_THROW(result = resolve_foundations(args))
                << "CPU-key filesystem failures must not escape the resolver";
            ASSERT_ERROR(result, ResolutionErrorCode::CpuKeyReadFailed)
                << "first-priority CPU-key inspection failure is structured and terminal";
            EXPECT_EQ(result.error().path, path("first/cpukey.txt"))
                << "first-priority CPU-key inspection failure is structured and terminal";
            EXPECT_EQ(result.error().item, "cpukey.txt")
                << "first-priority CPU-key inspection failure is structured and terminal";
        }

    } // namespace
} // namespace gxbuild3::cli
