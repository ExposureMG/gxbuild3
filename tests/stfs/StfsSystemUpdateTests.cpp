// The tracked system update package 17559/su20076000_00000000 (two hash levels, 31 consecutive
// files): StfsContainer lists, verifies and extracts it, and the hash-verified extract agrees
// with extract_to_memory. Its file table and metadata are pinned field by field by the
// stfs_su20076000_* goldens, which this binary does not own.

#include "PirsPackage.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>

namespace gxbuild3::stfs {
    namespace {

        using pirs::data_offset;
        using pirs::make_package;
        using pirs::pattern;
        using Verify = StfsContainer::Verify;

        // Read once per process and shared by both cases; a missing tracked fixture fails them.
        const Result<test::Bytes>& system_update_package() {
            static const Result<test::Bytes> package =
                test::read_support_file("17559/su20076000_00000000");
            return package;
        }

        // The extract_to_memory key of an entry: a leading "$flash_" (exactly that case) is
        // dropped and the rest lower-cased.
        std::string memory_key(const std::string& name) {
            std::string key = name;
            if (key.starts_with("$flash_")) {
                key.erase(0, 7);
            }
            std::transform(key.begin(), key.end(), key.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            return key;
        }

        TEST(StfsSystemUpdate, FixtureListsItsFilesAndExtractsThemByteIdentically) {
            const auto& package = system_update_package();
            ASSERT_OK(package) << "fixture su20076000_00000000 is readable";
            ASSERT_FALSE(package->empty()) << "fixture su20076000_00000000 is readable";
            const auto bytes = std::as_bytes(std::span{*package});

            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "StfsContainer opens the fixture";
            EXPECT_EQ(container->entries().size(), 31u) << "fixture lists 31 files";
            const auto meta = parse_metadata(bytes);
            ASSERT_OK(meta) << "parse_metadata accepts the fixture";
            const auto& display_name = meta->display_name;
            EXPECT_EQ(std::string(display_name.begin(), display_name.end()), "System Update")
                << "fixture display_name decodes from UTF-16BE";

            const auto in_memory = container->extract_to_memory();
            ASSERT_OK(in_memory) << "StfsContainer extracts the fixture to memory";
            for (const auto& entry : container->entries()) {
                SCOPED_TRACE(entry.name);
                const auto verified = container->extract(entry, Verify::Yes);
                ASSERT_OK(verified) << "StfsContainer verifies " << entry.name;
                const auto key = memory_key(entry.name);
                ASSERT_TRUE(in_memory->contains(key))
                    << "verified extract and extract_to_memory return identical bytes";
                EXPECT_BYTES_EQ(in_memory->at(key), *verified)
                    << "verified extract and extract_to_memory return identical bytes";
            }

            const auto verified_sha1 = [&](std::string_view name) -> std::string {
                for (const auto& entry : container->entries()) {
                    if (entry.name == name) {
                        const auto verified = container->extract(entry, Verify::Yes);
                        return verified ? test::sha1_hex(*verified)
                                        : "verify failed: " + verified.error().describe();
                    }
                }
                return "fixture entry missing";
            };
            EXPECT_EQ(verified_sha1("xboxupd.bin"), "ea7666ebe2799812270581538b342b8143397ab9")
                << "xboxupd.bin extracts byte-identically";
            EXPECT_EQ(verified_sha1("$flash_dash.xex"), "3d44ef57781c20669705cd687e3b62b1c2f1ff6b")
                << "$flash_dash.xex extracts byte-identically";
        }

        // StfsContainer::extract with Verify::Yes checks the hash tables up to the top hash and
        // returns the same bytes as the unverified extract_to_memory path.
        TEST(StfsSystemUpdate, VerifiedExtractEqualsExtractToMemoryAndCorruptionFailsIt) {
            const auto& package = system_update_package();
            ASSERT_OK(package) << "fixture su20076000_00000000 is readable";
            ASSERT_FALSE(package->empty()) << "fixture su20076000_00000000 is readable";
            const auto bytes = std::as_bytes(std::span{*package});

            const auto container = StfsContainer::open(bytes);
            ASSERT_OK(container) << "StfsContainer opens the fixture";
            EXPECT_EQ(container->entries().size(), 31u) << "StfsContainer lists 31 entries";
            EXPECT_EQ(container->header_size(), 0xAD0Eu)
                << "StfsContainer reports header size 0xAD0E";
            const auto in_memory = container->extract_to_memory();
            ASSERT_OK(in_memory) << "StfsContainer extracts the fixture to memory";

            std::size_t files = 0;
            for (const auto& entry : container->entries()) {
                if (entry.is_directory()) {
                    continue;
                }
                SCOPED_TRACE(entry.name);
                const auto verified = container->extract(entry, Verify::Yes);
                ASSERT_OK(verified) << "StfsContainer verifies " << entry.name;
                const auto key = memory_key(entry.name);
                ASSERT_TRUE(in_memory->contains(key))
                    << "verified extract equals extract_to_memory for " << entry.name;
                EXPECT_BYTES_EQ(in_memory->at(key), *verified)
                    << "verified extract equals extract_to_memory for " << entry.name;
                ++files;
            }
            EXPECT_EQ(files, in_memory->size()) << "every in-memory file was verified";

            const test::ScratchDir dir;
            EXPECT_OK(container->extract_all(dir.path() / "out", Verify::Yes))
                << "StfsContainer verified extract_all succeeds on the fixture";

            auto data_corrupt = make_package({{"a.bin", pattern(10, 1)}});
            data_corrupt[data_offset(1) + 0x800] ^= std::byte{0x01}; // past file_size, hashed
            const auto corrupt = StfsContainer::open(data_corrupt);
            ASSERT_OK(corrupt) << "StfsContainer opens the corrupted package";
            const auto& entry = corrupt->entries().at(0);
            const auto unverified = corrupt->extract(entry);
            EXPECT_OK(unverified) << "unverified container extraction ignores the hash";
            EXPECT_BYTES_EQ(pattern(10, 1), unverified.value_or(pirs::Bytes{}))
                << "unverified container extraction ignores the hash";
            EXPECT_ERROR(corrupt->extract(entry, Verify::Yes), ErrorCode::HashMismatch)
                << "verified container extraction fails the hash";
            const test::ScratchDir corrupt_dir;
            EXPECT_ERROR(corrupt->extract_all(corrupt_dir.path() / "out", Verify::Yes),
                         ErrorCode::HashMismatch)
                << "verified container extract_all fails the hash";
        }

    } // namespace
} // namespace gxbuild3::stfs
