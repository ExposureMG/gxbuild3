// The embedded freeBOOT rebooter and payload (src/nand/objects/Freeboot.hpp, arrays from
// freeboot/): their sizes and first bytes, the kernel version a built rebooter states at 0xD0B
// in place of the thirty-two X placeholder, the old hold address a 9199 rebooter takes, and the
// word count the payload's `li r4, 0xFFFF` at 0x50 is given for the core it loads.

#include "nand/objects/Freeboot.hpp"
#include "support/Bytes.hpp"
#include "support/Expect.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <span>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        TEST(FreebootProvider, RebooterStatesTheKernelVersionAndPayloadLoadsItsWordCount) {
            EXPECT_EQ(freeboot_rebooter().size(), 0xd40u) << "embedded rebooter is 0xd40 bytes";
            EXPECT_EQ(freeboot_payload().size(), 0x200u) << "embedded payload is 0x200 bytes";
            ASSERT_FALSE(freeboot_rebooter().empty()) << "embedded rebooter starts with 0x3c";
            EXPECT_EQ(freeboot_rebooter()[0], 0x3c) << "embedded rebooter starts with 0x3c";
            ASSERT_FALSE(freeboot_payload().empty()) << "embedded payload starts with 0x80";
            EXPECT_EQ(freeboot_payload()[0], 0x80) << "embedded payload starts with 0x80";

            // The core carries thirty-two X's at 0xD0B for the kernel version, and the payload's
            // `li r4, 0xFFFF` at 0x50 for the words it loads; a built image states both.
            const Bytes blank(0x20, 'X');
            const auto core = freeboot_rebooter();
            const auto version_end = 0xD0B + blank.size();
            ASSERT_GE(core.size(), version_end)
                << "embedded rebooter carries the version placeholder at 0xD0B";
            EXPECT_BYTES_EQ(blank, core.subspan(0xD0B, blank.size()))
                << "embedded rebooter carries the version placeholder at 0xD0B";
            Bytes version(0x20, 0);
            std::copy_n("17559", 5, version.begin());
            const auto stated = freeboot_rebooter_for("17559");
            const std::span<const uint8_t> stated_span(stated);
            ASSERT_EQ(stated.size(), core.size())
                << "the rebooter states the kernel version, zero-padded, at 0xD0B";
            EXPECT_BYTES_EQ(version, stated_span.subspan(0xD0B, version.size()))
                << "the rebooter states the kernel version, zero-padded, at 0xD0B";
            EXPECT_BYTES_EQ(core.first(0xD0B), stated_span.first(0xD0B))
                << "the version string is the only change to the rebooter";
            EXPECT_BYTES_EQ(core.subspan(version_end), stated_span.subspan(version_end))
                << "the version string is the only change to the rebooter";

            const Bytes hold{0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x30, 0x78};
            const Bytes old_hold{0x80, 0x00, 0x00, 0x00, 0x00, 0x1F, 0xFF, 0xF8};
            const auto old = freeboot_rebooter_for("9199");
            EXPECT_TRUE(std::search(core.begin(), core.end(), hold.begin(), hold.end()) !=
                        core.end())
                << "a 9199 rebooter takes the old hold address";
            EXPECT_TRUE(std::search(old.begin(), old.end(), hold.begin(), hold.end()) == old.end())
                << "a 9199 rebooter takes the old hold address";
            EXPECT_TRUE(std::search(old.begin(), old.end(), old_hold.begin(), old_hold.end()) !=
                        old.end())
                << "a 9199 rebooter takes the old hold address";

            ASSERT_GT(freeboot_payload().size(), 0x53u) << "embedded payload loads 0xFFFF words";
            EXPECT_EQ(freeboot_payload()[0x52], 0xFF) << "embedded payload loads 0xFFFF words";
            EXPECT_EQ(freeboot_payload()[0x53], 0xFF) << "embedded payload loads 0xFFFF words";
            const auto payload = freeboot_payload_for(stated.size());
            ASSERT_EQ(payload.size(), 0x200u)
                << "the payload loads the 0xD40-byte core as 0x350 words";
            EXPECT_EQ(payload[0x52], 0x03)
                << "the payload loads the 0xD40-byte core as 0x350 words";
            EXPECT_EQ(payload[0x53], 0x50)
                << "the payload loads the 0xD40-byte core as 0x350 words";
            const auto partial = freeboot_payload_for(0xD2B);
            ASSERT_GT(partial.size(), 0x53u) << "a partial word rounds up";
            EXPECT_EQ(partial[0x53], 0x4B) << "a partial word rounds up";
        }

    } // namespace
} // namespace gxbuild3::nand
