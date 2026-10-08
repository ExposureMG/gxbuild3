// src/stfs/MetadataParser.hpp: the locale strings decode from UTF-16BE to UTF-8 (surrogate
// pairs joined, unpaired ones U+FFFD, each field stopping at its size), and the thumbnail sizes
// are kept, clamped to 0x4000 or, when negative, empty.

#include "PirsPackage.hpp"
#include "stfs/MetadataParser.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <string_view>

namespace gxbuild3::stfs {
    namespace {

        using pirs::Bytes;
        using pirs::make_package;
        using pirs::pattern;
        using pirs::put_be;

        void put_utf16be(Bytes& bytes, std::size_t offset, std::u16string_view text) {
            for (std::size_t i = 0; i < text.size(); ++i) {
                put_be(bytes, offset + 2 * i, text[i], 2);
            }
        }

        std::string as_string(const std::u8string& text) {
            return {text.begin(), text.end()};
        }

        TEST(StfsMetadata, LocaleStringsDecodeFromUtf16Be) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            put_utf16be(bytes, 0x411, u"System Update");
            put_utf16be(bytes, 0xD11, u"caf\u00e9 \u20ac \U0001F600"); // 2-, 3- and 4-byte UTF-8
            put_utf16be(bytes, 0x1611, u"Pub\xD800x");                 // unpaired high surrogate
            put_utf16be(bytes, 0x1691, std::u16string(0x40, u'T'));    // fills the whole field
            bytes[0x1691 + 0x80] = std::byte{0x41};                    // next field, not part of it

            const auto meta = parse_metadata(bytes);
            ASSERT_OK(meta) << "parse_metadata accepts the package";
            EXPECT_EQ(as_string(meta->display_name), "System Update") << "display_name decodes";
            EXPECT_EQ(as_string(meta->display_description),
                      "caf\xC3\xA9 \xE2\x82\xAC \xF0\x9F\x98\x80")
                << "non-ASCII and surrogate pairs decode to UTF-8";
            EXPECT_EQ(as_string(meta->publisher_name), "Pub\xEF\xBF\xBDx")
                << "unpaired surrogates become U+FFFD";
            EXPECT_EQ(as_string(meta->title_name), std::string(0x40, 'T'))
                << "a field without a terminator stops at its size";
        }

        TEST(StfsMetadata, NegativeThumbnailSizeIsEmptyAndPositiveSizesAreClamped) {
            auto bytes = make_package({{"a.bin", pattern(10, 1)}});
            put_be(bytes, 0x1712, 0xFFFFFFFF, 4);
            put_be(bytes, 0x1716, 0x80000000, 4);
            const auto meta = parse_metadata(bytes);
            ASSERT_OK(meta) << "parse_metadata accepts negative thumbnail sizes";
            EXPECT_TRUE(meta->thumbnail_image.empty()) << "negative thumbnail sizes yield no image";
            EXPECT_TRUE(meta->title_thumbnail_image.empty())
                << "negative thumbnail sizes yield no image";

            put_be(bytes, 0x1712, 0x20, 4);
            put_be(bytes, 0x1716, 0x7FFFFFFF, 4);
            const auto sized = parse_metadata(bytes);
            ASSERT_OK(sized) << "parse_metadata accepts positive thumbnail sizes";
            EXPECT_EQ(sized->thumbnail_image.size(), 0x20u)
                << "positive sizes are kept and clamped to 0x4000";
            EXPECT_EQ(sized->title_thumbnail_image.size(), 0x4000u)
                << "positive sizes are kept and clamped to 0x4000";
        }

    } // namespace
} // namespace gxbuild3::stfs
