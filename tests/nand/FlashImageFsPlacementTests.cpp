// Where FlashImage places its FlashFS root (src/nand/FlashImageWrite.cpp, FlashImageParse.cpp):
// away from the file allocations and recorded in the layout, on the last free data block when
// the root is deferred, found again under the legacy 0x2C root type, and bound to its own
// driver after the image is copied or moved.

#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/objects/FlashFileSystem.hpp"
#include "support/Expect.hpp"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::nand {
    namespace {

        using test::Bytes;

        TEST(FlashImageFsPlacement, FlashImagePlacesFilesystemRootConsistently) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);

            FlashFileSystem filesystem{};
            ASSERT_OK(filesystem.format(image.flash_driver.block_count()))
                << "FlashFS must format before placement";
            const Bytes file_data{0x10, 0x20, 0x30};
            ASSERT_OK(filesystem.add_file("test.bin", file_data))
                << "FlashFS must accept a test file";
            image.filesystem = std::move(filesystem);

            ASSERT_OK(image.write_to_driver()) << "FlashImage must write a filesystem image";

            const auto root_block = image.filesystem->root_block();
            ASSERT_EQ(image.flash_driver.layout().fs_root_block, root_block)
                << "FlashImage layout must identify the block containing the filesystem root";
            ASSERT_NE(root_block, 0x3E0)
                << "FlashImage must relocate the default filesystem root away from file "
                   "allocations";

            auto parsed = FlashImage::read(image.flash_driver.serialize());
            ASSERT_TRUE(parsed.has_value()) << "FlashImage must parse the filesystem it just wrote";
            ASSERT_OK(parsed->parse()) << "FlashImage must parse the filesystem it just wrote";
            ASSERT_TRUE(parsed->filesystem.has_value())
                << "FlashImage must find the filesystem root at the recorded block";
            EXPECT_EQ(parsed->filesystem->get_file("test.bin"), file_data)
                << "FlashImage must preserve files after root relocation";
        }

        // A copied or moved image's filesystem reads and writes its own driver: adding a file to
        // it and saving lands in that image's flash and leaves the image it came from untouched,
        // even once the source is gone.
        TEST(FlashImageFsPlacement, FlashImageCopyAndMoveRebindTheFilesystem) {
            FlashImage source{};
            source.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            FlashFileSystem filesystem{};
            filesystem.set_driver(&source.flash_driver);
            const Bytes source_file{0x11, 0x22, 0x33};
            ASSERT_OK(filesystem.format(source.flash_driver.block_count()))
                << "FlashFS must format for the rebinding check";
            ASSERT_OK(filesystem.add_file("source.bin", source_file))
                << "FlashFS must accept the source file";
            ASSERT_OK(filesystem.save()) << "FlashFS must save into the source image";
            source.filesystem = std::move(filesystem);
            const Bytes source_bytes = std::as_const(source.flash_driver).serialize();

            // Adds `name` to the image's filesystem, saves it and reads it back through a
            // filesystem loaded fresh from the image's own driver.
            const auto lands_in_own_driver = [](FlashImage& image, std::string_view name,
                                                const Bytes& data) {
                if (!image.filesystem || !image.filesystem->add_file(name, data) ||
                    !image.filesystem->save()) {
                    return false;
                }
                FlashFileSystem reread{};
                return reread.load(image.flash_driver, image.filesystem->root_block())
                           .has_value() &&
                       reread.get_file(name) == data && image.filesystem->get_file(name) == data;
            };

            {
                FlashImage copy = source;
                EXPECT_TRUE(lands_in_own_driver(copy, "copy.bin", {0x01}))
                    << "a copy-constructed image's filesystem must write its own driver";
            }
            {
                FlashImage assigned{};
                assigned = source;
                EXPECT_TRUE(lands_in_own_driver(assigned, "assigned.bin", {0x02}))
                    << "a copy-assigned image's filesystem must write its own driver";
            }
            {
                std::optional<FlashImage> donor = source;
                FlashImage moved = std::move(*donor);
                donor.reset();
                EXPECT_TRUE(lands_in_own_driver(moved, "moved.bin", {0x03}))
                    << "a move-constructed image's filesystem must write its own driver";
            }
            {
                std::optional<FlashImage> donor = source;
                FlashImage assigned{};
                assigned = std::move(*donor);
                donor.reset();
                EXPECT_TRUE(lands_in_own_driver(assigned, "move_assigned.bin", {0x04}))
                    << "a move-assigned image's filesystem must write its own driver";
            }
            EXPECT_BYTES_EQ(source_bytes, std::as_const(source.flash_driver).serialize())
                << "writes through a copy or a move must leave the source image's flash";
            ASSERT_TRUE(source.filesystem.has_value())
                << "the source image's filesystem must keep only its own file";
            EXPECT_EQ(source.filesystem->list_files(), std::vector<std::string>{"source.bin"})
                << "the source image's filesystem must keep only its own file";
        }

        // Direct regression for the reported double-allocation bug: when files and mobile
        // data pack the data region so only the final block below the limit stays free, a
        // deferred-root filesystem must still place its root there and serialize. The old
        // reserve-then-relocate path pre-consumed that block in format() and then failed
        // with "Failed to place FlashFS root block after payload allocations".
        TEST(FlashImageFsPlacement, FlashImagePlacesDeferredRootInLastFreeBlock) {
            FlashImage image{};
            image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            const size_t limit = image.flash_driver.data_block_limit();

            FlashFileSystem filesystem{};
            filesystem.set_driver(&image.flash_driver);
            ASSERT_OK(
                filesystem.format(image.flash_driver.block_count(), FlashFileSystem::kDeferRoot))
                << "deferred-root FlashFS must format";
            const Bytes file_data{0x10, 0x20, 0x30};
            ASSERT_OK(filesystem.add_file("test.bin", file_data))
                << "FlashFS must accept a test file";
            const auto entry = filesystem.stat("test.bin");
            ASSERT_TRUE(entry.has_value()) << "FlashFS must accept a test file";
            const size_t file_block = entry->block_number;
            ASSERT_OK(filesystem.reserve_blocks(file_block + 1, limit - 1 - (file_block + 1)))
                << "FlashFS reserves every data block below the final one";
            image.filesystem = std::move(filesystem);

            const auto output = image.write();
            ASSERT_OK(output) << "FlashImage must serialize a data region with one free block";
            ASSERT_TRUE(image.filesystem->has_root())
                << "FlashFS root must be placed after serializing a full data region";
            const auto root_block = image.filesystem->root_block();
            ASSERT_EQ(image.flash_driver.layout().fs_root_block, root_block)
                << "deferred root must land on the sole free data block, not the reserved tail";
            ASSERT_EQ(size_t{root_block}, limit - 1)
                << "deferred root must land on the sole free data block, not the reserved tail";

            auto parsed = FlashImage::read(*output);
            ASSERT_TRUE(parsed.has_value())
                << "FlashImage must parse the packed filesystem it just wrote";
            ASSERT_OK(parsed->parse())
                << "FlashImage must parse the packed filesystem it just wrote";
            ASSERT_TRUE(parsed->filesystem.has_value())
                << "FlashImage must parse the packed filesystem it just wrote";
            EXPECT_EQ(parsed->filesystem->get_file("test.bin"), file_data)
                << "FlashImage must preserve the file when the root takes the last free block";
        }

        TEST(FlashImageFsPlacement, FlashImageAcceptsLegacyFilesystemRootType) {
            Driver source(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
            FlashFileSystem filesystem{};
            ASSERT_OK(filesystem.format(source.block_count(), 0x80))
                << "FlashFS must format at a test root block";
            filesystem.set_driver(&source);
            ASSERT_OK(filesystem.save()) << "FlashFS must serialize its test root";

            BlockMetadata metadata{};
            metadata.logical_block_id = 0x80;
            metadata.sequence = 3;
            metadata.block_type = 0x2C;
            source.write_block_metadata(0x80, metadata);

            auto image = FlashImage::read(source.serialize());
            ASSERT_TRUE(image.has_value())
                << "FlashImage must parse a NAND image with a legacy filesystem root";
            ASSERT_OK(image->parse())
                << "FlashImage must parse a NAND image with a legacy filesystem root";
            EXPECT_TRUE(image->filesystem.has_value())
                << "FlashImage must recognize filesystem block type 0x2C";
        }

    } // namespace
} // namespace gxbuild3::nand
