// src/utils/Utils.hpp: read_file, write_file and create_directory report failures as Errors that
// carry the path, and write_file creates missing parents.

#include "Error.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "utils/Utils.hpp"

#include <gtest/gtest.h>
#include <string>

namespace gxbuild3::utils {
    namespace {

        using test::Bytes;

        class UtilsIo : public test::ScratchTest {};

        TEST_F(UtilsIo, FailuresAreErrorsCarryingThePathAndWriteCreatesParents) {
            const auto missing = utils::read_file(root() / "absent.bin");
            EXPECT_ERROR(missing, ErrorCode::NotFound)
                << "reading a missing file fails with NotFound naming the path";
            ASSERT_FALSE(missing.has_value());
            EXPECT_TRUE(missing.error().message.contains("absent.bin"))
                << "reading a missing file fails with NotFound naming the path: "
                << missing.error().message;

            const auto nested = root() / "out/deeper/image.bin";
            EXPECT_OK(utils::write_file(nested, {0x01, 0x02, 0x03}))
                << "write_file creates missing parents and writes";
            const auto read_back = utils::read_file(nested);
            ASSERT_OK(read_back) << "written bytes read back";
            EXPECT_EQ(*read_back, (Bytes{0x01, 0x02, 0x03})) << "written bytes read back";
            const auto truncated = utils::read_file(nested, 2);
            ASSERT_OK(truncated) << "max_length truncates the read";
            EXPECT_EQ(*truncated, (Bytes{0x01, 0x02})) << "max_length truncates the read";

            const auto blocker = write("blocker", Bytes{0x00});
            EXPECT_ERROR(utils::create_directory(blocker / "child"), ErrorCode::IoError)
                << "create_directory under a regular file fails with IoError";
            const auto blocked_write = utils::write_file(blocker / "child/file.bin", {0x00});
            ASSERT_FALSE(blocked_write.has_value())
                << "write_file reports a parent creation failure with context";
            EXPECT_FALSE(blocked_write.error().context.empty())
                << "write_file reports a parent creation failure with context";
            EXPECT_OK(utils::create_directory(root() / "out"))
                << "create_directory on an existing directory succeeds";
        }

    } // namespace
} // namespace gxbuild3::utils
