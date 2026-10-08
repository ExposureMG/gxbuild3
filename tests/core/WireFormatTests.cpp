// Formatting src/Wire.hpp fields: std::format and fail() through the std::formatter
// specialisations, and gxbuild3::Log (spdlog with its bundled fmt) through wire::format_as,
// found by ADL, without .get().

#include "Error.hpp"
#include "Wire.hpp"
#include "core/WireSample.hpp"
#include "support/Expect.hpp"
#include "utils/Log.hpp"

#include <format>
#include <gtest/gtest.h>
#include <memory>
#include <spdlog/sinks/ostream_sink.h>
#include <spdlog/spdlog.h>
#include <sstream>
#include <string>

namespace gxbuild3::core {
    namespace {

        TEST(WireFormat, StdFormatAndFailReadHostValues) {
            const auto r = make_sample();
            EXPECT_EQ(std::format("{:04X} {:#x} {}", r.magic, r.count, r.block),
                      "4342 0x11223344 11259375")
                << "std::format reads the host value";
            const Result<void> failed =
                fail(ErrorCode::Malformed, "bad magic {:04X} at {:#x}", r.magic, r.stamp);
            ASSERT_FALSE(failed.has_value()) << "fail() formats wire fields";
            EXPECT_EQ(failed.error().message, "bad magic 4342 at 0x102030405060708")
                << "fail() formats wire fields";
        }

        // Log::Init with the GxBuild3 logger's sinks replaced by one capturing "%v" lines.
        // TearDown always runs Log::Shutdown, also after a failed SetUp ASSERT, so the next
        // Log::Init in this process (another test, --gtest_repeat) can register the logger again.
        class LogCaptureTest : public ::testing::Test {
          protected:
            void SetUp() override {
                Log::Init();
                m_logger = spdlog::get("GxBuild3");
                ASSERT_NE(m_logger, nullptr) << "Log::Init registers the GxBuild3 logger";
                auto sink = std::make_shared<spdlog::sinks::ostream_sink_mt>(m_captured);
                sink->set_pattern("%v");
                m_logger->sinks().clear();
                m_logger->sinks().push_back(sink);
            }

            void TearDown() override {
                m_logger.reset();
                Log::Shutdown();
            }

            // Everything logged so far, flushed.
            [[nodiscard]] std::string captured() {
                m_logger->flush();
                return m_captured.str();
            }

          private:
            std::ostringstream m_captured;
            std::shared_ptr<spdlog::logger> m_logger;
        };

        class WireLog : public LogCaptureTest {};

        TEST_F(WireLog, LogInfoFormatsWireFieldsWithoutGet) {
            const auto r = make_sample();
            Log::Info("magic {:04X} version {} count {:#x} block {:06X} stamp {:#x}", r.magic,
                      r.version, r.count, r.block, r.stamp);
            EXPECT_EQ(
                captured(),
                "magic 4342 version 8002 count 0x11223344 block ABCDEF stamp 0x102030405060708\n")
                << "Log::Info formats wire fields without .get()";
        }

    } // namespace
} // namespace gxbuild3::core
