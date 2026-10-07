// update_goldens, the work behind `gxbuild3_golden_tests --update <name>...`, against a scratch
// golden directory and fake registries: two agreeing renders are required, an unchanged golden
// (a CRLF checkout included) is never rewritten, and one failing name writes nothing at all.

#include "support/Expect.hpp"
#include "support/Scratch.hpp"
#include "support/golden/Golden.hpp"

#include <chrono>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {
    namespace {

        bool contains(std::string_view text, std::string_view needle) {
            return text.find(needle) != std::string_view::npos;
        }

        test::GoldenRender constant(std::string text) {
            return [text = std::move(text)]() -> Result<std::string> { return text; };
        }

        class GoldenUpdate : public test::ScratchTest {
          protected:
            [[nodiscard]] std::string text_of(std::string_view name) const {
                const auto bytes = test::read_file(root() / (std::string{name} + ".txt"));
                return bytes ? std::string(bytes->begin(), bytes->end()) : std::string{"<absent>"};
            }

            bool update(const std::vector<std::string>& names,
                        const std::vector<test::GoldenEntry>& registry) {
                return test::update_goldens(names, registry, root(), report_);
            }

            [[nodiscard]] std::string report() const { return report_.str(); }

          private:
            std::ostringstream report_;
        };

        TEST_F(GoldenUpdate, UnchangedGoldenIsNotRewritten) {
            const auto path = write("alpha.txt", std::string_view{"one\n"});
            const auto stamp = std::filesystem::last_write_time(path) - std::chrono::hours{24};
            std::filesystem::last_write_time(path, stamp);
            EXPECT_TRUE(update({"alpha"}, {{"alpha", constant("one\n")}})) << report();
            EXPECT_EQ(text_of("alpha"), "one\n");
            EXPECT_EQ(std::filesystem::last_write_time(path), stamp);
            EXPECT_TRUE(contains(report(), "golden alpha unchanged")) << report();
        }

        TEST_F(GoldenUpdate, CrlfCheckoutOfAnUnchangedGoldenIsKept) {
            write("alpha.txt", std::string_view{"one\r\ntwo\r\n"});
            EXPECT_TRUE(update({"alpha"}, {{"alpha", constant("one\ntwo\n")}})) << report();
            EXPECT_EQ(text_of("alpha"), "one\r\ntwo\r\n");
        }

        TEST_F(GoldenUpdate, ChangedGoldenIsRewritten) {
            write("alpha.txt", std::string_view{"old\n"});
            EXPECT_TRUE(update({"alpha"}, {{"alpha", constant("new\n")}})) << report();
            EXPECT_EQ(text_of("alpha"), "new\n");
            EXPECT_TRUE(contains(report(), "GOLDEN UPDATED: alpha -> ")) << report();
        }

        TEST_F(GoldenUpdate, MissingGoldenIsCreated) {
            EXPECT_TRUE(update({"alpha"}, {{"alpha", constant("created\n")}})) << report();
            EXPECT_EQ(text_of("alpha"), "created\n");
        }

        TEST_F(GoldenUpdate, RendersEachNamedGoldenExactlyTwice) {
            auto calls = std::make_shared<int>(0);
            const test::GoldenRender counted = [calls]() -> Result<std::string> {
                ++*calls;
                return std::string{"same\n"};
            };
            EXPECT_TRUE(update({"alpha"}, {{"alpha", counted}, {"beta", counted}})) << report();
            EXPECT_EQ(*calls, 2);
            EXPECT_EQ(text_of("beta"), "<absent>");
        }

        TEST_F(GoldenUpdate, DisagreeingRendersWriteNothing) {
            write("alpha.txt", std::string_view{"old\n"});
            auto calls = std::make_shared<int>(0);
            const test::GoldenRender drifting = [calls]() -> Result<std::string> {
                return "run " + std::to_string(++*calls) + '\n';
            };
            EXPECT_FALSE(update({"alpha"}, {{"alpha", drifting}}));
            EXPECT_EQ(text_of("alpha"), "old\n");
            EXPECT_TRUE(contains(report(), "GOLDEN UPDATE FAILED: alpha: two renders differ"))
                << report();
            EXPECT_TRUE(contains(report(), "  - run 1\n  + run 2\n")) << report();
            EXPECT_TRUE(contains(report(), "nothing written")) << report();
        }

        TEST_F(GoldenUpdate, FailedRenderWritesNothing) {
            const test::GoldenRender broken = []() -> Result<std::string> {
                return fail(ErrorCode::Malformed, "planted render failure");
            };
            EXPECT_FALSE(update({"alpha"}, {{"alpha", broken}}));
            EXPECT_EQ(text_of("alpha"), "<absent>");
            EXPECT_TRUE(contains(
                report(), "GOLDEN UPDATE FAILED: alpha: render failed: planted render failure"))
                << report();
        }

        TEST_F(GoldenUpdate, OneFailingNameWritesNoneOfTheOthers) {
            write("alpha.txt", std::string_view{"old\n"});
            const test::GoldenRender broken = []() -> Result<std::string> {
                return fail(ErrorCode::Malformed, "planted render failure");
            };
            EXPECT_FALSE(
                update({"alpha", "beta"}, {{"alpha", constant("new\n")}, {"beta", broken}}));
            EXPECT_EQ(text_of("alpha"), "old\n");
            EXPECT_EQ(text_of("beta"), "<absent>");
            EXPECT_TRUE(contains(report(), "nothing written")) << report();
        }

        TEST_F(GoldenUpdate, UnknownOrInvalidNameWritesNothing) {
            EXPECT_FALSE(update({"alpha", "nosuch"}, {{"alpha", constant("new\n")}}));
            EXPECT_TRUE(contains(report(), "GOLDEN UPDATE FAILED: unknown golden 'nosuch'"))
                << report();
            EXPECT_FALSE(update({"../escape"}, {{"../escape", constant("new\n")}}));
            EXPECT_TRUE(contains(report(), "GOLDEN UPDATE FAILED: invalid golden name '../escape'"))
                << report();
            EXPECT_EQ(text_of("alpha"), "<absent>");
            EXPECT_FALSE(std::filesystem::exists(root().parent_path() / "escape.txt"));
        }

    } // namespace
} // namespace gxbuild3::snapshots
