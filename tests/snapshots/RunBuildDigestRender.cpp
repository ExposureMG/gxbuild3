// run_build output digests (tests/golden/run_build_digests.txt): SmallBlock, NewSmallBlock,
// BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built twice under a
// pinned build time (SOURCE_DATE_EPOCH in UTC) with every donor nonce filled so no nonce is
// drawn. The two builds must be byte-identical; the SHA-1 of the output goes to the golden.
// The old BuildRunnerTests.cpp test_run_build_output_digests, verbatim: its require() messages
// are problems now, and its golden compare and summary line are RunBuildDigestGolden's.

#include "BuildRunner.hpp"
#include "RunBuildGoldenRender.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/builders/Inputs.hpp"

#include <array>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots::run_build_digests {
    namespace {

        using test::digest_input;
        using test::sha1_hex;

        void require(bool condition, std::string message, std::vector<std::string>& problems) {
            if (!condition) {
                problems.push_back(std::move(message));
            }
        }

    } // namespace

    Rendered render() {
        constexpr std::array layouts{std::pair{ImageType::SmallBlock, "small"},
                                     std::pair{ImageType::NewSmallBlock, "newsmall"},
                                     std::pair{ImageType::BigBlock, "big"},
                                     std::pair{ImageType::Emmc, "emmc"}};
        constexpr std::array builds{
            std::pair{BuildType::Retail, "retail"}, std::pair{BuildType::Glitch2, "glitch2"},
            std::pair{BuildType::Devkit, "devkit"}, std::pair{BuildType::Devgl, "devgl"}};

        const auto build_pinned = [](const Input& input) {
            const test::PinnedBuildTime pinned{"1791105724", "UTC0"};
            return run_build(input);
        };

        Rendered out;
        std::string& rendered = out.text;
        for (const auto& [image_type, layout_name] : layouts) {
            for (const auto& [build_type, build_name] : builds) {
                ++out.total;
                const std::string label = std::string{layout_name} + '.' + build_name;
                const auto input = digest_input(image_type, build_type);
                const auto first = build_pinned(input);
                const auto second = build_pinned(input);
                if (!first || !second) {
                    rendered += label + " error=" +
                                (first ? second.error().message : first.error().message) + '\n';
                    require(false, label + " builds", out.problems);
                    continue;
                }
                if (*first != *second) {
                    require(false, label + " builds byte-identically twice", out.problems);
                    rendered += label + " nondeterministic\n";
                    continue;
                }
                ++out.identical;
                char size[32];
                std::snprintf(size, sizeof(size), "0x%zx", first->size());
                rendered += label + " size=" + size + " sha1=" + sha1_hex(*first) + '\n';
            }
        }
        return out;
    }

    Result<std::string> render_file() {
        Rendered rendered = render();
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the run_build_digests render reports {} problem(s), first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::run_build_digests
