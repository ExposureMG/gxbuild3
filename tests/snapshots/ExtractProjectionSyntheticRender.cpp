// Every public extract_* projection (tests/support/render/ExtractProjection.hpp) of two
// run_build digest outputs, against tests/golden/extract_projections_synthetic.txt:
//   small.glitch2             CB_A + CB_B, CE, CF/CG in slot 0, patch file and XeLL;
//   newsmall.devkit           the SB/SC/SD/SE chain, where extract_all_info states the SC
//                             decrypted while extract_some_info reads it sealed;
//   newsmall.devkit.zero-key  the same image under the all-zero CPU key: its keyvault was
//                             sealed under the test console's key, stays sealed, and
//                             extract_all leaves it out (extract_metadata refuses).
// Each image is built twice under the pinned build time and donor nonces, and each image
// is projected twice; both must be identical. The mydata dump's projections are
// MydataRender.cpp's (tests/golden/extract_projections_mydata.txt).
// The old BuildRunnerTests.cpp test_extract_projection_snapshots, verbatim: its require()
// messages are problems now. The loop body is render_case, the "<label>.extract_" lines of one
// case, which each ExtractProjectionSynthetic row compares with its section of the golden;
// render (and render_file, the whole-file renderer --update uses) concatenates the three cases
// in the file's order.

#include "BuildRunner.hpp"
#include "RunBuildGoldenRender.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/builders/Inputs.hpp"
#include "support/render/ExtractProjection.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots::extract_projections_synthetic {
    namespace {

        using test::digest_input;
        using test::valid_cpu_key;

        void require(bool condition, std::string message, std::vector<std::string>& problems) {
            if (!condition) {
                problems.push_back(std::move(message));
            }
        }

        // The cases of the file, in its order.
        struct Case {
            std::string_view label;
            ImageType image_type;
            BuildType build_type;
            bool zero_cpu_key;
        };
        constexpr std::array kCases{
            Case{"small.glitch2", ImageType::SmallBlock, BuildType::Glitch2, false},
            Case{"newsmall.devkit", ImageType::NewSmallBlock, BuildType::Devkit, false},
            Case{"newsmall.devkit.zero-key", ImageType::NewSmallBlock, BuildType::Devkit, true},
        };

    } // namespace

    CaseRendered render_case(std::string_view case_label) {
        CaseRendered out;
        const auto found = std::ranges::find(kCases, case_label, &Case::label);
        if (found == kCases.end()) {
            out.problems.push_back("extract_projections_synthetic has no case " +
                                   std::string{case_label});
            return out;
        }
        const Case& c = *found;
        const auto build_pinned = [](const Input& input) {
            const test::PinnedBuildTime pinned{"1791105724", "UTC0"};
            return run_build(input);
        };
        const auto cpu_key = valid_cpu_key();
        const std::array<uint8_t, 16> zero_key{};

        std::string& rendered = out.text;
        const std::string label{c.label};
        const auto input = digest_input(c.image_type, c.build_type);
        const auto first = build_pinned(input);
        const auto second = build_pinned(input);
        if (!first || !second) {
            rendered += label +
                        " build-error=" + (first ? second.error().message : first.error().message) +
                        '\n';
            require(false, label + " builds", out.problems);
            return out;
        }
        if (*first != *second) {
            require(false, label + " builds byte-identically twice", out.problems);
            rendered += label + " nondeterministic-build\n";
            return out;
        }
        const std::span<const uint8_t> key =
            c.zero_cpu_key ? std::span<const uint8_t>(zero_key) : std::span(cpu_key);
        const auto once = test::projection::render_extract_projections(label, *first, key);
        const auto twice = test::projection::render_extract_projections(label, *first, key);
        out.comparisons += once.comparisons;
        out.agreements += once.agreements;
        for (const auto& what : once.disagreements) {
            require(false, what + " renders the same as the core's span overload", out.problems);
        }
        if (once.text == twice.text) {
            out.stable = true;
        } else {
            require(false, label + " projects identically twice", out.problems);
        }
        rendered += once.text;
        return out;
    }

    Rendered render() {
        Rendered out;
        out.cases = kCases.size();
        for (const auto& c : kCases) {
            CaseRendered rendered = render_case(c.label);
            out.text += rendered.text;
            out.stable += rendered.stable ? 1 : 0;
            out.comparisons += rendered.comparisons;
            out.agreements += rendered.agreements;
            out.problems.insert(out.problems.end(), rendered.problems.begin(),
                                rendered.problems.end());
        }
        return out;
    }

    Result<std::string> render_file() {
        Rendered rendered = render();
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the extract_projections_synthetic render reports {} problem(s), "
                        "first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::extract_projections_synthetic
