// The run_build digests and extract_* projections over the tracked mydata/image.bin
// (MydataGoldenRender.hpp), against tests/golden/orchestration_mydata_builds.txt and
// tests/golden/extract_projections_mydata.txt. The old tests/OrchestrationGoldenTests.cpp main()
// and test_extract_projection_snapshots, verbatim: its check() messages are problems now, and its
// golden compares and summary lines are MydataGolden's.

#include "BuildRunner.hpp"
#include "MydataGoldenRender.hpp"
#include "support/Bytes.hpp"
#include "support/Env.hpp"
#include "support/Keys.hpp"
#include "support/Scratch.hpp"
#include "support/render/ExtractProjection.hpp"

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::snapshots {

    namespace mydata {
        namespace {

            using Bytes = std::vector<uint8_t>;

            // The CPU key of the tracked mydata/image.bin, public in build_all.sh (-p ...).
            constexpr auto kCpuKey = test::kBuildAllCpuKey;

            BuildResult build_pinned(const Input& input) {
                const test::PinnedBuildTime pinned{"1791105724", "UTC0"};
                return run_build(input);
            }

            struct Variant {
                std::string_view name;
                BuildType build_type;
                const char* patchset;
                const char* xell;
                bool smcnocheck;
            };

            constexpr std::array<Variant, kVariants> variants{
                Variant{"retail", BuildType::Retail, nullptr, nullptr, false},
                Variant{"jtag", BuildType::Jtag, "patches_jasper.bin", "xell-2f.bin", true},
                Variant{"glitch2", BuildType::Glitch2, "patches_g2jasper.bin", "xell-gggggg.bin",
                        false},
            };

            Result<Donor> load_donor() {
                auto image = test::read_support_file("mydata/image.bin", kSupportOverride);
                if (!image) {
                    return fail(image.error().code, "mydata/image.bin reads: {}",
                                image.error().describe());
                }
                auto extracted = extract_all(*image, kCpuKey);
                if (!extracted) {
                    return fail(extracted.error().code, "extract_all(mydata/image.bin): {}",
                                extracted.error().describe());
                }
                return Donor{std::move(*image), std::move(*extracted)};
            }

            VariantBuild build_variant(const Donor& donor, const Variant& variant) {
                VariantBuild out;
                const std::string label = "mydata." + std::string{variant.name};
                Input input = donor.extracted;
                input.build_type = variant.build_type;
                if (variant.patchset) {
                    const auto patchset = test::read_support_file(std::filesystem::path{"17559"} /
                                                                      "bin" / variant.patchset,
                                                                  kSupportOverride);
                    const auto xell = test::read_support_file(
                        std::filesystem::path{"mydata"} / variant.xell, kSupportOverride);
                    if (!patchset || !xell) {
                        out.problems.push_back(label + ": tracked patch file and XeLL read");
                        out.line = label + " missing-input\n";
                        return out;
                    }
                    InputPatches patches{};
                    patches.automatic = InputPatchFile{variant.patchset, *patchset};
                    input.patches = std::move(patches);
                    if (!input.payloads) {
                        input.payloads = InputPayloads{};
                    }
                    input.payloads->xell = *xell;
                }
                if (variant.smcnocheck) {
                    input.options.smcnocheck = true;
                }
                const auto first = build_pinned(input);
                const auto second = build_pinned(input);
                if (!first || !second) {
                    const auto& error = first ? second.error() : first.error();
                    out.line = label + " error=" + error.message + '\n';
                    out.problems.push_back(label + " builds: " + error.message);
                    return out;
                }
                if (*first != *second) {
                    out.problems.push_back(label + " builds byte-identically twice");
                    out.line = label + " nondeterministic\n";
                    return out;
                }
                out.identical = true;
                char size[32];
                std::snprintf(size, sizeof(size), "0x%zx", first->size());
                out.line = label + " size=" + size + " sha1=" + test::sha1_hex(*first) + '\n';
                out.output = *first;
                return out;
            }

        } // namespace

        const Result<Donor>& donor() {
            static const Result<Donor> cached = load_donor();
            return cached;
        }

        bool all_nonces_filled(const Input& input) {
            const auto& nonces = input.metadata.donor_nonces;
            if (!nonces || !nonces->cf || !nonces->cg) {
                return false;
            }
            for (const auto& stage : nonces->stages) {
                if (!stage) {
                    return false;
                }
            }
            return true;
        }

        const VariantBuild& variant_build(std::size_t index) {
            static std::array<std::optional<VariantBuild>, kVariants> cache;
            auto& slot = cache.at(index);
            if (!slot) {
                if (const auto& loaded = donor(); loaded) {
                    slot = build_variant(*loaded, variants[index]);
                } else {
                    slot = VariantBuild{};
                    slot->problems.push_back(loaded.error().describe());
                }
            }
            return *slot;
        }

    } // namespace mydata

    namespace orchestration_mydata_builds {

        Rendered render() {
            Rendered out;
            out.total = mydata::kVariants;
            if (const auto& loaded = mydata::donor(); !loaded) {
                out.problems.push_back(loaded.error().describe());
                return out;
            }
            for (std::size_t index = 0; index < mydata::kVariants; ++index) {
                const auto& build = mydata::variant_build(index);
                out.text += build.line;
                out.problems.insert(out.problems.end(), build.problems.begin(),
                                    build.problems.end());
                out.identical += build.identical ? 1 : 0;
            }
            return out;
        }

        Result<std::string> render_file() {
            Rendered rendered = render();
            if (!rendered.problems.empty()) {
                return fail(ErrorCode::Internal,
                            "the orchestration_mydata_builds render reports {} problem(s), "
                            "first: {}",
                            rendered.problems.size(), rendered.problems.front());
            }
            return std::move(rendered.text);
        }

    } // namespace orchestration_mydata_builds

    namespace extract_projections_mydata {

        // Every public extract_* projection (tests/support/render/ExtractProjection.hpp) of
        //   mydata.image           image.bin under its CPU key;
        //   mydata.image.zero-key  image.bin under the all-zero CPU key, under which the
        //                          console's keyvault stays sealed (extract_all leaves it out);
        //   mydata.glitch2         the glitch2 rebuild, read back under the CPU key;
        // each extracted twice with identical text. The snapshot pins the CB_B display LDV that
        // extract_all_info reads at +0x3B1 beside the per-box LDV extract_metadata reads, SC
        // decrypted=1 in extract_all_info, and the keyvault summary decode.
        Rendered render() {
            using Bytes = std::vector<uint8_t>;
            constexpr auto kCpuKey = test::kBuildAllCpuKey;
            Rendered out;
            const auto& loaded = mydata::donor();
            if (!loaded) {
                out.problems.push_back(loaded.error().describe());
                return out;
            }
            const Bytes& image = loaded->image;
            const auto& glitch2_output = mydata::variant_build(mydata::kGlitch2).output;

            const std::array<uint8_t, 16> zero_key{};
            struct Case {
                std::string label;
                const Bytes* image;
                std::span<const uint8_t> cpu_key;
            };
            std::vector<Case> cases{
                {"mydata.image", &image, kCpuKey},
                {"mydata.image.zero-key", &image, zero_key},
            };
            if (glitch2_output.has_value()) {
                cases.push_back({"mydata.glitch2", &*glitch2_output, kCpuKey});
            } else {
                out.problems.emplace_back("the glitch2 rebuild exists for its projection");
            }
            out.cases = cases.size();

            std::string& rendered = out.text;
            for (const auto& c : cases) {
                const auto first =
                    test::projection::render_extract_projections(c.label, *c.image, c.cpu_key);
                const auto second =
                    test::projection::render_extract_projections(c.label, *c.image, c.cpu_key);
                out.comparisons += first.comparisons;
                out.agreements += first.agreements;
                for (const auto& what : first.disagreements) {
                    out.problems.push_back(what + " renders the same as the core's span overload");
                }
                if (first.text == second.text) {
                    ++out.stable;
                } else {
                    out.problems.push_back(c.label + " projects identically twice");
                }
                rendered += first.text;
            }
            return out;
        }

        Result<std::string> render_file() {
            Rendered rendered = render();
            if (!rendered.problems.empty()) {
                return fail(ErrorCode::Internal,
                            "the extract_projections_mydata render reports {} problem(s), "
                            "first: {}",
                            rendered.problems.size(), rendered.problems.front());
            }
            return std::move(rendered.text);
        }

    } // namespace extract_projections_mydata

} // namespace gxbuild3::snapshots
