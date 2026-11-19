// tests/golden/flashimage_golden.txt over the tracked donor tests/gxBuild-support-files/mydata/
// image.bin (16 MiB Jasper retail). Runs on a clean clone: it needs no untracked fixture. Lines:
//   parse.*      every nand_header field, every boot stage, the console blocks, the payloads,
//                the filesystem, mobile data, SMC and keyvault right after parse();
//   layout.*     update_slots_end(), patch_slot_offset(), active_payload_block_ranges() and
//                payload_layout() on the parsed image;
//   write.*      SHA-256 of write() straight after parse();
//   decrypt.*    the same snapshot after decrypt_all() under the CPU key of image.bin;
//   roundtrip.*  SHA-256 of write() after parse, decrypt_all and encrypt_all;
//   info.*       extract_all_info()'s KeyvaultSummaryInfo (and its SMC and FlashFS summaries),
//                with Serial and ConsoleId cross-checked against xeBuild's own image.info.
// This is the old FlashImageGoldenTests.cpp main() up to the golden compare, verbatim; its
// check() calls and the render library's checks all go to one RenderChecks, whose failed
// messages are the problems.

#include "FlashImageGoldenRender.hpp"
#include "nand/FlashImage.hpp"
#include "support/Env.hpp"
#include "support/Scratch.hpp"
#include "support/render/FlashImageRender.hpp"

#include <iostream>
#include <sstream>
#include <utility>

namespace gxbuild3::snapshots::flashimage_golden {

    using test::render::build_type_name;
    using test::render::hex32;
    using test::render::kCpuKey;
    using test::render::parsed_image;
    using test::render::render_image;
    using test::render::render_info;
    using test::render::render_layout;
    using test::render::RenderChecks;
    using test::render::sha256;

    Result<Inputs> load_inputs() {
        const std::filesystem::path support = test::support_dir();
        Inputs inputs;
        inputs.image_path = support / "mydata" / "image.bin";
        if (auto override_path = test::env_value(kImageOverride);
            override_path && !override_path->empty()) {
            inputs.image_path = *override_path;
            std::cerr << "note: image overridden by GXBUILD3_FLASHIMAGE_GOLDEN_IMAGE\n";
        }
        auto bytes = test::read_file(inputs.image_path);
        if (!bytes || bytes->empty()) {
            return fail(ErrorCode::NotFound, "cannot read the tracked donor {}",
                        inputs.image_path.string());
        }
        inputs.image = std::move(*bytes);
        const auto info_bytes = test::read_file(support / "mydata" / "image.info");
        if (!info_bytes) {
            return fail(ErrorCode::NotFound, "cannot read the tracked mydata/image.info");
        }
        inputs.image_info.assign(info_bytes->begin(), info_bytes->end());
        return inputs;
    }

    Rendered render(const Inputs& inputs) {
        const test::PinnedBuildTime pinned{"1791105724", "UTC"};
        const auto& bytes = inputs.image;

        std::ostringstream text;
        text << "# FlashImage golden over tracked mydata/image.bin; identities only as SHA-1.\n";
        text << "input.size=" << hex32(bytes.size()) << '\n';
        text << "input.sha256=" << sha256(bytes) << '\n';

        RenderChecks checks;

        // (1)-(3): parse, layout queries, write() straight after parse.
        if (auto img = parsed_image(bytes, checks)) {
            text << render_image(*img, "parse.");
            text << render_layout(*img, &checks);
            const auto written = img->write();
            if (checks.check(written.has_value(), "write() after parse")) {
                text << "write.size=" << hex32(written->size()) << '\n';
                text << "write.sha256=" << sha256(*written) << '\n';
                text << "write.identity=" << (*written == bytes ? 1 : 0) << '\n';
            }
        }

        // (4)-(5): parse, decrypt_all (snapshot), encrypt_all, write().
        if (auto img = parsed_image(bytes, checks)) {
            if (checks.check(img->decrypt_all(kCpuKey), "decrypt_all under the donor's CPU key")) {
                text << render_image(*img, "decrypt.");
                const auto type = img->build_type.value_or(BuildType::Retail);
                text << "roundtrip.encrypt_build_type=" << build_type_name(type) << '\n';
                if (checks.check(img->encrypt_all(kCpuKey, type),
                                 "encrypt_all after decrypt_all")) {
                    const auto written = img->write();
                    if (checks.check(written.has_value(),
                                     "write() after decrypt_all and encrypt_all")) {
                        text << "roundtrip.size=" << hex32(written->size()) << '\n';
                        text << "roundtrip.sha256=" << sha256(*written) << '\n';
                        text << "roundtrip.identity=" << (*written == bytes ? 1 : 0) << '\n';
                    }
                }
            }
        }

        // O0b part (2): the public summary of the same dump.
        text << render_info(bytes, inputs.image_info, checks);

        return {text.str(), checks.count, std::move(checks.problems)};
    }

    Result<std::string> render_file() {
        auto inputs = load_inputs();
        if (!inputs) {
            return std::unexpected(std::move(inputs.error()));
        }
        Rendered rendered = render(*inputs);
        if (!rendered.problems.empty()) {
            return fail(ErrorCode::Internal,
                        "the flashimage_golden render reports {} problem(s), first: {}",
                        rendered.problems.size(), rendered.problems.front());
        }
        return std::move(rendered.text);
    }

} // namespace gxbuild3::snapshots::flashimage_golden
