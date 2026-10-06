#include "BuildRunner.hpp"
#include "Endian.hpp"
#include "ExtractProjection.hpp"
#include "GoldenSnapshot.hpp"
#include "Library.hpp"
#include "ScopedTimeZone.hpp"
#include "TestResult.hpp"
#include "XeRsaTestKey.hpp"
#include "excrypt.h"
#include "nand/FlashDriver.hpp"
#include "nand/FlashImage.hpp"
#include "nand/bootloaders/2bl.hpp"
#include "nand/bootloaders/3bl.hpp"
#include "nand/bootloaders/4bl.hpp"
#include "nand/bootloaders/5bl.hpp"
#include "nand/bootloaders/6bl.hpp"
#include "nand/bootloaders/7bl.hpp"
#include "nand/objects/Keyvault.hpp"
#include "nand/objects/Patchset.hpp"
#include "nand/objects/SMC.hpp"
#include "nand/objects/SecuredFiles.hpp"
#include "utils/XeRsa.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace gxbuild3;
using namespace gxbuild3::nand;

namespace {

    using Bytes = std::vector<uint8_t>;

    // The failed extraction a test takes when the image it extracts from did not build.
    const std::unexpected<gxbuild3::Error>
        not_built(std::in_place, gxbuild3::ErrorCode::InvalidArgument, "the image did not build");

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    bool require(const gxbuild3::Result<>& result, std::string_view message) {
        if (!result) {
            std::cerr << "FAIL: " << message << ": " << result.error().describe() << '\n';
            return false;
        }
        return true;
    }

    // A console's key: the all-zero key, which binds an image to no console, does not count.
    std::array<uint8_t, 16> valid_cpu_key() {
        for (size_t bit_count = 0; bit_count <= 106; ++bit_count) {
            std::array<uint8_t, 16> candidate{};
            for (size_t bit = 0; bit < bit_count; ++bit) {
                candidate[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
            }
            XeCryptUidEccEncode(candidate.data());
            if (!gxbuild3::nand::is_zero_cpu_key(candidate) &&
                gxbuild3::nand::cpukey_valid(candidate)) {
                return candidate;
            }
        }
        std::abort();
    }

    std::array<uint8_t, 16> different_valid_cpu_key(std::span<const uint8_t> reference) {
        std::array<uint8_t, 16> candidate{};
        for (size_t bit = 53; bit < 106; ++bit) {
            candidate[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
        }
        XeCryptUidEccEncode(candidate.data());
        if (gxbuild3::nand::cpukey_valid(candidate) &&
            !std::equal(candidate.begin(), candidate.end(), reference.begin(), reference.end())) {
            return candidate;
        }
        std::abort();
    }

    Bytes make_smc(uint8_t marker) {
        Bytes smc(0x300, marker);
        smc[0x100] = 0x10;
        return smc;
    }

    // The JTAG hack mark D0 00 00 1B, which a JTAG image requires of its SMC.
    void mark_jtag_smc(Bytes& smc) {
        const Bytes mark{0xD0, 0x00, 0x00, 0x1B};
        std::copy(mark.begin(), mark.end(), smc.begin() + 0x200);
    }

    Bytes make_jtag_smc(uint8_t marker) {
        auto smc = make_smc(marker);
        mark_jtag_smc(smc);
        return smc;
    }

    Bytes canonical_keyvault(std::span<const uint8_t> cpu_key, Bytes plaintext) {
        return keyvault_decrypt(cpu_key, keyvault_encrypt(cpu_key, plaintext).value()).value();
    }

    InputBootloaders valid_bootloaders() {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.data.resize(0x380, 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        cb.decrypted = true;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + 0x20);
        cd.header.ce_hash[0] = 1;
        cd.data.resize(0x20, 0x42);
        cd.decrypted = true;

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = cb.serialize();
        bootloaders.cd = cd.serialize();
        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 1;
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + 0x20);
        sc.data.assign(0x20, 0x53);
        sc.decrypted = true;
        bootloaders.sc = sc.serialize();
        return bootloaders;
    }

    Input fresh_input(ImageType image_type) {
        Input input{};
        const auto cpu_key = valid_cpu_key();
        input.image_type = image_type;
        input.metadata.cpu_key.assign(cpu_key.begin(), cpu_key.end());
        input.metadata.smc = make_smc(0x11);
        input.metadata.keyvault =
            canonical_keyvault(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0x22));
        input.bootloaders = valid_bootloaders();
        return input;
    }

    Bytes valid_xell() {
        Bytes bytes(0x40000, 0);
        bytes[0] = 0x7F;
        bytes[1] = 'E';
        bytes[2] = 'L';
        bytes[3] = 'F';
        return bytes;
    }

    std::pair<Bytes, Bytes> valid_system_update(uint8_t marker) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x340, marker);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = false;
        std::fill(std::begin(cf.header.fixpoint_nonce), std::end(cf.header.fixpoint_nonce),
                  static_cast<uint8_t>(marker + 1));

        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.version = 1;
        cg.header.source_size = 0;
        cg.data.assign(0x40, marker);
        cg.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg.data.size());
        cg.decrypted = false;
        return {cf.serialize(), cg.serialize()};
    }

    // run_build opens a supplied sealed CG and seals it again under a new nonce, so a CG is
    // compared by what it carries: its plaintext, with the nonce at +0x10 cleared.
    std::optional<Bytes> opened_cg(const Bytes& cf_bytes, const Bytes& cg_bytes) {
        auto cf = BootloaderCf::parse_or_throw(cf_bytes);
        if (!cf.is_decrypted()) {
            cf.decrypt_or_throw(key_1bl);
        }
        const auto key = cf.cg_key();
        if (!key || cg_bytes.size() < sizeof(cg_header)) {
            return std::nullopt;
        }
        auto cg = test::must(BootloaderCg::parse(cg_bytes));
        if (!cg.decrypted) {
            test::must(cg.decrypt(key->data()));
        }
        auto opened = cg.serialize();
        std::fill(opened.begin() + 0x10, opened.begin() + 0x20, 0);
        return opened;
    }

    Bytes decrypted_cf(uint8_t lockdown_value, std::array<uint8_t, 3> pairing_data,
                       uint16_t source_version = 0, uint16_t source_qfe = 0,
                       uint16_t target_version = 0, uint16_t target_qfe = 0, uint32_t reserved = 0,
                       uint32_t cg_size = 0) {
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.header.source_version = source_version;
        cf.header.source_qfe = source_qfe;
        cf.header.target_version = target_version;
        cf.header.target_qfe = target_qfe;
        cf.header.reserved = reserved;
        cf.header.cg_size = cg_size;
        cf.data.assign(0x340, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        if (!cf.parse_perbox()) {
            std::abort();
        }
        cf.perbox->lockdown_value = lockdown_value;
        std::copy(pairing_data.begin(), pairing_data.end(), cf.perbox->pairing_data);
        if (!cf.serialize_perbox()) {
            std::abort();
        }
        return cf.serialize();
    }

    bool has_big_endian_pairing(std::span<const uint8_t> bytes) {
        return bytes.size() >= sizeof(generic_header) && bytes[4] == 0x12 && bytes[5] == 0x34;
    }

    void append_be32(Bytes& bytes, uint32_t value) {
        bytes.push_back(static_cast<uint8_t>(value >> 24));
        bytes.push_back(static_cast<uint8_t>(value >> 16));
        bytes.push_back(static_cast<uint8_t>(value >> 8));
        bytes.push_back(static_cast<uint8_t>(value));
    }

    uint32_t read_be32(std::span<const uint8_t> bytes, size_t offset) {
        return (static_cast<uint32_t>(bytes[offset]) << 24) |
               (static_cast<uint32_t>(bytes[offset + 1]) << 16) |
               (static_cast<uint32_t>(bytes[offset + 2]) << 8) |
               static_cast<uint32_t>(bytes[offset + 3]);
    }

    uint32_t align_16(uint32_t value) {
        return (value + 0x0F) & ~uint32_t{0x0F};
    }

    bool zero_between(std::span<const uint8_t> bytes, size_t begin, size_t end) {
        return end <= bytes.size() &&
               std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(begin),
                           bytes.begin() + static_cast<std::ptrdiff_t>(end),
                           [](uint8_t byte) { return byte == 0; });
    }

    uint16_t read_be16(std::span<const uint8_t> bytes, size_t offset) {
        return static_cast<uint16_t>((static_cast<uint16_t>(bytes[offset]) << 8) |
                                     static_cast<uint16_t>(bytes[offset + 1]));
    }

    uint64_t read_be64(std::span<const uint8_t> bytes, size_t offset) {
        return (static_cast<uint64_t>(bytes[offset]) << 56) |
               (static_cast<uint64_t>(bytes[offset + 1]) << 48) |
               (static_cast<uint64_t>(bytes[offset + 2]) << 40) |
               (static_cast<uint64_t>(bytes[offset + 3]) << 32) |
               (static_cast<uint64_t>(bytes[offset + 4]) << 24) |
               (static_cast<uint64_t>(bytes[offset + 5]) << 16) |
               (static_cast<uint64_t>(bytes[offset + 6]) << 8) |
               static_cast<uint64_t>(bytes[offset + 7]);
    }

    Bytes glitch_patchset(uint32_t first_address, uint32_t first_word, uint32_t cd_address,
                          uint32_t cd_word, std::span<const uint8_t> khv) {
        Bytes bytes;
        append_be32(bytes, first_address);
        append_be32(bytes, 1);
        append_be32(bytes, first_word);
        append_be32(bytes, 0xFFFFFFFF);
        append_be32(bytes, cd_address);
        append_be32(bytes, 1);
        append_be32(bytes, cd_word);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), khv.begin(), khv.end());
        return bytes;
    }

    Bytes jtag_patchset(std::span<const uint8_t> section4) {
        Bytes bytes(4, 0x10);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x11);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), 4, 0x12);
        append_be32(bytes, 0xFFFFFFFF);
        bytes.insert(bytes.end(), section4.begin(), section4.end());
        return bytes;
    }

    std::optional<Bytes> read_logical(std::span<const uint8_t> image, size_t offset,
                                      size_t length) {
        auto parsed = FlashImage::read(Bytes(image.begin(), image.end()));
        if (!parsed || !parsed->parse()) {
            return std::nullopt;
        }
        const auto bytes = std::as_const(parsed->flash_driver).read_offset(offset, length);
        return Bytes(bytes.begin(), bytes.end());
    }

    bool test_glitch_patches_resize_cb_and_cd_and_update_declared_sizes() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        const uint32_t cb_patch_address =
            static_cast<uint32_t>(input.bootloaders.cb_or_a.size() + 0x10);
        const uint32_t cd_patch_address = static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(cb_patch_address, 0xA1B2C3D4,
                                                        cd_patch_address, 0x10203040, Bytes{0x91})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value(), "patched glitch image builds and extracts")) {
            return false;
        }

        const auto& cb = extracted->bootloaders.cb_or_a;
        const auto& cd = extracted->bootloaders.cd;
        const uint32_t cb_end = align_16(cb_patch_address + 4);
        const uint32_t cd_end = align_16(cd_patch_address + 4);
        return require(cb.size() >= cb_patch_address + 4 &&
                           read_be32(cb, cb_patch_address) == 0xA1B2C3D4,
                       "CB grows to and contains the greatest patched end") &&
               require(read_be32(cb, 0x0C) == cb_end,
                       "CB declared size is the patched end rounded up to 0x10") &&
               require(zero_between(cb, cb_patch_address + 4, cb_end),
                       "CB padding after the patched end is zero") &&
               require(cd.size() >= cd_patch_address + 4 &&
                           read_be32(cd, cd_patch_address) == 0x10203040,
                       "CD grows to and contains the greatest patched end") &&
               require(read_be32(cd, 0x0C) == cd_end,
                       "CD declared size is the patched end rounded up to 0x10") &&
               require(zero_between(cd, cd_patch_address + 4, cd_end),
                       "CD padding after the patched end is zero");
    }

    // Glitch2m CD 9452: 0x5290 bytes, patched to 0x52A8, states 0x52B0 (xeBuild 1.21).
    bool test_glitch2m_cd_patch_states_the_16_byte_aligned_size() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch2m;
        input.bootloaders.cb_b = input.bootloaders.cb_or_a;
        const uint32_t cd_size = static_cast<uint32_t>(input.bootloaders.cd.size());
        const uint32_t cd_patch_address = cd_size + 0x14;
        InputPatches patches{};
        patches.automatic = InputPatchFile{
            "automatic", glitch_patchset(0x20, 0, cd_patch_address, 0x5A5A5A5A, Bytes{0x93})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value(), "patched glitch2m image builds and extracts")) {
            return false;
        }
        const auto& cd = extracted->bootloaders.cd;
        const uint32_t cd_end = align_16(cd_patch_address + 4);
        return require(cd_end != cd_patch_address + 4, "fixture patch ends off a 0x10 boundary") &&
               require(read_be32(cd, 0x0C) == cd_end && cd.size() == cd_end,
                       "glitch2m CD states and carries the 16-byte-aligned patched size") &&
               require(read_be32(cd, cd_patch_address) == 0x5A5A5A5A,
                       "glitch2m CD carries the patched word") &&
               require(zero_between(cd, cd_patch_address + 4, cd_end),
                       "glitch2m CD padding inside the stated size is zero");
    }

    bool test_glitch2_targets_cbb() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch2;
        input.bootloaders.cb_b = input.bootloaders.cb_or_a;
        const uint32_t cbb_patch_address =
            static_cast<uint32_t>(input.bootloaders.cb_b->size() + 0x10);
        InputPatches patches{};
        patches.automatic = InputPatchFile{
            "automatic", glitch_patchset(cbb_patch_address, 0xCAFEBABE, 0x30, 0, Bytes{0x92})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value() && extracted->bootloaders.cb_b.has_value(),
                     "Glitch2 CBB image builds and extracts")) {
            return false;
        }
        return require(extracted->bootloaders.cb_b->size() >= cbb_patch_address + 4 &&
                           read_be32(*extracted->bootloaders.cb_b, cbb_patch_address) == 0xCAFEBABE,
                       "Glitch2 applies section one to CBB") &&
               require(read_be32(*extracted->bootloaders.cb_b, 0x0C) ==
                           align_16(cbb_patch_address + 4),
                       "CBB declared size is the patched end rounded up to 0x10");
    }

    // A clean retail SMC: motherboard nibble at 0x100, the reboot site "05 ?? E5 ?? B4 05"
    // at 0x180, and the four zero bytes every plaintext SMC ends in.
    constexpr size_t kSmcRebootSite = 0x180;

    Bytes clean_retail_smc() {
        Bytes smc(0x300, 0x11);
        smc[0x100] = 0x40;
        const std::array<uint8_t, 6> site{0x05, 0x6C, 0xE5, 0x2A, 0xB4, 0x05};
        std::copy(site.begin(), site.end(), smc.begin() + kSmcRebootSite);
        std::fill(smc.end() - 4, smc.end(), uint8_t{0});
        return smc;
    }

    // Glitch, glitch2 and glitch2m take the reboot patch on a clean retail SMC: the two bytes
    // at the site become zero and nothing else changes.
    bool test_glitch_types_patch_a_clean_retail_smc() {
        for (const auto& [build_type, name] :
             {std::pair{BuildType::Glitch, "glitch"}, std::pair{BuildType::Glitch2, "glitch2"},
              std::pair{BuildType::Glitch2m, "glitch2m"}}) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = build_type;
            input.metadata.smc = clean_retail_smc();
            if (build_type != BuildType::Glitch) {
                input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            }
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0x94})};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            auto image = built ? FlashImage::read(*built) : std::nullopt;
            if (!require(image && image->parse() && image->smc,
                         std::string(name) + " image builds with an SMC")) {
                return false;
            }
            image->smc->decrypt();
            auto expected = clean_retail_smc();
            expected[kSmcRebootSite] = 0x00;
            expected[kSmcRebootSite + 1] = 0x00;
            if (!require(image->smc->data == expected,
                         std::string(name) +
                             " zeroes the two reboot-site bytes and nothing else")) {
                return false;
            }
        }
        return true;
    }

    bool test_noblpatch_skips_bootloader_mutation_but_writes_khv() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        input.options.noblpatch = true;
        const auto original_cb_size = input.bootloaders.cb_or_a.size();
        InputPatches patches{};
        patches.automatic = InputPatchFile{
            "automatic", glitch_patchset(static_cast<uint32_t>(original_cb_size + 0x10), 0xDEADBEEF,
                                         0x30, 0, Bytes{0xA0, 0xA1})};
        patches.addons = {{"addon", {0xA2}}};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        const auto khv = built ? read_logical(*built, 0x80010, 3) : std::nullopt;
        return require(extracted.has_value() &&
                           extracted->bootloaders.cb_or_a.size() == original_cb_size,
                       "noblpatch leaves CB size unchanged") &&
               require(khv == Bytes({0xA0, 0xA1, 0xA2}),
                       "noblpatch still writes merged KHV at the runtime anchor");
    }

    // nopatch names the stages left unpatched: cb keeps the CB, cd the CD, khv the KHV payload.
    bool test_nopatch_skips_only_the_named_stages() {
        struct Case {
            const char* options;
            bool cb_patched;
            bool cd_patched;
            bool khv_written;
        };
        for (const auto& test_case :
             {Case{"nopatch=cb", false, true, true}, Case{"nopatch=cd", true, false, true},
              Case{"nopatch=khv", true, true, false},
              Case{"nopatch=cb,nopatch=khv", false, true, false}}) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch;
            OptionsManager options;
            if (!require(options.parse(test_case.options), "nopatch options parse")) {
                return false;
            }
            input.options = options.data();
            const uint32_t cb_patch_address =
                static_cast<uint32_t>(input.bootloaders.cb_or_a.size() + 0x10);
            const uint32_t cd_patch_address =
                static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
            const auto original_cb_size = input.bootloaders.cb_or_a.size();
            const auto original_cd_size = input.bootloaders.cd.size();
            InputPatches patches{};
            patches.automatic = InputPatchFile{
                "automatic", glitch_patchset(cb_patch_address, 0xA1B2C3D4, cd_patch_address,
                                             0x10203040, Bytes{0xA0, 0xA1})};
            patches.addons = {{"addon", {0xA2}}};
            input.patches = std::move(patches);

            const auto built = run_build(input);
            const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
            const auto khv = built ? read_logical(*built, 0x80010, 3) : std::nullopt;
            if (!require(extracted.has_value(),
                         std::string(test_case.options) + " image builds and extracts") ||
                !require((extracted->bootloaders.cb_or_a.size() != original_cb_size) ==
                             test_case.cb_patched,
                         std::string(test_case.options) + " leaves exactly the named CB alone") ||
                !require((extracted->bootloaders.cd.size() != original_cd_size) ==
                             test_case.cd_patched,
                         std::string(test_case.options) + " leaves exactly the named CD alone") ||
                !require((khv == Bytes({0xA0, 0xA1, 0xA2})) == test_case.khv_written,
                         std::string(test_case.options) +
                             " writes the KHV payload only if unnamed")) {
                return false;
            }
        }
        return true;
    }

    bool test_jtag_patchset_is_serialized_at_fixed_region() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        input.metadata.smc = make_jtag_smc(0x11);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x13})};
        patches.addons = {{"first", {0x20}}, {"second", {0x30}}};
        input.patches = std::move(patches);

        Bytes expected(4, 0x10);
        append_be32(expected, 0xFFFFFFFF);
        expected.insert(expected.end(), 4, 0x11);
        append_be32(expected, 0xFFFFFFFF);
        expected.insert(expected.end(), 4, 0x12);
        append_be32(expected, 0xFFFFFFFF);
        expected.insert(expected.end(), {0x13, 0x13, 0x20, 0x30});

        const auto built = run_build(input);
        const auto raw = built ? read_logical(*built, 0x91000, expected.size()) : std::nullopt;
        return require(built.has_value(), "JTAG patchset image builds") &&
               require(raw == expected, "merged JTAG patchset is byte-exact at 0x91000");
    }

    bool test_jtag_flows_payload_and_extra_bootloaders() {
        // Plaintext stages, as the release ships them: a CB whose 0x260..0x380 is zero and a
        // CD stating a CE hash with no 6BL nonce.
        BootloaderCb extra_cb{};
        extra_cb.header.header.magic = NANDBootloaderMagic::CB;
        extra_cb.header.header.version = 4579;
        extra_cb.data.resize(0x380, 0);
        extra_cb.data.resize(0x400, 0x71);
        extra_cb.header.header.size =
            static_cast<uint32_t>(sizeof(generic_header) + extra_cb.data.size());
        BootloaderCd extra_cd{};
        extra_cd.header.header.magic = NANDBootloaderMagic::CD;
        extra_cd.header.header.version = 8453;
        extra_cd.header.ce_hash[0] = 1;
        extra_cd.data.resize(0x100, 0x72);
        extra_cd.header.header.size =
            static_cast<uint32_t>(sizeof(cd_header) + extra_cd.data.size());
        const Bytes cb_bytes = extra_cb.serialize();
        const Bytes cd_bytes = extra_cd.serialize();

        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        input.metadata.smc = make_jtag_smc(0x11);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x13})};
        input.patches = std::move(patches);
        input.bootloaders.extra_cb = cb_bytes;
        input.bootloaders.extra_cd = cd_bytes;
        InputPayloads payloads{};
        payloads.payload = Bytes(0x200, 0x73);
        input.payloads = std::move(payloads);

        // Small-block window base is 0x90000, so the window tail starts at 0x90000 + 0x45060.
        const size_t cb_at = 0xD5060;
        const size_t cd_at = cb_at + ((cb_bytes.size() + 0x0F) & ~size_t{0x0F});
        const auto built = run_build(input);
        const auto placed_payload = built ? read_logical(*built, 0x200, 0x200) : std::nullopt;
        const auto placed_cb = built ? read_logical(*built, cb_at, cb_bytes.size()) : std::nullopt;
        const auto placed_cd = built ? read_logical(*built, cd_at, cd_bytes.size()) : std::nullopt;
        const auto main_cb = built ? read_logical(*built, 0x8000, 0x20) : std::nullopt;
        // The second chain is sealed: each stage keeps its clear header and takes the main
        // chain's CB or CD nonce, and its body no longer reads as the plaintext supplied.
        const auto same = [](const std::optional<Bytes>& left, size_t left_at, const Bytes& right,
                             size_t right_at, size_t length) {
            return left && left->size() >= left_at + length && right.size() >= right_at + length &&
                   std::equal(left->begin() + left_at, left->begin() + left_at + length,
                              right.begin() + right_at);
        };
        return require(built.has_value(),
                       "JTAG image carrying payload and extra bootloaders builds") &&
               require(placed_payload == Bytes(0x200, 0x73), "SMC payload is placed at 0x200") &&
               require(same(placed_cb, 0, cb_bytes, 0, 0x10),
                       "extra CB is placed in the JTAG window tail with its clear header") &&
               require(main_cb && same(placed_cb, 0x10, *main_cb, 0x10, 0x10),
                       "extra CB takes the main CB's nonce") &&
               require(!same(placed_cb, 0x380, cb_bytes, 0x380, 0x80),
                       "extra CB is sealed, not written as supplied") &&
               require(same(placed_cd, 0, cd_bytes, 0, 0x10),
                       "extra CD follows the 16-byte-aligned extra CB") &&
               require(!same(placed_cd, 0x20, cd_bytes, 0x20, 0x100),
                       "extra CD is sealed, not written as supplied");
    }

    // xeBuild programs the bytes after each JTAG window item zero up to the next item or the end
    // of the 16 KiB block holding the item's end. The patch buffer is programmed whole, so its
    // erased tail is written as pages that carry a spare stamp.
    bool test_jtag_window_padding_is_programmed_like_xebuild() {
        BootloaderCb extra_cb{};
        extra_cb.header.header.magic = NANDBootloaderMagic::CB;
        extra_cb.header.header.version = 4579;
        extra_cb.data.resize(0x380, 0);
        extra_cb.data.resize(0x400, 0x71);
        extra_cb.header.header.size =
            static_cast<uint32_t>(sizeof(generic_header) + extra_cb.data.size());
        BootloaderCd extra_cd{};
        extra_cd.header.header.magic = NANDBootloaderMagic::CD;
        extra_cd.header.header.version = 8453;
        extra_cd.header.ce_hash[0] = 1;
        extra_cd.data.resize(0x100, 0x72);
        extra_cd.header.header.size =
            static_cast<uint32_t>(sizeof(cd_header) + extra_cd.data.size());
        const Bytes cb_bytes = extra_cb.serialize();
        const Bytes cd_bytes = extra_cd.serialize();

        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        input.metadata.smc = make_jtag_smc(0x11);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x13})};
        input.patches = std::move(patches);
        input.bootloaders.extra_cb = cb_bytes;
        input.bootloaders.extra_cd = cd_bytes;
        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x40, 0x74);
        payloads.payload = Bytes(0x200, 0x73);
        input.payloads = std::move(payloads);

        const size_t cd_at = 0xD5060 + ((cb_bytes.size() + 0x0F) & ~size_t{0x0F});
        const size_t chain_end = cd_at + cd_bytes.size();
        const size_t pad_end = (chain_end + 0x3FFF) & ~size_t{0x3FFF};
        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        if (!require(built.has_value(), "JTAG image with a rebooter and a payload builds") ||
            !require(image.has_value(), "JTAG image with a rebooter reads back") ||
            !require(image->parse(), "JTAG image with a rebooter parses")) {
            return false;
        }
        const auto all_equal = [&image](size_t offset, size_t length, uint8_t value) {
            const auto bytes = std::as_const(image->flash_driver).read_offset(offset, length);
            return bytes.size() == length && std::all_of(bytes.begin(), bytes.end(),
                                                         [value](uint8_t b) { return b == value; });
        };
        const auto spare_stamped = [&image](size_t offset) {
            const auto spare = std::as_const(image->flash_driver).read_page_spare(offset / 0x200);
            return std::any_of(spare.begin(), spare.end(), [](uint8_t b) { return b != 0xFF; });
        };
        const auto payload_spare = std::as_const(image->flash_driver).read_page_spare(1);
        return require(all_equal(0x90040, 0x1000 - 0x40, 0),
                       "the bytes after the rebooter are zero up to the patch list") &&
               require(all_equal(0x91100, 0x94000 - 0x91100, 0),
                       "the bytes after the patch list are zero to the end of its block") &&
               require(all_equal(0x94000, 0x1000, 0xFF),
                       "the patch buffer's tail stays erased data") &&
               require(spare_stamped(0x94000) && spare_stamped(0x94E00),
                       "the patch buffer's erased tail is programmed as pages") &&
               require(!spare_stamped(0x95200),
                       "pages past the patch buffer that nothing writes stay unprogrammed") &&
               require(chain_end < pad_end && all_equal(chain_end, pad_end - chain_end, 0),
                       "the bytes after the second chain are zero to the end of its block") &&
               require(payload_spare.size() == 16 && payload_spare[10] == 0x03 &&
                           payload_spare[11] == 0x50,
                       "the payload page's spare carries xeBuild's 0x03 0x50 at bytes 10 and 11");
    }

    // A JTAG image boots through its SMC's hack: an SMC with no JTAG mark is refused, unless
    // smcnocheck waives the check. A marked SMC, sealed or plaintext, builds.
    bool test_jtag_refuses_a_clean_smc() {
        const auto jtag_input = [](Bytes smc) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            input.metadata.smc = std::move(smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x13})};
            input.patches = std::move(patches);
            return input;
        };
        const auto clean = run_build(jtag_input(make_smc(0x11)));
        auto waived_input = jtag_input(make_smc(0x11));
        waived_input.options.smcnocheck = true;
        const auto waived = run_build(waived_input);
        const auto marked = run_build(jtag_input(make_jtag_smc(0x11)));
        auto cygnos_smc = make_smc(0x11);
        const Bytes cygnos_mark{0x78, 0xBA, 0xB6};
        std::copy(cygnos_mark.begin(), cygnos_mark.end(), cygnos_smc.begin() + 0x180);
        const auto sealed = run_build(jtag_input(gxbuild3::nand::smc_encrypt(cygnos_smc)));
        auto retail_input = fresh_input(ImageType::SmallBlock);
        retail_input.build_type = BuildType::Retail;
        const auto retail = run_build(retail_input);
        return require(!clean && clean.error().code == BuildErrorCode::InvalidSmc &&
                           clean.error().message.find("Clean SMC") != std::string::npos,
                       "JTAG over an SMC with no JTAG mark is refused as a clean SMC") &&
               require(waived.has_value(), "smcnocheck builds JTAG over a clean SMC") &&
               require(marked.has_value(), "JTAG builds over a JTAG-marked SMC") &&
               require(sealed.has_value(),
                       "JTAG builds over a sealed SMC carrying the Cygnos mark") &&
               require(retail.has_value(), "the check leaves retail images alone");
    }

    bool test_patch_regions_reject_overflow() {
        auto jtag = fresh_input(ImageType::SmallBlock);
        jtag.build_type = BuildType::Jtag;
        jtag.metadata.smc = make_jtag_smc(0x11);
        InputPatches jtag_patches{};
        jtag_patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes(0x4001, 0x44))};
        jtag.patches = std::move(jtag_patches);
        const auto jtag_result = run_build(jtag);

        auto glitch = fresh_input(ImageType::SmallBlock);
        glitch.build_type = BuildType::Glitch;
        InputPatches glitch_patches{};
        glitch_patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55))};
        glitch.patches = std::move(glitch_patches);
        const auto glitch_result = run_build(glitch);

        return require(!jtag_result && jtag_result.error().code == BuildErrorCode::PatchFailure,
                       "JTAG patch overflow returns PatchFailure") &&
               require(!glitch_result && glitch_result.error().code == BuildErrorCode::PatchFailure,
                       "glitch patch overflow returns PatchFailure");
    }

    bool test_runbuild_rejects_retail_and_devkit_addon_patch_data() {
        for (const auto build_type : {BuildType::Retail, BuildType::Devkit}) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = build_type;
            input.patches = InputPatches{.automatic = std::nullopt,
                                         .addons = {InputPatchFile{"addon", {0x01}}}};
            const auto result = run_build(input);
            if (!require(!result && result.error().code == BuildErrorCode::InvalidInput,
                         "run_build rejects retail and devkit add-on patch data")) {
                return false;
            }
        }
        return true;
    }

    bool test_glitch_patch_region_does_not_overwrite_mobile_data() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0, 0xA1, 0xA2})};
        input.patches = std::move(patches);

        // Every blob type, each a full block, laid from the first free block.
        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            Bytes expected_mobile(0x4000);
            for (size_t index = 0; index < expected_mobile.size(); ++index) {
                expected_mobile[index] = static_cast<uint8_t>((index * 17U + block_type) & 0xFFU);
            }
            *input.mobiles.slot(block_type) = std::move(expected_mobile);
        }

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value(), "glitch image with mobile data extracts")) {
            return false;
        }
        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            if (!require(*extracted->mobiles.slot(block_type) == *input.mobiles.slot(block_type),
                         "glitch patch reservation prevents overwriting mobile data")) {
                return false;
            }
        }
        return true;
    }

    bool test_glitch_patch_uses_header_overlay_anchor() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);

        const auto built = run_build(input);
        const auto khv = built ? read_logical(*built, 0xC0010, 1) : std::nullopt;
        const auto xell_magic = built ? read_logical(*built, 0x70000, 4) : std::nullopt;
        return require(built.has_value(), "glitch patch and XeLL image builds") &&
               require(khv == Bytes({0xA0}),
                       "glitch KHV starts at header update base plus stride plus 0x10") &&
               require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                       "glitch patch placement preserves XeLL");
    }

    bool test_bigblock_glitch_uses_big_patch_stride() {
        auto input = fresh_input(ImageType::BigBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes(0x10000, 0xB4))};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        // With no XeLL the first slot is the chain's end rounded up by 0x20000, which is 0x80000,
        // and the overlay one 0x20000 stride above it.
        const auto first = built ? read_logical(*built, 0xA0010, 1) : std::nullopt;
        return require(built.has_value(), "big-block glitch accepts payload above small stride") &&
               require(first == Bytes({0xB4}), "big-block KHV uses the second-slot overlay");
    }

    bool test_glitch_patch_is_disjoint_from_rebooter_without_xell() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x1000, 0x71);
        input.payloads = std::move(payloads);

        const auto built = run_build(input);
        return require(built.has_value(), "fixed KHV anchor is disjoint from the rebooter") &&
               require(read_logical(*built, 0x80010, 1) == Bytes{0xA0},
                       "KHV stays at runtime anchor");
    }

    bool test_jtag_xell_without_rebooter_preserves_patches_and_uses_fixed_offset() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        mark_jtag_smc(*input.metadata.smc);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x14})};
        input.patches = patches;
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);

        const auto merged = parse_and_merge_patch_set(patches, BuildType::Jtag);
        const auto expected = merged ? serialize_patch_set(*merged) : Bytes{};
        const auto built = run_build(input);
        const auto written_patch =
            built ? read_logical(*built, 0x91000, expected.size()) : std::nullopt;
        const auto xell_magic = built ? read_logical(*built, 0x95060, 4) : std::nullopt;
        return require(built.has_value(), "JTAG patch plus XeLL image builds") &&
               require(written_patch == expected, "JTAG patch bytes survive beside XeLL") &&
               require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                       "JTAG XeLL always starts at 0x95060");
    }

    bool test_glitch_xell_shifts_patchslots_on_small_and_big_layouts() {
        for (auto image_type : {ImageType::SmallBlock, ImageType::BigBlock, ImageType::Emmc}) {
            auto input = fresh_input(image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0,
                                                            Bytes{0, 0, 0x10, 0, 0, 0, 0, 1, 0x60,
                                                                  0, 0, 0, 255, 255, 255, 255})};
            input.patches = patches;
            input.payloads = InputPayloads{};
            input.payloads->xell = valid_xell();
            auto [cf, cg] = valid_system_update(0x61);
            input.bootloaders.cf0 = cf;
            input.bootloaders.cg0 = cg;
            auto built = run_build(input);
            // XeLL sits at 0x70000 on every shape and the slots follow it, rounded up by the
            // erase block: 0xB0000, or 0xC0000 on big block, whose slot is 0x20000 long.
            const size_t base = image_type == ImageType::BigBlock ? 0xC0000 : 0xB0000;
            const size_t stride = image_type == ImageType::BigBlock ? 0x20000 : 0x10000;
            const size_t xell_at = 0x70000;
            if (!require(built.has_value(), "one update slot and runtime overlay build") ||
                !require(read_logical(*built, base + stride + 0x10, 4) == Bytes({0, 0, 0x10, 0}),
                         "KHV matches CD header anchor") ||
                !require(read_logical(*built, xell_at, 0x40000) == input.payloads->xell,
                         "XeLL sits at 0x70000"))
                return false;
            auto extracted = extract_all(*built, input.metadata.cpu_key);
            if (!require(extracted && extracted->patches &&
                             extracted->build_type == BuildType::Glitch,
                         "extraction preserves the runtime patch stream and build type"))
                return false;
            auto rebuilt = run_build(*extracted);
            if (!require(rebuilt &&
                             read_logical(*rebuilt, base + stride + 0x10, 4) ==
                                 Bytes({0, 0, 0x10, 0}) &&
                             read_logical(*rebuilt, xell_at, 0x40000) == input.payloads->xell,
                         "extract/rebuild preserves XeLL and the KHV anchor"))
                return false;
            input.bootloaders.cf1 = cf;
            input.bootloaders.cg1 = cg;
            auto conflict = run_build(input);
            if (!require(!conflict && conflict.error().message.find("second update slot") !=
                                          std::string::npos,
                         "CF1 cannot occupy the glitch overlay"))
                return false;
        }
        return true;
    }

    bool test_small_glitch_xell_rejects_fixed_payload_collisions() {
        struct Case {
            std::string_view name;
            bool add_rebooter;
            bool add_fuses;
            std::string_view collided_payload;
        };
        const std::array cases{Case{"rebooter", true, false, "rebooter"},
                               Case{"virtual fuses", false, true, "virtual-fuse"}};

        for (const auto& test_case : cases) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            if (test_case.add_rebooter) {
                payloads.rebooter = Bytes(0x1000, 0x71);
            }
            if (test_case.add_fuses) {
                payloads.fuses = Bytes(0x60, 0x72);
            }
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            if (!require(!built && built.error().code == BuildErrorCode::InvalidInput,
                         "small-block Glitch rejects overlapping fixed payloads") ||
                !require(!built || built.error().message.find(test_case.collided_payload) !=
                                       std::string::npos,
                         "fixed-payload collision identifies the overwritten payload")) {
                return false;
            }
        }
        return true;
    }

    bool test_donor_transition_rejects_retained_glitch_xell_collision() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        donor_input.build_type = BuildType::Jtag;
        mark_jtag_smc(*donor_input.metadata.smc);
        InputPatches donor_patches{};
        donor_patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA1})};
        donor_input.patches = std::move(donor_patches);
        InputPayloads donor_payloads{};
        donor_payloads.rebooter = Bytes(0x1000, 0x71);
        donor_payloads.fuses = Bytes(0x60, 0x72);
        donor_payloads.xell = valid_xell();
        donor_input.payloads = std::move(donor_payloads);
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "adjacent JTAG donor payload layout builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA2})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        return require(!built && built.error().code == BuildErrorCode::InvalidInput,
                       "donor transition rejects retained payload collision") &&
               require(!built || built.error().message.find("XeLL overlaps rebooter") !=
                                     std::string::npos,
                       "donor transition reports the retained XeLL and rebooter collision");
    }

    bool test_fixed_payloads_roundtrip_in_valid_jtag_layout() {
        struct Case {
            ImageType image_type;
            BuildType build_type;
            InputPatchFile automatic;
            size_t xell_offset;
        };
        const std::array cases{
            Case{ImageType::SmallBlock, BuildType::Jtag,
                 InputPatchFile{"automatic", jtag_patchset(Bytes{0xA3})}, 0x95060},

        };

        for (const auto& test_case : cases) {
            const std::string layout_name =
                test_case.build_type == BuildType::Jtag ? "JTAG" : "big-block Glitch";
            auto input = fresh_input(test_case.image_type);
            input.build_type = test_case.build_type;
            if (input.build_type == BuildType::Jtag) {
                mark_jtag_smc(*input.metadata.smc);
            }
            InputPatches patches{};
            patches.automatic = test_case.automatic;
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            payloads.fuses = Bytes(0x60, 0x72);
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            const auto rebooter =
                built ? read_logical(*built, 0x90000, input.payloads->rebooter->size())
                      : std::nullopt;
            const auto fuses =
                built ? read_logical(*built, 0x95000, input.payloads->fuses->size()) : std::nullopt;
            const auto xell_magic =
                built ? read_logical(*built, test_case.xell_offset, 4) : std::nullopt;
            if (!require(built.has_value(), layout_name + " fixed payload layout builds") ||
                !require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                         layout_name + " keeps XeLL at its historical offset") ||
                !require(rebooter == input.payloads->rebooter && fuses == input.payloads->fuses,
                         layout_name + " fixed payload layout roundtrips every payload")) {
                return false;
            }
        }
        return true;
    }

    bool test_small_glitch_patch_base_xell_owns_overlapping_fixed_payload_offsets() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA7})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        payloads.xell->at(0x20000) = 0x47;
        payloads.xell->at(0x25000) = 0x57;
        input.payloads = std::move(payloads);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        return require(
                   extracted.has_value() && extracted->payloads && extracted->payloads->xell &&
                       *extracted->payloads->xell == *input.payloads->xell,
                   "small-block Glitch extract_all retains patch-base XeLL bytes at 0x20000 and "
                   "0x25000") &&
               require(!extracted->payloads->rebooter && !extracted->payloads->fuses,
                       "patch-base XeLL suppresses ambiguous rebooter and fuse inference");
    }

    bool test_patch_base_xell_ownership_never_falls_back_to_an_internal_jtag_elf() {
        const std::array image_types{ImageType::SmallBlock, ImageType::NewSmallBlock};
        for (const auto image_type : image_types) {
            auto input = fresh_input(image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xAA})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            auto image = built ? FlashImage::read(*built) : std::nullopt;
            const Bytes invalid_patch_base{0, 0, 0, 0};
            const Bytes false_jtag_elf{0x7F, 'E', 'L', 'F'};
            const Bytes false_rebooter{0xAB};
            const Bytes false_fuses{0xAC};
            const bool modified = image && image->parse() &&
                                  image->flash_driver.write_offset(0x70000, invalid_patch_base) &&
                                  image->flash_driver.write_offset(0x90000, false_rebooter) &&
                                  image->flash_driver.write_offset(0x95000, false_fuses) &&
                                  image->flash_driver.write_offset(0x95060, false_jtag_elf);
            const auto extracted =
                modified ? extract_all(image->flash_driver.serialize(), input.metadata.cpu_key)
                         : not_built;

            if (!require(modified, "shifted patch-base XeLL fixture is modified successfully") ||
                !require(extracted.has_value() &&
                             (!extracted->payloads ||
                              (!extracted->payloads->xell && !extracted->payloads->rebooter &&
                               !extracted->payloads->fuses)),
                         "patch-base XeLL ownership does not invent JTAG or overlapping fixed "
                         "payloads")) {
                return false;
            }
        }
        return true;
    }

    bool test_big_and_emmc_glitch_do_not_infer_jtag_inside_xell() {
        for (auto image_type : {ImageType::BigBlock, ImageType::Emmc}) {
            auto input = fresh_input(image_type);
            input.build_type = BuildType::Glitch;
            input.patches = InputPatches{};
            const Bytes khv{0, 0, 0x10, 0, 0, 0, 0, 1, 0x60, 0, 0, 0, 255, 255, 255, 255};
            input.patches->automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, khv)};
            input.payloads = InputPayloads{};
            input.payloads->xell = valid_xell();
            auto built = run_build(input);
            auto image = built ? FlashImage::read(*built) : std::nullopt;
            if (!require(image && image->parse(), "glitch donor with runtime KHV parses"))
                return false;
            if (!require(image->flash_driver.write_offset(0x70000, Bytes{0, 0, 0, 0}) &&
                             image->flash_driver.write_offset(0x95060, valid_xell()),
                         "the stale JTAG anchors are laid"))
                return false;
            auto extracted = extract_all(image->flash_driver.serialize(), input.metadata.cpu_key);
            if (!require(extracted && (!extracted->payloads || !extracted->payloads->xell),
                         "known glitch image cannot infer JTAG XeLL inside its damaged payload"))
                return false;
        }
        return true;
    }

    bool test_bigblock_glitch_xell_anchors_at_patch_base_and_shifts_cf() {
        for (const auto image_type : {ImageType::BigBlock, ImageType::Emmc}) {
            auto input = fresh_input(image_type);
            input.build_type = BuildType::Glitch2;
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            const auto [cf, cg] = valid_system_update(0x61);
            input.bootloaders.cf0 = cf;
            input.bootloaders.cg0 = cg;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA5})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            if (!require(built.has_value(),
                         "big-geometry glitch carrying a XeLL builds without a collision")) {
                return false;
            }
            auto image = FlashImage::read(*built);
            const bool parsed = image && image->parse();
            constexpr size_t xell_at = 0x70000;
            const bool big = image_type == ImageType::BigBlock;
            const size_t stride = big ? 0x20000 : 0x10000;
            const size_t shifted_slot = big ? 0xC0000 : 0xB0000;
            const auto xell_magic = read_logical(*built, xell_at, 4);
            const auto khv = read_logical(*built, shifted_slot + stride + 0x10, 1);
            const auto cg_bytes =
                read_logical(*built, shifted_slot + ((cf.size() + 0x0F) & ~0x0F), cg.size());
            if (!require(parsed && image->system_update_0.cf.has_value() &&
                             image->system_update_0.cg.has_value(),
                         "big-geometry glitch parses CF and CG out of the shifted patch slot") ||
                !require(image->header.cf_offset == shifted_slot,
                         "the XeLL pushes the first slot to the next erase-block boundary") ||
                !require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                         "big-geometry glitch XeLL sits at 0x70000") ||
                !require(khv == Bytes({0xA5}),
                         "glitch KHV follows the shifted slot plus one stride plus 0x10") ||
                !require(cg_bytes &&
                             opened_cg(cf, cg) ==
                                 opened_cg(image->system_update_0.cf->serialize(), *cg_bytes),
                         "CG survives beside the anchored XeLL")) {
                return false;
            }

            const auto extracted = extract_all(*built, input.metadata.cpu_key);
            if (!require(extracted.has_value() && extracted->bootloaders.cf0.has_value(),
                         "the shifted CF0 is recovered by extract_all") ||
                !require(extracted->payloads && extracted->payloads->xell == input.payloads->xell,
                         "the anchored XeLL round-trips byte for byte")) {
                return false;
            }
        }
        return true;
    }

    bool test_unambiguous_jtag_xell_preserves_fixed_payload_extraction() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        mark_jtag_smc(*input.metadata.smc);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA8})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        payloads.rebooter = Bytes(0x1000, 0x81);
        payloads.fuses = Bytes(0x60, 0x82);
        input.payloads = std::move(payloads);

        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        return require(extracted.has_value() && extracted->payloads &&
                           extracted->payloads->xell == input.payloads->xell &&
                           extracted->payloads->rebooter == input.payloads->rebooter &&
                           extracted->payloads->fuses == input.payloads->fuses,
                       "an exact JTAG XeLL preserves adjacent fixed payload extraction");
    }

    bool test_boot_chain_collision_is_rejected_for_unpatched_payload_layouts() {
        struct Case {
            BuildType build_type;
            bool noblpatch;
            bool jtag_patchset;
            size_t xell_offset;
        };
        const std::array cases{Case{BuildType::Retail, false, false, 0x70000},
                               Case{BuildType::Devkit, false, false, 0x70000},
                               Case{BuildType::Jtag, false, true, 0x95060},
                               Case{BuildType::Glitch, true, false, 0x70000}};

        for (const auto& test_case : cases) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = test_case.build_type;
            if (input.build_type == BuildType::Jtag) {
                mark_jtag_smc(*input.metadata.smc);
            }
            input.options.noblpatch = test_case.noblpatch;
            input.bootloaders.cb_or_a.resize(test_case.xell_offset - 0x8000 + 0x10, 0xA9);
            const uint32_t cb_size =
                bswap32(static_cast<uint32_t>(input.bootloaders.cb_or_a.size()));
            std::memcpy(input.bootloaders.cb_or_a.data() + offsetof(generic_header, size), &cb_size,
                        sizeof(cb_size));
            if (test_case.jtag_patchset || test_case.noblpatch) {
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", test_case.jtag_patchset
                                     ? jtag_patchset(Bytes{0xAA})
                                     : glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xAB})};
                input.patches = std::move(patches);
            }
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = run_build(input);
            if (!require(
                    !built && built.error().code == BuildErrorCode::InvalidInput,
                    "oversized unpatched boot chain is rejected before fixed payload overwrite") ||
                !require(!built || built.error().message.find("serialized boot chain") !=
                                       std::string::npos,
                         "boot-chain collision identifies the serialized boot-chain interval")) {
                return false;
            }
        }
        return true;
    }

    bool test_bootloader_patch_end_is_bounded_by_boot_chain_layout() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x70000, 0xDEADBEEF, 0x30, 0, Bytes{0xA0})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        if (!require(!built && built.error().code == BuildErrorCode::PatchFailure,
                     "bootloader patch beyond chain capacity fails before resize")) {
            return false;
        }

        auto hostile = fresh_input(ImageType::SmallBlock);
        hostile.build_type = BuildType::Glitch;
        InputPatches hostile_patches{};
        hostile_patches.automatic = InputPatchFile{
            "hostile", glitch_patchset(0xFFFFFFF8, 0xDEADBEEF, 0x30, 0, Bytes{0xA0})};
        hostile.patches = std::move(hostile_patches);
        const auto hostile_result = run_build(hostile);
        return require(!hostile_result &&
                           hostile_result.error().code == BuildErrorCode::PatchFailure,
                       "near-UINT32_MAX patch end is rejected without allocation");
    }

    Bytes make_donor(const Input& source,
                     std::initializer_list<std::pair<uint8_t, Bytes>> mobiles) {
        FlashImage donor{};
        donor.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        donor.smc = Smc::parse(*source.metadata.smc).value();
        donor.keyvault = Keyvault::parse(*source.metadata.keyvault).value();
        donor.keyvault->encrypted = false;
        if (!donor.keyvault->encrypt(source.metadata.cpu_key)) {
            std::abort();
        }
        donor.cb_section.cb_or_A = BootloaderCb::parse_or_throw(source.bootloaders.cb_or_a);
        donor.cb_section.sc = test::must(BootloaderSc::parse(*source.bootloaders.sc));
        donor.kernel_section.cd = BootloaderCd::parse_or_throw(source.bootloaders.cd);
        if (!donor.encrypt_all(source.metadata.cpu_key)) {
            std::abort();
        }
        donor.mobile_data = MobileData{};
        for (const auto& [block_type, bytes] : mobiles) {
            *donor.mobile_data->get_slot(block_type) = bytes;
        }
        return donor.write().value_or(Bytes{});
    }

    std::optional<FlashImage> parse_image(std::span<const uint8_t> bytes) {
        auto image = FlashImage::read(Bytes(bytes.begin(), bytes.end()));
        if (!image || !image->parse()) {
            return std::nullopt;
        }
        return image;
    }

    bool test_invalid_input_returns_structured_error() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.cpu_key.pop_back();

        const auto built = run_build(input);
        return require(!built.has_value(), "invalid input is rejected") &&
               require(built.error().code == BuildErrorCode::InvalidInput,
                       "invalid input has an InvalidInput build error");
    }

    // An eMMC anchor names four blobs, types 0x31-0x34. Those are laid; 0x35-0x39 are left
    // out with a warning and the build goes on.
    bool emmc_keeps_anchor_mobiles_only(const Input& input, std::string_view what) {
        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        if (!require(built.has_value() && parsed.has_value() && parsed->mobile_data.has_value(),
                     std::string(what) + ": eMMC build with mobile data succeeds")) {
            return false;
        }
        const auto lays_anchor_mobiles =
            std::string(what) + ": eMMC lays mobiles 0x31-0x34 and drops the rest";
        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            const auto* given = input.mobiles.slot(block_type);
            const auto* laid = parsed->mobile_data->get_slot(block_type);
            const bool expected = block_type <= 0x34 && given && *given;
            if (!require(expected ? *laid == *given : !laid->has_value(), lays_anchor_mobiles)) {
                return false;
            }
        }
        return true;
    }

    bool test_emmc_lays_four_anchor_mobiles_and_drops_the_rest() {
        auto input = fresh_input(ImageType::Emmc);
        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            *input.mobiles.slot(block_type) = Bytes(0x800, block_type);
        }
        *input.mobiles.slot(0x32) = Bytes(0x200, 0x32);
        return emmc_keeps_anchor_mobiles_only(input, "fresh eMMC");
    }

    bool test_emmc_donor_lays_four_anchor_mobiles_and_drops_the_rest() {
        const auto donor = run_build(fresh_input(ImageType::Emmc));
        if (!require(donor.has_value(), "eMMC donor fixture builds")) {
            return false;
        }
        // The donor's eMMC geometry wins over the requested small block.
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
            *input.mobiles.slot(block_type) = Bytes{block_type};
        }
        return emmc_keeps_anchor_mobiles_only(input, "eMMC donor");
    }

    bool test_nand_donor_accepts_high_mobile_when_requested_type_is_emmc() {
        auto input = fresh_input(ImageType::Emmc);
        input.metadata.nand_image = make_donor(input, {});
        *input.mobiles.slot(0x33) = Bytes{0x33, 0xCC};

        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        return require(built.has_value(),
                       built ? "NAND donor accepts high mobile input despite requested eMMC"
                             : "NAND donor high mobile build failure: " + built.error().message) &&
               require(parsed.has_value() &&
                           parsed->flash_driver.driver_mode() == Driver::DriverMode::Small,
                       "NAND donor retains its effective geometry") &&
               require(parsed->mobile_data.has_value() &&
                           parsed->mobile_data->x33 == *input.mobiles.slot(0x33),
                       "NAND donor persists the high mobile replacement");
    }

    bool test_donor_overlays_replace_explicit_values_and_preserve_mobile_slots() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = make_donor(input, {{0x31, Bytes{1}}, {0x32, Bytes{2}}});
        input.metadata.smc = make_smc(0xA1);
        input.metadata.keyvault =
            canonical_keyvault(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0xB2));
        *input.mobiles.slot(0x32) = Bytes{9};

        const auto built = run_build(input);
        if (!require(built.has_value(), "donor overlay build succeeds")) {
            return false;
        }
        auto parsed = parse_image(*built);
        if (!require(parsed.has_value(), "built donor image parses")) {
            return false;
        }
        if (!require(parsed->mobile_data.has_value(), "built donor image has mobile data") ||
            !require(parsed->mobile_data->x31 == Bytes{1}, "unmodified donor mobile survives") ||
            !require(parsed->mobile_data->x32 == Bytes{9}, "user mobile replaces donor mobile")) {
            return false;
        }

        if (!require(parsed->decrypt_all(input.metadata.cpu_key),
                     "built donor components decrypt")) {
            return false;
        }
        return require(parsed->smc.has_value() && parsed->smc->data == *input.metadata.smc,
                       "user SMC replaces donor SMC") &&
               require(parsed->keyvault.has_value() &&
                           parsed->keyvault->serialize() == *input.metadata.keyvault,
                       "user keyvault replaces donor keyvault");
    }

    bool test_mobile_overlay_replaces_longer_donor_mobile_without_stale_tail() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x800, 2)}});
        *input.mobiles.slot(0x32) = Bytes(0x200, 9);

        const auto built = run_build(input);
        if (!require(built.has_value(), "long mobile overlay build succeeds")) {
            return false;
        }
        const auto parsed = parse_image(*built);
        if (!require(parsed.has_value() && parsed->mobile_data.has_value() &&
                         parsed->mobile_data->x32.has_value(),
                     "long mobile overlay is present")) {
            return false;
        }
        return require(parsed->mobile_data->x32->size() == input.mobiles.slot(0x32)->value().size(),
                       "shorter replacement mobile retains its requested size") &&
               require(parsed->mobile_data->x32 == *input.mobiles.slot(0x32),
                       "shorter replacement mobile does not retain the donor tail");
    }

    // One copy of a blob fills at most its block on small block; nothing longer can be laid.
    bool test_mobile_overlay_longer_than_one_block_is_refused() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x800, 2)}});
        *input.mobiles.slot(0x32) = Bytes(0x4001, 9);

        const auto built = run_build(input);
        return require(!built.has_value(), "a mobile overlay longer than a block is refused") &&
               require(built.error().code == BuildErrorCode::SerializationFailure,
                       "an over-long mobile reports SerializationFailure") &&
               require(built.error().message.find("Mobile data type 0x32 is 0x4001 bytes") !=
                           std::string::npos,
                       "the writer's reason reaches the BuildError message");
    }

    bool test_extracted_plaintext_keyvault_reencrypts_for_a_fresh_layout() {
        auto source = fresh_input(ImageType::SmallBlock);
        for (size_t i = 0; i < source.metadata.keyvault->size(); ++i) {
            (*source.metadata.keyvault)[i] = static_cast<uint8_t>(i);
        }
        source.metadata.keyvault =
            canonical_keyvault(source.metadata.cpu_key, *source.metadata.keyvault);
        const auto donor = make_donor(source, {});
        auto extracted = extract_all(donor, source.metadata.cpu_key);
        if (!require(extracted.has_value() &&
                         extracted->metadata.keyvault == source.metadata.keyvault,
                     "extraction exposes the canonical plaintext keyvault")) {
            return false;
        }

        extracted->metadata.nand_image.reset();
        const auto rebuilt = run_build(*extracted);
        if (!require(rebuilt.has_value(),
                     "fresh layout rebuild with extracted keyvault succeeds")) {
            return false;
        }
        auto parsed = parse_image(*rebuilt);
        if (!require(parsed.has_value() && parsed->decrypt_all(extracted->metadata.cpu_key),
                     "rebuilt keyvault decrypts")) {
            return false;
        }
        return require(parsed->keyvault.has_value() &&
                           parsed->keyvault->serialize() == *source.metadata.keyvault,
                       "rebuilt keyvault decrypts to the extracted plaintext");
    }

    bool test_donor_rejects_a_different_structurally_valid_cpu_key() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {});

        auto input = source;
        const auto wrong_key = different_valid_cpu_key(source.metadata.cpu_key);
        input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
        input.metadata.nand_image = donor;
        const auto built = run_build(input);
        return require(!built.has_value(), "wrong valid CPU key rejects donor") &&
               require(built.error().code == BuildErrorCode::InvalidDonor,
                       "wrong valid CPU key maps to InvalidDonor");
    }

    bool test_payload_must_match_its_0x200_size_contract() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.payloads = InputPayloads{};
        input.payloads->payload = Bytes{0xC0, 0xDE};

        const auto built = run_build(input);
        return require(!built.has_value(), "mis-sized payload is rejected") &&
               require(built.error().code == BuildErrorCode::InvalidInput,
                       "mis-sized payload returns InvalidInput") &&
               require(built.error().message == "Payload must contain exactly 0x200 bytes",
                       "mis-sized payload explains the 0x200-byte contract");
    }

    bool test_extract_all_preserves_complete_donor_baseline() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {{0x31, Bytes{3}}, {0x39, Bytes{9}}});

        const auto extracted = extract_all(donor, source.metadata.cpu_key);
        return require(extracted.has_value(), "donor baseline extracts") &&
               require(extracted->metadata.nand_image == donor,
                       "extraction retains backing donor image") &&
               require(extracted->image_type == ImageType::SmallBlock,
                       "extraction maps small donor mode to small image type") &&
               require(extracted->metadata.smc.has_value(), "extraction retains donor SMC") &&
               require(extracted->metadata.keyvault.has_value(),
                       "extraction retains donor keyvault") &&
               require(extracted->mobiles.slot(0x31)->value() == Bytes{3},
                       "extraction retains first mobile slot") &&
               require(extracted->mobiles.slot(0x39)->value() == Bytes{9},
                       "extraction retains last mobile slot");
    }

    bool test_extract_some_info_reads_public_nand_metadata_without_cpu_key() {
        auto input = fresh_input(ImageType::BigBlock);

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 5;
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + 0x20);
        ce.data.assign(0x20, 0xCE);
        input.bootloaders.ce = ce.serialize();

        const auto [cf0, cg0] = valid_system_update(0x41);
        input.bootloaders.cf0 = cf0;
        input.bootloaders.cg0 = cg0;

        const auto built = run_build(input);
        const auto info = built ? extract_some_info(*built) : not_built;
        return require(info.has_value(), "public NAND metadata extracts without a CPU key") &&
               require(info->block_type == ImageType::BigBlock,
                       "public NAND metadata reports the detected block type") &&
               require(info->smc.present && !info->smc.version.empty(),
                       "public NAND metadata reports the SMC version") &&
               require(!info->smc.type_name.empty(), "public NAND metadata reports the SMC type") &&
               require(info->bootloaders.cb_a.has_value() && info->bootloaders.cb_a->version == 1,
                       "public NAND metadata reports the bootloader version") &&
               require(info->bootloaders.sc.has_value() && info->bootloaders.sc->version == 1,
                       "public NAND metadata reports the SC version") &&
               require(info->bootloaders.cd.has_value() && info->bootloaders.cd->version == 1,
                       "public NAND metadata reports the kernel version") &&
               require(info->bootloaders.ce.has_value() && info->bootloaders.ce->version == 5,
                       "public NAND metadata reports the hypervisor version") &&
               require(info->bootloaders.cf_0.has_value() && info->bootloaders.cg_0.has_value(),
                       "public NAND metadata reports the update versions") &&
               require(info->cpu_key.empty() && !info->raw_keyvault.has_value() &&
                           !info->keyvault.present,
                       "public NAND metadata omits CPU-key-dependent keyvault data");
    }

    bool test_extract_all_info_reports_the_detected_block_type() {
        const auto input = fresh_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        const auto info = built ? extract_all_info(*built, input.metadata.cpu_key) : not_built;
        return require(info.has_value(), "full NAND metadata extracts") &&
               require(info->block_type == ImageType::NewSmallBlock,
                       "full NAND metadata reports the detected block type");
    }

    // The image with its CD record's header stating 0x20 bytes, which is shorter than a CD header.
    // Empty when the chain from the entry offset reaches no CD record.
    Bytes with_short_cd_record(Bytes image) {
        constexpr size_t kEntryOffset = 0x8000;
        constexpr uint16_t kCdMagic = 0x4344;
        constexpr size_t kMaxRecords = 8;
        Driver driver(std::move(image));
        size_t cursor = kEntryOffset;
        for (size_t record = 0; record < kMaxRecords; ++record) {
            const auto header = driver.read_clean(cursor, sizeof(generic_header));
            if (header.size() < sizeof(generic_header)) {
                return {};
            }
            const uint32_t size = read_be32(header, offsetof(generic_header, size));
            if (read_be16(header, offsetof(generic_header, magic)) == kCdMagic) {
                const std::array<uint8_t, 4> short_size{0x00, 0x00, 0x00, 0x20};
                if (!driver.write_offset(cursor + offsetof(generic_header, size), short_size)) {
                    return {};
                }
                return driver.serialize();
            }
            if (size == 0) {
                return {};
            }
            cursor += align_16(size);
        }
        return {};
    }

    // A malformed bootloader record makes its parser throw. Each extraction entry point reports
    // that as a failure and lets no exception escape.
    bool test_extraction_reports_a_cd_record_shorter_than_its_header() {
        const auto input = fresh_input(ImageType::SmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value(), "the image to damage builds")) {
            return false;
        }
        const auto malformed = with_short_cd_record(*built);
        if (!require(!malformed.empty(), "the built image has a CD record to damage")) {
            return false;
        }

        const auto fails_without_throwing = [](const auto& extract) {
            try {
                return !extract().has_value();
            } catch (...) {
                return false;
            }
        };
        const auto& cpu_key = input.metadata.cpu_key;
        const bool some_info = fails_without_throwing([&] { return extract_some_info(malformed); });
        const bool metadata =
            fails_without_throwing([&] { return extract_metadata(malformed, cpu_key); });
        const bool all_info =
            fails_without_throwing([&] { return extract_all_info(malformed, cpu_key); });
        const bool all = fails_without_throwing([&] { return extract_all(malformed, cpu_key); });
        bool passed = require(some_info, "extract_some_info refuses a short CD record");
        passed = require(metadata, "extract_metadata refuses a short CD record") && passed;
        passed = require(all_info, "extract_all_info refuses a short CD record") && passed;
        passed = require(all, "extract_all refuses a short CD record") && passed;
        return passed;
    }

    // The extraction cores return their reason and log nothing; the public GxBuild::Extract*
    // shims log that reason once and return std::nullopt.
    bool test_extraction_cores_return_their_reason_and_the_shims_return_nullopt() {
        const auto input = fresh_input(ImageType::SmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value(), "the image to extract builds")) {
            return false;
        }
        const auto& cpu_key = input.metadata.cpu_key;
        const Bytes short_key(cpu_key.begin(), cpu_key.begin() + 15);
        const auto short_key_all = extract_all(*built, short_key);
        const auto empty_info = extract_some_info(Bytes{});
        const auto malformed = with_short_cd_record(*built);
        const auto malformed_all = extract_all(malformed, cpu_key);
        return require(!short_key_all && short_key_all.error().code == ErrorCode::InvalidArgument &&
                           short_key_all.error().describe().find("16 bytes") != std::string::npos,
                       "extract_all names a CPU key of the wrong length") &&
               require(!empty_info && empty_info.error().code == ErrorCode::InvalidArgument &&
                           empty_info.error().describe().find("empty") != std::string::npos,
                       "extract_some_info names an empty image") &&
               require(!malformed_all &&
                           malformed_all.error().describe().find(
                               "Failed to parse the NAND image structure") != std::string::npos,
                       "extract_all puts the parse context on a malformed record") &&
               require(!GxBuild::ExtractAll(*built, short_key).has_value() &&
                           !GxBuild::ExtractSomeInfo(Bytes{}).has_value() &&
                           !GxBuild::ExtractAll(malformed, cpu_key).has_value() &&
                           GxBuild::ExtractAll(*built, cpu_key).has_value(),
                       "the public Extract* shims return nullopt exactly when the core fails");
    }

    // The keyvault's fcrt.bin flag is read as xeBuild 1.21 reads it: bits 0x0320 of the big-endian
    // OddFeatures word at 0x1C.
    bool test_extract_all_info_reads_the_fcrt_flag_big_endian() {
        bool passed = true;
        for (const auto& [features, required] : {std::pair<uint16_t, bool>{0x0020, true},
                                                 {0x0200, true},
                                                 {0x2000, false},
                                                 {0x0000, false}}) {
            auto input = fresh_input(ImageType::SmallBlock);
            Bytes plain(Keyvault::kSize, 0x00);
            plain[0x1C] = static_cast<uint8_t>(features >> 8);
            plain[0x1D] = static_cast<uint8_t>(features);
            input.metadata.keyvault = canonical_keyvault(input.metadata.cpu_key, plain);
            const auto built = run_build(input);
            const auto info = built ? extract_all_info(*built, input.metadata.cpu_key) : not_built;
            passed = require(info.has_value() && info->keyvault.present &&
                                 info->keyvault.fcrt_required == required,
                             "full NAND metadata reports the keyvault's fcrt.bin flag") &&
                     passed;
        }
        return passed;
    }

    // The keyvault summary of the full NAND metadata, pinned against a plaintext keyvault written
    // by hand at its on-disk offsets (not through XE_KEYVAULT_DATA), so a moved field, a dropped
    // byte swap or a changed bound shows up here:
    //   0x01C OddFeatures (big-endian)       0x0B0 serial, 12 chars, no terminator needed
    //   0x0C8 game region (big-endian)       0x100 DVD key
    //   0x9CA console id (5 bytes)           0x9E4 manufacturing date (8 chars)
    //   0xC92 OSIG text (28 chars at most)   0x1EF0..0x1EF7 last 8 bytes of the special signature
    // kv_type is 1 when every byte of that 8-byte tail is 0x00 or 0xFF, and 2 otherwise.
    bool test_extract_all_info_pins_the_keyvault_summary_at_its_offsets() {
        const auto put = [](Bytes& plain, size_t at, std::string_view text) {
            std::copy(text.begin(), text.end(), plain.begin() + static_cast<std::ptrdiff_t>(at));
        };
        const auto keyvault = [&](uint16_t odd_features, uint16_t region, std::string_view osig,
                                  uint8_t last_tail_byte) {
            Bytes plain(Keyvault::kSize, 0x00);
            plain[0x1C] = static_cast<uint8_t>(odd_features >> 8);
            plain[0x1D] = static_cast<uint8_t>(odd_features);
            put(plain, 0xB0, "123456789012");
            plain[0xBC] = 'X'; // the padding after the serial is not part of it
            plain[0xC8] = static_cast<uint8_t>(region >> 8);
            plain[0xC9] = static_cast<uint8_t>(region);
            for (size_t i = 0; i < 0x10; ++i) {
                plain[0x100 + i] = static_cast<uint8_t>(0xD0 + i);
            }
            const std::array<uint8_t, 5> console_id{0x12, 0x34, 0x56, 0x78, 0x9A};
            std::copy(console_id.begin(), console_id.end(), plain.begin() + 0x9CA);
            put(plain, 0x9E4, "09-14-10");
            put(plain, 0xC92, osig);
            // A byte that is neither 0x00 nor 0xFF just before the tail does not count.
            plain[0x1EEF] = 0x5A;
            for (size_t i = 0; i < 8; ++i) {
                plain[0x1EF0 + i] = (i % 2 == 0) ? 0xFF : 0x00;
            }
            plain[0x1EF7] = last_tail_byte;
            return plain;
        };

        struct Case {
            std::string_view name;
            Bytes plain;
            uint16_t region_raw;
            std::string_view region_name;
            std::string_view osig;
            uint8_t kv_type;
            bool fcrt_required;
        };
        const std::array<Case, 2> cases{{
            {"type-1 keyvault", keyvault(0x0020, 0x01FE, "GXB SYNTHETIC OSIG 01", 0x00), 0x01FE,
             "NTSC/JAP", "GXB SYNTHETIC OSIG 01", 1, true},
            // The OSIG runs past 28 chars with no terminator: the summary stops at 28.
            {"type-2 keyvault",
             keyvault(0x0000, 0x02FE, "GXB SYNTHETIC OSIG TEXT 0123456789", 0x01), 0x02FE, "PAL/EU",
             "GXB SYNTHETIC OSIG TEXT 0123", 2, false},
        }};

        bool passed = true;
        for (const auto& test_case : cases) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.metadata.keyvault = canonical_keyvault(input.metadata.cpu_key, test_case.plain);
            const auto built = run_build(input);
            const auto info = built ? extract_all_info(*built, input.metadata.cpu_key) : not_built;
            if (!require(info.has_value() && info->keyvault.present && info->keyvault.decrypted,
                         std::string(test_case.name) + ": full NAND metadata has the keyvault")) {
                passed = false;
                continue;
            }
            const auto& kv = info->keyvault;
            const auto field = [&](bool ok, std::string_view what) {
                return require(ok, std::string(test_case.name) + ": " + std::string(what));
            };
            passed = field(kv.serial_number == "123456789012", "serial_number at 0xB0") && passed;
            passed = field(kv.region_raw == test_case.region_raw,
                           "region_raw is the big-endian word at 0xC8") &&
                     passed;
            passed = field(kv.region_name == test_case.region_name, "region_name") && passed;
            passed = field(kv.dvd_key == "D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF", "dvd_key at 0x100") &&
                     passed;
            passed = field(kv.console_id_raw == "123456789A", "console_id_raw at 0x9CA") && passed;
            // 0x123456789 printed in 11 digits, then the low nibble of the fifth byte.
            passed =
                field(kv.console_id_friendly == "0488671834510", "console_id_friendly") && passed;
            passed = field(kv.mfr_date == "09-14-10", "mfr_date at 0x9E4") && passed;
            passed = field(kv.osig == test_case.osig, "osig at 0xC92") && passed;
            passed =
                field(kv.kv_type == test_case.kv_type, "kv_type from the 0x1EF0 tail") && passed;
            passed = field(kv.fcrt_required == test_case.fcrt_required,
                           "fcrt_required from OddFeatures at 0x1C") &&
                     passed;
        }
        return passed;
    }

    bool test_sc_survives_extraction_and_backing_cleared_layout_override() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {});
        auto extracted = extract_all(donor, source.metadata.cpu_key);
        if (!require(extracted.has_value() && extracted->bootloaders.sc == source.bootloaders.sc,
                     "extraction preserves exact SC bytes"))
            return false;
        extracted->metadata.nand_image.reset();
        extracted->image_type = ImageType::BigBlock;
        const auto rebuilt = run_build(*extracted);
        auto parsed = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        return require(parsed.has_value() && parsed->cb_section.sc.has_value() &&
                           parsed->cb_section.sc->serialize() == *source.bootloaders.sc,
                       "SC survives backing-cleared layout override");
    }

    // An SC is sealed under HMAC(16 zero bytes, nonce), whatever its parent.
    bool test_decrypt_all_distinguishes_encrypted_and_zero_key_plaintext_sc() {
        auto encrypted_source = fresh_input(ImageType::SmallBlock);
        auto encrypted_sc = test::must(BootloaderSc::parse(*encrypted_source.bootloaders.sc));
        const auto expected_encrypted_sc_data = encrypted_sc.data;
        encrypted_sc.decrypted = true;
        test::must(encrypted_sc.encrypt(BootloaderSc::kZeroSecret));
        encrypted_source.bootloaders.sc = encrypted_sc.serialize();

        const auto encrypted_build = run_build(encrypted_source);
        auto encrypted_image = encrypted_build ? FlashImage::read(*encrypted_build) : std::nullopt;
        const bool encrypted_parsed = encrypted_image && encrypted_image->parse();
        const bool encrypted_decrypted =
            encrypted_parsed && encrypted_image->decrypt_all(encrypted_source.metadata.cpu_key);

        auto plaintext_source = fresh_input(ImageType::SmallBlock);
        const auto expected_plaintext_sc = *plaintext_source.bootloaders.sc;
        const auto plaintext_build = run_build(plaintext_source);
        const auto plaintext_extracted =
            plaintext_build ? extract_all(*plaintext_build, plaintext_source.metadata.cpu_key)
                            : not_built;

        return require(encrypted_decrypted && encrypted_image->cb_section.sc.has_value() &&
                           encrypted_image->cb_section.sc->is_decrypted(),
                       "decrypt_all decrypts explicitly encrypted SC") &&
               require(encrypted_image->cb_section.sc->data == expected_encrypted_sc_data,
                       "decrypt_all restores the exact encrypted SC plaintext") &&
               require(plaintext_extracted &&
                           plaintext_extracted->bootloaders.sc == expected_plaintext_sc,
                       "decrypt_all preserves zero-key plaintext SC bytes");
    }

    bool test_fresh_layouts_match_requested_image_types() {
        const std::array<std::pair<ImageType, Driver::DriverMode>, 4> layouts{{
            {ImageType::SmallBlock, Driver::DriverMode::Small},
            {ImageType::NewSmallBlock, Driver::DriverMode::NewSmall},
            {ImageType::BigBlock, Driver::DriverMode::Big},
            {ImageType::Emmc, Driver::DriverMode::Emmc},
        }};

        for (const auto& [image_type, expected_mode] : layouts) {
            const auto built = run_build(fresh_input(image_type));
            if (!require(built.has_value(), "fresh layout build succeeds")) {
                return false;
            }
            const auto parsed = parse_image(*built);
            if (!require(parsed.has_value(), "fresh layout output parses") ||
                !require(parsed->flash_driver.driver_mode() == expected_mode,
                         "fresh layout uses the requested NAND driver mode")) {
                return false;
            }
        }
        return true;
    }

    // xeBuild leaves header 0x74 zero (xerunner build.py `header`), as do the console
    // dumps measured; a rewrite must not carry a donor's value forward either.
    bool test_header_0x74_stays_zero_on_fresh_and_rewritten_images() {
        const auto zero_at_0x74 = [](const Bytes& image) {
            return image.size() >= 0x78 && std::all_of(image.begin() + 0x74, image.begin() + 0x78,
                                                       [](uint8_t b) { return b == 0; });
        };
        for (const auto image_type :
             {ImageType::SmallBlock, ImageType::BigBlock, ImageType::Emmc}) {
            const auto built = run_build(fresh_input(image_type));
            if (!require(built.has_value(), "header 0x74 fixture builds") ||
                !require(zero_at_0x74(*built), "fresh image leaves header 0x74 zero"))
                return false;
            auto parsed = parse_image(*built);
            if (!require(parsed.has_value(), "header 0x74 fixture parses"))
                return false;
            parsed->header.smc_config_offset = 0xF7C000;
            if (!require(zero_at_0x74(parsed->write().value_or(Bytes{})),
                         "rewrite does not carry a donor's header 0x74"))
                return false;
        }
        return true;
    }

    bool test_bigblock_flashfs_formats_and_roundtrips_an_empty_overlay() {
        auto input = fresh_input(ImageType::BigBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        const auto built = run_build(input);
        if (!require(built.has_value(), "BigBlock empty FlashFS formats")) {
            return false;
        }
        const auto parsed = parse_image(*built);
        return require(parsed.has_value() && parsed->filesystem.has_value(),
                       "BigBlock empty FlashFS parses");
    }

    bool test_bigblock_flashfs_roundtrips_a_file_larger_than_16_kib() {
        Bytes expected(0x5000);
        for (size_t index = 0; index < expected.size(); ++index) {
            expected[index] =
                static_cast<uint8_t>((index * 37U + (index >> 8U) * 13U + 0x5BU) & 0xFFU);
        }

        auto input = fresh_input(ImageType::BigBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"big-file.bin", expected}};
        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        const auto extracted = parsed && parsed->filesystem
                                   ? parsed->filesystem->get_file("big-file.bin")
                                   : std::nullopt;

        return require(built.has_value(), "BigBlock FlashFS file image builds") &&
               require(parsed.has_value() && parsed->filesystem.has_value(),
                       "BigBlock FlashFS file image parses") &&
               require(extracted.has_value() && extracted->size() == expected.size(),
                       "BigBlock FlashFS file retains its exact length") &&
               require(extracted == expected, "BigBlock FlashFS file retains its exact contents");
    }

    bool test_big_block_donor_retains_flashfs_without_replacement() {
        auto input = fresh_input(ImageType::BigBlock);
        const Bytes expected(0x4003, 0x52);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"data.bin", expected}};
        const auto built = run_build(input);
        if (!require(built.has_value(), "big-block filesystem donor builds"))
            return false;

        input.metadata.nand_image = *built;
        input.flashfs_sec.reset();
        const auto rebuilt = run_build(input);
        const auto parsed = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        return require(
            parsed && parsed->filesystem && parsed->filesystem->get_file("data.bin") == expected,
            "moved donor filesystem uses the current driver geometry without an overlay");
    }

    // An extended.bin in the clear behind the nonce its plaintext derives, its head the
    // keyvault's.
    Bytes clear_extended(const Input& input, uint8_t fill) {
        const auto& cpu_key = input.metadata.cpu_key;
        Bytes plain(gxbuild3::nand::kExtendedSize - 0x10, fill);
        std::copy_n(input.metadata.keyvault->begin() + 0x10, 8, plain.begin());
        const uint8_t tail[2] = {0x07, 0x12};
        uint8_t digest[20]{};
        ExCryptHmacSha(cpu_key.data(), 16, plain.data(), static_cast<uint32_t>(plain.size()), tail,
                       2, nullptr, 0, digest, sizeof(digest));
        Bytes out(digest, digest + 0x10);
        out.insert(out.end(), plain.begin(), plain.end());
        return out;
    }

    // A secdata.bin in the clear behind the nonce its plaintext derives.
    Bytes clear_secdata(const Input& input, uint8_t fill) {
        const auto& cpu_key = input.metadata.cpu_key;
        Bytes plain(gxbuild3::nand::kSecdataSize - 0x10, fill);
        uint8_t digest[20]{};
        ExCryptHmacSha(cpu_key.data(), 16, plain.data(), static_cast<uint32_t>(plain.size()),
                       nullptr, 0, nullptr, 0, digest, sizeof(digest));
        Bytes out(digest, digest + 0x10);
        out.insert(out.end(), plain.begin(), plain.end());
        return out;
    }

    bool test_secure_flashfs_files_roundtrip_through_extract_and_rebuild() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto& cpu_key = input.metadata.cpu_key;
        const auto extended = clear_extended(input, 0x42);
        const auto secdata = clear_secdata(input, 0x31);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"secdata.bin", secdata},
                                                                       {"extended.bin", extended}};
        const auto built = run_build(input);
        if (!require(built.has_value(), "secure FlashFS build succeeds")) {
            return false;
        }
        auto extracted = extract_all(*built, cpu_key);
        const auto file = [](const Input& from, std::string_view name) -> const Bytes* {
            if (!from.flashfs_sec) {
                return nullptr;
            }
            for (const auto& [file_name, data] : *from.flashfs_sec) {
                if (file_name == name) {
                    return &data;
                }
            }
            return nullptr;
        };
        const auto* first_secdata = extracted ? file(*extracted, "secdata.bin") : nullptr;
        if (!require(extracted && file(*extracted, "extended.bin") &&
                         *file(*extracted, "extended.bin") == extended && first_secdata &&
                         gxbuild3::nand::secdata_opened(*first_secdata, cpu_key) &&
                         std::equal(secdata.begin() + 0x10, secdata.begin() + 0x18,
                                    first_secdata->begin() + 0x10),
                     "extraction returns plaintext secure FlashFS files")) {
            return false;
        }
        extracted->metadata.nand_image.reset();
        const auto rebuilt = run_build(*extracted);
        if (!require(rebuilt.has_value(), "secure FlashFS rebuild succeeds")) {
            return false;
        }
        const auto roundtrip = extract_all(*rebuilt, cpu_key);
        const auto* second_secdata = roundtrip ? file(*roundtrip, "secdata.bin") : nullptr;
        return require(
            roundtrip && file(*roundtrip, "extended.bin") &&
                *file(*roundtrip, "extended.bin") == extended && second_secdata &&
                gxbuild3::nand::secdata_opened(*second_secdata, cpu_key) &&
                std::equal(secdata.begin() + 0x10, secdata.begin() + 0x18,
                           second_secdata->begin() + 0x10) &&
                std::equal(secdata.begin() + 0x28, secdata.end(), second_secdata->begin() + 0x28),
            "secure FlashFS files survive extract and rebuild");
    }

    // A signed record in the clear: magic, length and the SHA-1 of everything from 0x150 on.
    Bytes clear_signed_record(std::string_view magic, size_t length) {
        Bytes out(length);
        std::copy(magic.begin(), magic.end(), out.begin());
        out[4] = static_cast<uint8_t>(length >> 8);
        out[5] = static_cast<uint8_t>(length);
        for (size_t at = 0x150; at < length; ++at) {
            out[at] = static_cast<uint8_t>(at * 5 + 1);
        }
        ExCryptSha(out.data() + 0x150, static_cast<uint32_t>(length - 0x150), nullptr, 0, nullptr,
                   0, out.data() + 0x0C, 20);
        return out;
    }

    bool test_secured_flashfs_files_are_sealed_for_the_console() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto& cpu_key = input.metadata.cpu_key;
        input.metadata.cf_ldv = 9;
        const auto clear_crl = clear_signed_record("CRLP", 0xA00);
        const gxbuild3::nand::CrlSealing own_sealing{
            {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD,
             0xAE, 0xAF},
            {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
             0x11, 0x12}};
        const auto own_crl = gxbuild3::nand::reseal_crl(clear_crl, cpu_key, own_sealing, {0, 3});
        if (!require(own_crl.has_value(), "the console's crl.bin fixture seals")) {
            return false;
        }
        const auto extended = clear_extended(input, 0x5A);

        // fcrt.bin in the clear: the vector at 0x100, the sealed part from 0x140 and its SHA-1 at
        // 0x12C.
        Bytes fcrt(0x4000);
        std::fill(fcrt.begin() + 0x100, fcrt.begin() + 0x110, uint8_t{0x6C});
        fcrt[0x11E] = 0x01;
        fcrt[0x11F] = 0x40;
        for (size_t at = 0x140; at < fcrt.size(); ++at) {
            fcrt[at] = static_cast<uint8_t>(at * 3 + 1);
        }
        ExCryptSha(fcrt.data() + 0x140, static_cast<uint32_t>(fcrt.size() - 0x140), nullptr, 0,
                   nullptr, 0, fcrt.data() + 0x12C, 20);

        input.metadata.console_secured_files = {{"crl.bin", *own_crl}};
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"crl.bin", clear_crl}, {"extended.bin", extended}, {"fcrt.bin", fcrt}};
        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, cpu_key) : not_built;
        if (!require(extracted.has_value() && extracted->flashfs_sec.has_value(),
                     "a build with secured files extracts")) {
            return false;
        }
        const auto find = [&](std::string_view name) -> const Bytes* {
            for (const auto& [file, data] : *extracted->flashfs_sec) {
                if (file == name) {
                    return &data;
                }
            }
            return nullptr;
        };
        const auto* crl = find("crl.bin");
        const auto* opened_extended = find("extended.bin");
        const auto* sealed_fcrt = find("fcrt.bin");
        if (!require(crl && opened_extended && sealed_fcrt, "the three files are in the image")) {
            return false;
        }
        const auto sealing = gxbuild3::nand::crl_sealing(*crl, cpu_key);
        alignas(16) EXCRYPT_AES_STATE state{};
        ExCryptAesKey(&state, own_sealing.file_key.data());
        auto feed = own_sealing.iv;
        Bytes body(crl->size() - 0x140);
        ExCryptAesCbc(&state, crl->data() + 0x140, static_cast<uint32_t>(body.size()), body.data(),
                      feed.data(), 0);
        ExCryptAesKey(&state, cpu_key.data());
        std::array<uint8_t, 16> fcrt_feed{};
        std::copy_n(fcrt.begin() + 0x100, fcrt_feed.size(), fcrt_feed.begin());
        Bytes fcrt_body(fcrt.size() - 0x140);
        ExCryptAesCbc(&state, sealed_fcrt->data() + 0x140, static_cast<uint32_t>(fcrt_body.size()),
                      fcrt_body.data(), fcrt_feed.data(), 0);
        const auto& keyvault = *input.metadata.keyvault;
        return require(sealing && sealing->iv == own_sealing.iv &&
                           sealing->file_key == own_sealing.file_key,
                       "crl.bin is sealed under the console's own vector and file key") &&
               require(body[0x0F] == 9, "crl.bin states the CF lockdown value") &&
               require(std::equal(body.begin() + 0x10, body.end(), clear_crl.begin() + 0x150),
                       "crl.bin keeps the supplied content") &&
               require(extracted->metadata.console_secured_files.size() == 1 &&
                           extracted->metadata.console_secured_files.front().second == *crl,
                       "extraction keeps the console's own crl.bin") &&
               require(gxbuild3::nand::extended_opened(*opened_extended, cpu_key),
                       "extended.bin carries the nonce its plaintext derives") &&
               require(std::equal(keyvault.begin() + 0x10, keyvault.begin() + 0x18,
                                  opened_extended->begin() + 0x10),
                       "extended.bin's head is the keyvault's") &&
               require(std::equal(fcrt.begin(), fcrt.begin() + 0x140, sealed_fcrt->begin()) &&
                           *sealed_fcrt != fcrt &&
                           std::equal(fcrt_body.begin(), fcrt_body.end(), fcrt.begin() + 0x140),
                       "fcrt.bin in the clear is sealed under the CPU key and its own vector");
    }

    // An fcrt.bin that is neither in the clear nor opens under the CPU key is written as xeBuild
    // 1.21 writes it: its header as supplied and its sealed part as the failed opening left it.
    // The console's own copy is carried as it stands.
    bool test_a_damaged_fcrt_is_written_as_its_failed_opening() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto& cpu_key = input.metadata.cpu_key;
        Bytes damaged(0x4000);
        std::fill(damaged.begin() + 0x100, damaged.begin() + 0x110, uint8_t{0x6C});
        damaged[0x11E] = 0x01;
        damaged[0x11F] = 0x40;
        for (size_t at = 0x140; at < damaged.size(); ++at) {
            damaged[at] = static_cast<uint8_t>(at * 3 + 1);
        }
        // No hash at 0x12C holds, in the clear or opened.
        std::fill(damaged.begin() + 0x12C, damaged.begin() + 0x140, uint8_t{0xEE});
        alignas(16) EXCRYPT_AES_STATE state{};
        ExCryptAesKey(&state, cpu_key.data());
        std::array<uint8_t, 16> feed{};
        std::copy_n(damaged.begin() + 0x100, feed.size(), feed.begin());
        Bytes failed_opening = damaged;
        ExCryptAesCbc(&state, damaged.data() + 0x140, static_cast<uint32_t>(damaged.size() - 0x140),
                      failed_opening.data() + 0x140, feed.data(), 0);

        const auto image_fcrt = [&](const Input& build) -> std::optional<Bytes> {
            const auto built = run_build(build);
            const auto extracted = built ? extract_all(*built, cpu_key) : not_built;
            if (!extracted || !extracted->flashfs_sec) {
                return std::nullopt;
            }
            for (const auto& [file, data] : *extracted->flashfs_sec) {
                if (file == "fcrt.bin") {
                    return data;
                }
            }
            return std::nullopt;
        };
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"fcrt.bin", damaged}};
        const auto supplied = image_fcrt(input);
        input.metadata.console_secured_files = {{"fcrt.bin", damaged}};
        const auto own = image_fcrt(input);
        return require(supplied && *supplied == failed_opening && *supplied != damaged,
                       "a supplied damaged fcrt.bin is written as its failed opening") &&
               require(own && *own == damaged,
                       "the console's own fcrt.bin that does not open is carried as it stands");
    }

    bool test_flashfs_overlay_outranks_a_higher_sequence_donor_root() {
        auto first = fresh_input(ImageType::SmallBlock);
        first.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"first.bin", Bytes{1}}};
        const auto first_build = run_build(first);
        if (!require(first_build.has_value(), "initial FlashFS donor build succeeds")) {
            return false;
        }

        auto higher_sequence_donor = fresh_input(ImageType::SmallBlock);
        higher_sequence_donor.metadata.nand_image = *first_build;
        higher_sequence_donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"donor-old.bin", Bytes{2}}};
        const auto donor_build = run_build(higher_sequence_donor);
        auto donor_image = donor_build ? parse_image(*donor_build) : std::nullopt;
        if (!require(donor_image.has_value() && donor_image->filesystem.has_value() &&
                         donor_image->filesystem->version() == 1,
                     "a rebuilt FlashFS starts at root sequence 1")) {
            return false;
        }
        // Raise the donor root above the sequence a new build writes.
        const uint16_t donor_root = donor_image->filesystem->root_block();
        BlockMetadata raised = donor_image->flash_driver.interpret_cluster(donor_root);
        raised.sequence = 0x125;
        donor_image->flash_driver.write_cluster_metadata(donor_root, raised);
        // The bytes as they stand: a driver with no layout of its own would stamp its low
        // blocks, the root among them, as system area.
        const auto donor_bytes = std::as_const(donor_image->flash_driver).serialize();
        const auto parsed_donor = parse_image(donor_bytes);
        if (!require(parsed_donor.has_value() && parsed_donor->filesystem.has_value() &&
                         parsed_donor->filesystem->version() == 0x125,
                     "donor FlashFS root carries a sequence above the fresh default")) {
            return false;
        }

        auto overlay = fresh_input(ImageType::SmallBlock);
        overlay.metadata.nand_image = donor_bytes;
        overlay.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"replacement.bin", Bytes{7, 8, 9}}};
        const auto built = run_build(overlay);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        if (!require(parsed.has_value() && parsed->filesystem.has_value(),
                     "FlashFS overlay output parses")) {
            return false;
        }
        const auto replacement = parsed->filesystem->get_file("replacement.bin");
        return require(parsed->filesystem->version() == 1,
                       "the overlay root is written at sequence 1") &&
               require(replacement == Bytes({7, 8, 9}),
                       "FlashFS overlay selects the exact replacement contents") &&
               require(!parsed->filesystem->get_file("donor-old.bin").has_value(),
                       "stale donor FlashFS root cannot win selection");
    }

    bool test_serialized_mobile_overlay_skips_a_bad_donor_block() {
        const auto initial = run_build(fresh_input(ImageType::SmallBlock));
        auto donor = initial ? FlashImage::read(*initial) : std::nullopt;
        if (!require(donor.has_value(), "bad-block donor image opens")) {
            return false;
        }

        constexpr size_t first_mobile_block = 4;
        donor->flash_driver.mark_bad_block(first_mobile_block);
        const auto donor_bytes = donor->flash_driver.serialize();

        auto overlay = fresh_input(ImageType::SmallBlock);
        overlay.metadata.nand_image = donor_bytes;
        *overlay.mobiles.slot(0x31) = Bytes(0x4000, 0x31);
        const auto built = run_build(overlay);
        const auto parsed = built ? parse_image(*built) : std::nullopt;

        return require(built.has_value(), "bad-block mobile overlay builds") &&
               require(parsed.has_value() && parsed->mobile_data.has_value() &&
                           parsed->mobile_data->x31 == *overlay.mobiles.slot(0x31),
                       "serialized mobile overlay skips the bad donor block") &&
               require(parsed->flash_driver.is_bad_block(first_mobile_block),
                       "serialized bad donor marker remains set") &&
               require(parsed->flash_driver.interpret_block(first_mobile_block).block_type != 0x31,
                       "bad donor block is not assigned mobile metadata");
    }

    bool test_mobile_allocation_rejects_smc_tail_overlap() {
        FlashImage image{};
        image.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        const size_t limit = image.flash_driver.data_block_limit();
        gxbuild3::nand::FlashFileSystem filesystem{};
        filesystem.set_driver(&image.flash_driver);
        if (!require(filesystem.format(image.flash_driver.block_count(),
                                       gxbuild3::nand::FlashFileSystem::kDeferRoot) &&
                         filesystem.reserve_blocks(0, limit),
                     "a FlashFS holding every data block formats")) {
            return false;
        }
        image.filesystem = std::move(filesystem);
        image.mobile_data = MobileData{};
        image.mobile_data->x31 = Bytes(0x800, 0x31);

        if (!require(!image.write(), "mobile allocation cannot enter the SMC tail")) {
            return false;
        }
        for (size_t block = limit; block < image.flash_driver.block_count(); ++block) {
            if (!require(image.flash_driver.interpret_block(block).block_type != 0x31,
                         "no tail block is given the mobile")) {
                return false;
            }
        }
        return true;
    }

    bool test_flashfs_allocation_reports_exhaustion_before_the_smc_tail() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"probe.bin", Bytes{1}}};
        const auto probe = run_build(input);
        const auto probed = probe ? parse_image(*probe) : std::nullopt;
        const auto probe_entry =
            probed && probed->filesystem ? probed->filesystem->stat("probe.bin") : std::nullopt;
        if (!require(probe_entry.has_value(), "a one-file FlashFS builds and lists its file")) {
            return false;
        }
        const size_t first_flashfs_block = probe_entry->block_number;
        constexpr size_t smc_tail_start = 0x3DC;
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"fills-tail.bin", Bytes((smc_tail_start - first_flashfs_block + 1) * 0x4000, 0xA5)}};

        const auto built = run_build(input);
        return require(!built.has_value(), "FlashFS allocation cannot enter the SMC tail") &&
               require(built.error().code == BuildErrorCode::SerializationFailure,
                       "FlashFS tail exhaustion reports SerializationFailure");
    }

    bool test_serialized_flashfs_retains_an_empty_file() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"empty.bin", Bytes{}}};
        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;

        return require(built.has_value(), "empty FlashFS file build succeeds") &&
               require(parsed.has_value() && parsed->filesystem.has_value(),
                       "empty FlashFS file image parses") &&
               require(parsed->filesystem->get_file("empty.bin") == Bytes{},
                       "serialized empty FlashFS file is retained");
    }

    bool test_serialized_mobile_does_not_overlap_fixed_payloads() {
        auto input = fresh_input(ImageType::SmallBlock);
        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x1000, 0x71);
        payloads.fuses = Bytes(0x60, 0x72);
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);

        // The unreserved range begins at block 4. Nine one-block blobs are laid from there,
        // past the payload blocks from the rebooter at 0x90000 through XeLL at 0x95060.
        for (uint8_t block_type = 0x31; block_type <= 0x39; ++block_type) {
            *input.mobiles.slot(block_type) = Bytes(0x4000, block_type);
        }
        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        bool mobiles_intact = parsed.has_value() && parsed->mobile_data.has_value();
        for (uint8_t block_type = 0x31; mobiles_intact && block_type <= 0x39; ++block_type) {
            mobiles_intact =
                *parsed->mobile_data->get_slot(block_type) == *input.mobiles.slot(block_type);
        }

        return require(built.has_value(), "mobile and fixed payload image builds") &&
               require(mobiles_intact,
                       "serialized mobile bytes are not overwritten by fixed payloads") &&
               require(parsed->payloads.rebooter == input.payloads->rebooter,
                       "serialized rebooter bytes survive mobile allocation") &&
               require(parsed->payloads.fuses == input.payloads->fuses,
                       "serialized fuse bytes survive mobile allocation") &&
               require(parsed->payloads.xell.has_value() &&
                           parsed->payloads.xell->data == *input.payloads->xell,
                       "serialized XeLL bytes survive mobile allocation");
    }

    bool test_serialized_flashfs_does_not_overlap_fixed_payloads() {
        auto input = fresh_input(ImageType::SmallBlock);
        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x1000, 0x71);
        payloads.fuses = Bytes(0x60, 0x72);
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);
        input.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"payload-safe.bin", Bytes(0x4000, 0x5A)}};

        const auto built = run_build(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        return require(built.has_value(), "FlashFS and fixed payload image builds") &&
               require(parsed.has_value() && parsed->filesystem.has_value() &&
                           parsed->filesystem->get_file("payload-safe.bin") == Bytes(0x4000, 0x5A),
                       "serialized FlashFS bytes are not overwritten by fixed payloads") &&
               require(parsed->payloads.rebooter == input.payloads->rebooter,
                       "serialized rebooter bytes survive FlashFS allocation") &&
               require(parsed->payloads.fuses == input.payloads->fuses,
                       "serialized fuse bytes survive FlashFS allocation") &&
               require(parsed->payloads.xell.has_value() &&
                           parsed->payloads.xell->data == *input.payloads->xell,
                       "serialized XeLL bytes survive FlashFS allocation");
    }

    bool test_fixed_payloads_reject_noncanonical_sizes() {
        // The rebooter only has to fit its 0x1000-byte window region; the embedded freeBOOT
        // rebooter is 0xd40 bytes and is deliberately not padded.
        const std::array<size_t, 2> valid_rebooter_sizes{{0xd40, 0x1000}};
        for (const auto size : valid_rebooter_sizes) {
            auto input = fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(size, 0x71);
            input.payloads = std::move(payloads);
            if (!require(run_build(input).has_value(), "rebooter fitting its region is accepted")) {
                return false;
            }
        }

        const std::array<size_t, 2> invalid_rebooter_sizes{{0x1001, 0x2000}};
        for (const auto size : invalid_rebooter_sizes) {
            auto input = fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(size, 0x71);
            input.payloads = std::move(payloads);
            const auto built = run_build(input);
            if (!require(!built.has_value(), "oversized rebooter is rejected") ||
                !require(built.error().code == BuildErrorCode::InvalidInput,
                         "oversized rebooter is an input error")) {
                return false;
            }
        }

        const std::array<size_t, 4> invalid_fuse_sizes{{0x5F, 0x61, 0, 0x100}};
        for (const auto size : invalid_fuse_sizes) {
            auto input = fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.fuses = Bytes(size, 0x72);
            input.payloads = std::move(payloads);
            const auto built = run_build(input);
            if (!require(!built.has_value(), "noncanonical fuse size is rejected") ||
                !require(built.error().code == BuildErrorCode::InvalidInput,
                         "noncanonical fuse size is an input error")) {
                return false;
            }
        }
        return true;
    }

    bool test_flashfs_directory_serialization_capacity() {
        auto full = fresh_input(ImageType::SmallBlock);
        full.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        for (size_t index = 0; index < 256; ++index) {
            full.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
        }
        const auto full_build = run_build(full);
        const auto full_image = full_build ? parse_image(*full_build) : std::nullopt;
        if (!require(full_build.has_value(), "256 FlashFS entries serialize successfully") ||
            !require(full_image.has_value() && full_image->filesystem.has_value() &&
                         full_image->filesystem->list_files().size() == 256,
                     "serialized FlashFS retains all 256 directory entries")) {
            return false;
        }

        auto overflow = fresh_input(ImageType::SmallBlock);
        overflow.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        for (size_t index = 0; index < 257; ++index) {
            overflow.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
        }
        const auto overflow_build = run_build(overflow);
        return require(!overflow_build.has_value(), "257 FlashFS entries are rejected") &&
               require(overflow_build.error().code == BuildErrorCode::SerializationFailure,
                       "FlashFS directory overflow returns SerializationFailure");
    }

    bool test_bigblock_flashfs_overlay_handles_the_24_bit_sequence_limit() {
        auto first = fresh_input(ImageType::BigBlock);
        first.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"donor-old.bin", Bytes{2}}};
        const auto first_build = run_build(first);
        auto max_sequence_donor = first_build ? FlashImage::read(*first_build) : std::nullopt;
        if (!require(max_sequence_donor.has_value() && max_sequence_donor->parse() &&
                         max_sequence_donor->filesystem.has_value(),
                     "BigBlock donor FlashFS parses before sequence saturation")) {
            return false;
        }

        const uint16_t root = max_sequence_donor->filesystem->root_block();
        BlockMetadata max_sequence_root{};
        max_sequence_root.logical_block_id = root;
        max_sequence_root.sequence = 0xFFFFFF;
        max_sequence_root.block_type = 0x30;
        max_sequence_donor->flash_driver.write_block_metadata(root, max_sequence_root);
        const auto donor_bytes = max_sequence_donor->flash_driver.serialize();

        auto overlay = fresh_input(ImageType::BigBlock);
        overlay.metadata.nand_image = donor_bytes;
        overlay.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"replacement.bin", Bytes{7, 8, 9}}};
        const auto built = run_build(overlay);
        const auto parsed = built ? parse_image(*built) : std::nullopt;

        return require(built.has_value(), "24-bit sequence overlay build succeeds") &&
               require(parsed.has_value() && parsed->filesystem.has_value() &&
                           parsed->filesystem->get_file("replacement.bin") == Bytes({7, 8, 9}),
                       "24-bit sequence overlay selects replacement content");
    }

    bool test_emmc_mobile_slots_roundtrip_and_an_empty_input_removes_donor_data() {
        const Bytes donor_mobile_31(0x4000, 0x31);
        const Bytes donor_mobile_32(0x4000, 0x32);
        auto donor_input = fresh_input(ImageType::Emmc);
        *donor_input.mobiles.slot(0x31) = donor_mobile_31;
        *donor_input.mobiles.slot(0x32) = donor_mobile_32;
        const auto donor_bytes = run_build(donor_input);
        const auto parsed_donor = donor_bytes ? parse_image(*donor_bytes) : std::nullopt;
        if (!require(parsed_donor.has_value() && parsed_donor->mobile_data.has_value(),
                     "serialized eMMC mobiles parse")) {
            return false;
        }
        if (!require(!parsed_donor->filesystem.has_value(),
                     "eMMC donor without FlashFS does not invent a filesystem at block zero")) {
            return false;
        }
        if (!require(parsed_donor->mobile_data->x31 == donor_mobile_31,
                     "eMMC 0x31 roundtrips exactly") ||
            !require(parsed_donor->mobile_data->x32 == donor_mobile_32,
                     "eMMC 0x32 roundtrips exactly")) {
            return false;
        }

        auto removal = fresh_input(ImageType::Emmc);
        removal.metadata.nand_image = *donor_bytes;
        *removal.mobiles.slot(0x31) = Bytes{};
        const auto rebuilt = run_build(removal);
        const auto parsed_rebuilt = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        return require(rebuilt.has_value(),
                       rebuilt ? "eMMC empty mobile overlay builds"
                               : "eMMC empty mobile overlay failure: " + rebuilt.error().message) &&
               require(parsed_rebuilt.has_value(), "eMMC empty mobile overlay parses") &&
               require(!parsed_rebuilt->mobile_data.has_value() ||
                           !parsed_rebuilt->mobile_data->x31.has_value(),
                       "eMMC present-empty 0x31 removes donor data") &&
               require(parsed_rebuilt->mobile_data.has_value() &&
                           parsed_rebuilt->mobile_data->x32 == donor_mobile_32,
                       "eMMC absent 0x32 preserves donor data");
    }

    bool test_emmc_takes_each_anchor_mobile_alone_and_drops_each_other_type() {
        for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
            auto input = fresh_input(ImageType::Emmc);
            *input.mobiles.slot(0x31) = Bytes{0x31};
            *input.mobiles.slot(block_type) = Bytes{block_type};
            if (!emmc_keeps_anchor_mobiles_only(input, "single eMMC mobile")) {
                return false;
            }
        }
        return true;
    }

    bool test_serialized_mobile_overlays_preserve_absent_slots_for_nand_layouts() {
        const std::array<ImageType, 3> layouts{
            {ImageType::SmallBlock, ImageType::NewSmallBlock, ImageType::BigBlock}};
        for (const auto layout : layouts) {
            auto donor_input = fresh_input(layout);
            *donor_input.mobiles.slot(0x31) = Bytes{0x31};
            *donor_input.mobiles.slot(0x39) = Bytes{0x39};
            const auto donor_bytes = run_build(donor_input);
            if (!require(donor_bytes.has_value(), "serialized NAND mobile donor builds")) {
                return false;
            }

            auto overlay = fresh_input(layout);
            overlay.metadata.nand_image = *donor_bytes;
            *overlay.mobiles.slot(0x39) = Bytes{0xA9, 0x39};
            const auto rebuilt = run_build(overlay);
            const auto parsed = rebuilt ? parse_image(*rebuilt) : std::nullopt;
            if (!require(parsed.has_value() && parsed->mobile_data.has_value(),
                         "serialized NAND mobile overlay parses") ||
                !require(parsed->mobile_data->x31 == Bytes({0x31}),
                         "absent NAND mobile slot preserves donor data") ||
                !require(parsed->mobile_data->x39 == Bytes({0xA9, 0x39}),
                         "high NAND mobile slot accepts user replacement")) {
                return false;
            }
        }
        return true;
    }

    // A settings block as a console holds it: 0x400 bytes whose head is the one's complement
    // of the byte sum over [0x10, 0x10C), little-endian.
    Bytes sound_smc_config() {
        Bytes block(0x400);
        for (size_t i = 2; i < block.size(); ++i) {
            block[i] = static_cast<uint8_t>(i * 5 + 1);
        }
        uint32_t sum = 0;
        for (size_t i = 0x10; i < 0x10C; ++i) {
            sum += block[i];
        }
        const uint16_t head = static_cast<uint16_t>(~sum);
        block[0] = static_cast<uint8_t>(head);
        block[1] = static_cast<uint8_t>(head >> 8);
        return block;
    }

    // A donor of one layout rebuilt as another keeps its settings, statistics and
    // manufacturing blocks, each at the offsets of the layout built.
    bool test_settings_blocks_follow_the_console_into_another_layout() {
        auto donor_input = fresh_input(ImageType::NewSmallBlock);
        donor_input.metadata.smc_config = sound_smc_config();
        donor_input.metadata.statistics = Bytes(0x1000, 0x5A);
        Bytes manufacturing(0x1000, 0xFF);
        std::fill_n(manufacturing.begin(), 0x40, uint8_t{0x4D});
        donor_input.metadata.manufacturing = manufacturing;
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "settings donor builds")) {
            return false;
        }

        const struct {
            ImageType type;
            size_t settings;
            size_t step;
        } targets[] = {
            {ImageType::SmallBlock, 0xF7C000, 0x4000},
            {ImageType::BigBlock, 0x3BE0000, 0x20000},
            {ImageType::Emmc, 0x2FFC000, 0x4000},
        };
        for (const auto& target : targets) {
            auto extracted = extract_all(*donor, donor_input.metadata.cpu_key);
            if (!require(extracted.has_value() &&
                             extracted->metadata.smc_config == donor_input.metadata.smc_config &&
                             extracted->metadata.statistics == donor_input.metadata.statistics &&
                             extracted->metadata.manufacturing == manufacturing,
                         "extraction takes the donor's settings blocks")) {
                return false;
            }
            extracted->metadata.nand_image.reset();
            extracted->image_type = target.type;
            const auto built = run_build(*extracted);
            const auto parsed = built ? parse_image(*built) : std::nullopt;
            if (!require(parsed.has_value(), "cross-layout build with settings blocks parses")) {
                return false;
            }
            const auto& driver = std::as_const(parsed->flash_driver);
            Bytes settings(0x1000, 0xFF);
            std::copy(donor_input.metadata.smc_config->begin(),
                      donor_input.metadata.smc_config->end(), settings.begin());
            if (!require(driver.read_clean(target.settings, 0x1000) == settings,
                         "the settings block lands at the target layout's offset") ||
                !require(driver.read_clean(target.settings - target.step, 0x1000) ==
                             *donor_input.metadata.statistics,
                         "the statistics block lands one erase block below it") ||
                !require(driver.read_clean(target.settings - 2 * target.step, 0x1000) ==
                             manufacturing,
                         "the manufacturing block lands two erase blocks below it")) {
                return false;
            }
        }
        return true;
    }

    bool test_extraction_roundtrips_serialized_bootloaders_and_payloads() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto bootloader_donor = make_donor(source, {});
        auto bootloaders = extract_all(bootloader_donor, source.metadata.cpu_key);
        const auto extracted_cd = bootloaders
                                      ? BootloaderCd::parse_or_throw(bootloaders->bootloaders.cd)
                                      : BootloaderCd{};
        if (!require(bootloaders.has_value(), "serialized bootloader donor extracts") ||
            !require(bootloaders->bootloaders.cb_or_a == source.bootloaders.cb_or_a,
                     "extraction preserves exact CB/A bytes") ||
            !require(extracted_cd.header.header.magic == NANDBootloaderMagic::CD &&
                         extracted_cd.header.header.version == 1 &&
                         extracted_cd.data == Bytes(0x20, 0x42),
                     "extraction preserves decrypted CD header and payload data") ||
            !require(bootloaders->bootloaders.sc == source.bootloaders.sc,
                     "extraction preserves exact SC bytes")) {
            return false;
        }

        bootloaders->metadata.nand_image.reset();
        const auto bootloader_rebuilt = run_build(*bootloaders);
        const auto bootloader_roundtrip =
            bootloader_rebuilt ? extract_all(*bootloader_rebuilt, bootloaders->metadata.cpu_key)
                               : not_built;
        const auto roundtrip_cd =
            bootloader_roundtrip
                ? BootloaderCd::parse_or_throw(bootloader_roundtrip->bootloaders.cd)
                : BootloaderCd{};
        // The donor chain stops before CE, so the rebuild seals CB/A under a fresh nonce.
        const auto same_outside_nonce = [](const Bytes& left, const Bytes& right) {
            return left.size() == right.size() && left.size() >= 0x20 &&
                   std::equal(left.begin(), left.begin() + 0x10, right.begin()) &&
                   std::equal(left.begin() + 0x20, left.end(), right.begin() + 0x20);
        };
        if (!require(bootloader_roundtrip.has_value() &&
                         same_outside_nonce(bootloader_roundtrip->bootloaders.cb_or_a,
                                            source.bootloaders.cb_or_a),
                     "rebuilt CB/A remains serialized-identical outside its nonce") ||
            !require(roundtrip_cd.header.header.magic == NANDBootloaderMagic::CD &&
                         roundtrip_cd.header.header.version == 1 &&
                         roundtrip_cd.data == Bytes(0x20, 0x42),
                     "rebuilt CD retains decrypted header and payload data") ||
            !require(bootloader_roundtrip->bootloaders.sc == source.bootloaders.sc,
                     "rebuilt SC remains serialized-identical")) {
            return false;
        }

        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x1000, 0x71);
        payloads.fuses = Bytes(0x60, 0x72);
        payloads.xell = valid_xell();
        source.payloads = std::move(payloads);
        const auto donor_bytes = run_build(source);
        auto payload_extracted =
            donor_bytes ? extract_all(*donor_bytes, source.metadata.cpu_key) : not_built;
        if (!require(payload_extracted.has_value(), "serialized payload donor extracts") ||
            !require(payload_extracted->payloads.has_value() &&
                         payload_extracted->payloads->rebooter == source.payloads->rebooter,
                     "extraction preserves parsed rebooter bytes") ||
            !require(payload_extracted->payloads.has_value() &&
                         payload_extracted->payloads->fuses == source.payloads->fuses,
                     "extraction preserves parsed virtual-fuse bytes") ||
            !require(payload_extracted->payloads.has_value() &&
                         payload_extracted->payloads->xell == source.payloads->xell,
                     "an exact JTAG XeLL makes adjacent payload extraction unambiguous")) {
            return false;
        }

        payload_extracted->metadata.nand_image.reset();
        const auto rebuilt = run_build(*payload_extracted);
        const auto roundtrip =
            rebuilt ? extract_all(*rebuilt, payload_extracted->metadata.cpu_key) : not_built;
        return require(roundtrip.has_value() && roundtrip->payloads.has_value() &&
                           roundtrip->payloads->rebooter == source.payloads->rebooter,
                       "rebuilt rebooter remains serialized-identical") &&
               require(roundtrip->payloads.has_value() &&
                           roundtrip->payloads->fuses == source.payloads->fuses,
                       "rebuilt virtual fuses remain serialized-identical");
    }

    bool test_metadata_overrides_reach_final_patched_cb_b_and_cf0() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch2;
        auto cb_a = BootloaderCb::parse_or_throw(input.bootloaders.cb_or_a);
        if (!cb_a.parse_perbox()) {
            std::abort();
        }
        cb_a.perbox->lockdown_value = 0x11;
        cb_a.perbox->pairing_data[0] = 0x12;
        cb_a.perbox->pairing_data[1] = 0x13;
        cb_a.perbox->pairing_data[2] = 0x14;
        if (!cb_a.serialize_perbox()) {
            std::abort();
        }
        input.bootloaders.cb_or_a = cb_a.serialize();

        auto cb_b = BootloaderCb::parse_or_throw(input.bootloaders.cb_or_a);
        if (!cb_b.parse_perbox()) {
            std::abort();
        }
        cb_b.perbox->lockdown_value = 0x21;
        cb_b.perbox->pairing_data[0] = 0x22;
        cb_b.perbox->pairing_data[1] = 0x23;
        cb_b.perbox->pairing_data[2] = 0x24;
        if (!cb_b.serialize_perbox()) {
            std::abort();
        }
        input.bootloaders.cb_b = cb_b.serialize();
        input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34});
        const auto update0 = valid_system_update(0x51);
        const auto update1 = valid_system_update(0x61);
        input.bootloaders.cg0 = update0.second;
        input.metadata.cb_ldv = 9;
        input.metadata.cf_ldv = 10;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x100, 0x11223344, 0x30, 0, Bytes{0x91})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        const bool decrypted = parsed && image->decrypt_all(input.metadata.cpu_key);
        const bool cb_a_perbox = decrypted && image->cb_section.cb_or_A.parse_perbox();
        const bool cb_b_perbox = decrypted && image->cb_section.cb_B.has_value() &&
                                 image->cb_section.cb_B->parse_perbox();
        return require(built.has_value(), "metadata override fixture builds") &&
               require(parsed, "metadata override output parses") &&
               require(decrypted, "metadata override output decrypts") &&
               require(cb_a_perbox && cb_b_perbox,
                       "metadata override output CB per-box metadata parses") &&
               require(image->cb_section.cb_B.has_value() &&
                           image->system_update_0.cf.has_value() &&
                           !image->system_update_1.cf.has_value(),
                       "metadata override output contains all replacement bootloaders") &&
               require(image->cb_section.cb_or_A.perbox->lockdown_value == 0x11 &&
                           std::equal(std::begin(image->cb_section.cb_or_A.perbox->pairing_data),
                                      std::end(image->cb_section.cb_or_A.perbox->pairing_data),
                                      std::array<uint8_t, 3>{0x12, 0x13, 0x14}.begin()),
                       "CB_A remains non-authoritative when CB_B is supplied") &&
               require(image->cb_section.cb_B->perbox->lockdown_value == 9 &&
                           std::equal(std::begin(image->cb_section.cb_B->perbox->pairing_data),
                                      std::end(image->cb_section.cb_B->perbox->pairing_data),
                                      input.metadata.pairing_data.begin()),
                       "patched CB_B receives the winning LDV and all pairing bytes") &&
               require(image->system_update_0.cf->perbox->lockdown_value == 10 &&
                           std::equal(std::begin(image->system_update_0.cf->perbox->pairing_data),
                                      std::end(image->system_update_0.cf->perbox->pairing_data),
                                      input.metadata.pairing_data.begin()),
                       "every supplied CF receives the winning LDV and pairing bytes");
    }

    // Under the all-zero CPU key a chain with a CB_B is bound to no console (xeBuild 1.21
    // "zeropairing CB_B"): the CB_B per-box block is zero, the CFs state no pairing and LDV 0,
    // and the secured files state LDV 0, whatever the console's metadata says.
    bool test_zero_cpu_key_zero_pairs_a_cb_b_chain() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch2;
        input.metadata.cpu_key.assign(16, 0);
        input.metadata.keyvault =
            canonical_keyvault(input.metadata.cpu_key, Bytes(Keyvault::kSize, 0x22));
        input.bootloaders.cb_b = input.bootloaders.cb_or_a;
        input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34});
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.metadata.cb_ldv = 9;
        input.metadata.cf_ldv = 10;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
        input.metadata.cf_pairing_data = std::array<uint8_t, 3>{0xA4, 0xB5, 0xC6};
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"secdata.bin", Bytes{}}};
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x100, 0x11223344, 0x30, 0, Bytes{0x91})};
        input.patches = std::move(patches);

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool decrypted =
            image && image->parse() && image->decrypt_all(input.metadata.cpu_key);
        const bool cb_b_perbox = decrypted && image->cb_section.cb_B.has_value() &&
                                 image->cb_section.cb_B->parse_perbox();
        const auto* perbox = cb_b_perbox ? &*image->cb_section.cb_B->perbox : nullptr;
        const auto* perbox_bytes = reinterpret_cast<const uint8_t*>(perbox);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        const Bytes* secdata = nullptr;
        if (extracted && extracted->flashfs_sec) {
            for (const auto& [name, data] : *extracted->flashfs_sec) {
                if (name == "secdata.bin") {
                    secdata = &data;
                }
            }
        }
        return require(built.has_value() && decrypted && cb_b_perbox,
                       "a zero-key CB_B chain builds and opens under the zero key") &&
               require(std::all_of(perbox_bytes, perbox_bytes + sizeof(cb_perbox),
                                   [](uint8_t byte) { return byte == 0; }),
                       "the zero-key CB_B states no pairing, no LDV and no digest") &&
               require(image->system_update_0.cf.has_value() &&
                           image->system_update_0.cf->perbox->lockdown_value == 0 &&
                           std::all_of(std::begin(image->system_update_0.cf->perbox->pairing_data),
                                       std::end(image->system_update_0.cf->perbox->pairing_data),
                                       [](uint8_t byte) { return byte == 0; }),
                       "the zero-key CF states no pairing and LDV 0") &&
               require(extracted && extracted->metadata.keyvault == input.metadata.keyvault,
                       "the keyvault is sealed under the zero key") &&
               require(secdata && secdata->size() == gxbuild3::nand::kSecdataSize &&
                           gxbuild3::nand::secdata_opened(*secdata, input.metadata.cpu_key) &&
                           (*secdata)[0x19] == 0,
                       "the made-up secdata.bin states LDV 0");
    }

    // A console's keyvault does not open under the all-zero CPU key: its donor still extracts
    // and builds, with no keyvault of its own, and the keyvault the build is given is sealed
    // under the zero key.
    bool test_zero_cpu_key_leaves_the_donor_keyvault_sealed() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {});
        const Bytes zero_key(16, 0);
        const auto extracted = extract_all(donor, zero_key);
        if (!require(extracted.has_value() && !extracted->metadata.keyvault.has_value(),
                     "a donor extracts under the zero key without a keyvault") ||
            !require(!extract_metadata(donor, zero_key).has_value(),
                     "metadata extraction needs a keyvault that opens")) {
            return false;
        }

        auto input = source;
        input.metadata.cpu_key = zero_key;
        input.metadata.nand_image = donor;
        const auto built = run_build(input);
        auto image = built ? parse_image(*built) : std::nullopt;
        const bool opened =
            image && image->decrypt_all(zero_key) && image->keyvault && !image->keyvault->encrypted;
        const auto sealed_body = opened ? image->keyvault->serialize() : Bytes{};
        return require(built.has_value(), "a zero-key build over a console's donor succeeds") &&
               require(opened && sealed_body.size() == Keyvault::kSize &&
                           std::equal(sealed_body.begin() + 0x10, sealed_body.end(),
                                      input.metadata.keyvault->begin() + 0x10),
                       "the supplied keyvault is sealed under the zero key");
    }

    bool test_metadata_override_requires_writable_cb_perbox() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.cb_or_a = Bytes(sizeof(generic_header), 0);
        const auto built = run_build(input);
        return require(!built.has_value() &&
                           built.error().code == BuildErrorCode::InvalidBootloader,
                       "unwritable selected CB perbox is a structured bootloader error");
    }

    bool test_present_unwritable_cb_b_remains_metadata_authoritative() {
        auto input = fresh_input(ImageType::SmallBlock);
        auto cb_a = BootloaderCb::parse_or_throw(input.bootloaders.cb_or_a);
        cb_a.data[0x260] = 0x01;
        cb_a.decrypted = false;
        input.bootloaders.cb_or_a = cb_a.serialize();

        BootloaderCb cb_b{};
        cb_b.header.header.magic = NANDBootloaderMagic::CB;
        cb_b.header.header.version = 1;
        cb_b.header.header.size = sizeof(generic_header);
        input.bootloaders.cb_b = cb_b.serialize();

        const auto built = run_build(input);
        return require(
            !built.has_value() && built.error().code == BuildErrorCode::InvalidBootloader,
            "a present header-only CB_B is authoritative and fails metadata structurally");
    }

    bool test_donor_bootloader_chain_is_replaced_by_input_presence() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        auto donor_cb = BootloaderCb::parse_or_throw(donor_input.bootloaders.cb_or_a);
        donor_cb.data[0x260] = 0x01;
        donor_cb.decrypted = false;
        donor_input.bootloaders.cb_or_a = donor_cb.serialize();
        donor_input.bootloaders.cb_x = donor_cb.serialize();
        donor_input.bootloaders.cb_b = donor_cb.serialize();

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + 0x20);
        ce.data.assign(0x20, 0xCE);
        ce.decrypted = true;
        donor_input.bootloaders.ce = ce.serialize();
        donor_input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34});
        donor_input.bootloaders.cg0 = valid_system_update(0x51).second;
        donor_input.bootloaders.cf1 = decrypted_cf(0x41, {0x42, 0x43, 0x44});
        donor_input.bootloaders.cg1 = valid_system_update(0x61).second;
        *donor_input.mobiles.slot(0x31) = Bytes{0xD1, 0x31};

        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "all-optional donor fixture builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.metadata.cb_ldv = 7;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};
        input.bootloaders.cb_x.reset();
        input.bootloaders.cb_b.reset();
        input.bootloaders.sc.reset();
        input.bootloaders.ce.reset();
        input.bootloaders.cf0.reset();
        input.bootloaders.cg0.reset();
        input.bootloaders.cf1.reset();
        input.bootloaders.cg1.reset();

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        const bool decrypted = parsed && image->decrypt_all(input.metadata.cpu_key);
        const bool cb_a_perbox = decrypted && image->cb_section.cb_or_A.parse_perbox();
        const auto* donor_mobile =
            parsed && image->mobile_data ? image->mobile_data->get_slot(0x31) : nullptr;
        return require(built.has_value() && decrypted && cb_a_perbox,
                       "replacement-chain output parses, decrypts, and exposes CB/A metadata") &&
               require(!image->cb_section.cb_x.has_value() && !image->cb_section.cb_B.has_value() &&
                           !image->cb_section.sc.has_value() &&
                           !image->kernel_section.ce.has_value() &&
                           !image->system_update_0.cf.has_value() &&
                           !image->system_update_0.cg.has_value() &&
                           !image->system_update_1.cf.has_value() &&
                           !image->system_update_1.cg.has_value(),
                       "omitted Input bootloaders clear every donor optional stage") &&
               require(image->cb_section.cb_or_A.perbox->lockdown_value == 7,
                       "without donor CB_B, replacement CB/A is metadata-authoritative") &&
               require(donor_mobile && *donor_mobile && **donor_mobile == Bytes({0xD1, 0x31}),
                       "non-bootloader donor mobile data survives replacement");
    }

    bool test_donor_cf_span_is_cleared_when_replacement_omits_cg() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        const auto [donor_cf, donor_cg] = valid_system_update(0x51);
        donor_input.bootloaders.cf0 = donor_cf;
        donor_input.bootloaders.cg0 = donor_cg;
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "donor CF/CG fixture builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.bootloaders.cf0 = donor_cf; // Same size as the donor CF.
        input.bootloaders.cg0.reset();
        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        return require(built.has_value() && parsed && image->system_update_0.cf.has_value(),
                       "replacement CF without CG output parses") &&
               require(!image->system_update_0.cg.has_value(),
                       "replacement CF does not rediscover the donor CG tail");
    }

    bool test_header_only_donor_ce_is_cleared_when_input_omits_it() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.header.header.size = sizeof(ce_header);
        ce.decrypted = true;
        donor_input.bootloaders.ce = ce.serialize();
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "header-only CE donor fixture builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.bootloaders.ce.reset();
        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        return require(built.has_value() && parsed, "header-only CE replacement output parses") &&
               require(!image->kernel_section.ce.has_value(),
                       "omitted header-only donor CE does not reappear");
    }

    bool test_rebuilt_donor_uses_actual_cf_slot_base_for_each_build_type() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        donor_input.build_type = BuildType::Glitch;
        InputPatches donor_patches{};
        donor_patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
        donor_input.patches = donor_patches;
        InputPayloads donor_payloads{};
        donor_payloads.xell = valid_xell();
        donor_input.payloads = donor_payloads;
        const auto [donor_cf, donor_cg] = valid_system_update(0x51);
        donor_input.bootloaders.cf0 = donor_cf;
        donor_input.bootloaders.cg0 = donor_cg;
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value(), "shifted donor fixture builds")) {
            return false;
        }

        struct Case {
            BuildType type;
            size_t expected_slot;
            size_t expected_xell;
        };
        // A devkit image is 64 MB, so it is laid fresh beside this 16 MB donor (see
        // test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor).
        const std::array cases{Case{BuildType::Retail, 0xB0000, 0x70000},
                               Case{BuildType::Jtag, 0x70000, 0x95060}};
        for (const auto& test_case : cases) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            input.build_type = test_case.type;
            if (input.build_type == BuildType::Jtag) {
                mark_jtag_smc(*input.metadata.smc);
            }
            const auto [cf, cg] =
                valid_system_update(static_cast<uint8_t>(0x60 + test_case.expected_slot / 0x10000));
            input.bootloaders.cf0 = cf;
            input.bootloaders.cg0 = cg;
            if (test_case.type == BuildType::Jtag) {
                InputPatches patches{};
                patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA1})};
                input.patches = std::move(patches);
            }

            const auto built = run_build(input);
            auto image = built ? FlashImage::read(*built) : std::nullopt;
            const bool parsed = image && image->parse();
            const auto xell_magic =
                built ? read_logical(*built, test_case.expected_xell, 4) : std::nullopt;
            const auto cg_bytes =
                built ? read_logical(*built, test_case.expected_slot + ((cf.size() + 0x0F) & ~0x0F),
                                     cg.size())
                      : std::nullopt;
            if (!require(built.has_value() && parsed && image->system_update_0.cf.has_value() &&
                             image->system_update_0.cg.has_value(),
                         "rebuilt donor parses requested CF and CG") ||
                !require(image->header.cf_offset == test_case.expected_slot,
                         "serialized header names the actual replacement CF slot") ||
                !require(cg_bytes &&
                             opened_cg(cf, cg) ==
                                 opened_cg(image->system_update_0.cf->serialize(), *cg_bytes),
                         "replacement CG remains intact beside fixed payloads") ||
                !require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                         "retained XeLL remains intact without CF collision")) {
                return false;
            }
        }
        return true;
    }

    bool test_metadata_cf_roundtrip_preserves_extended_header_fields() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34}, 0x1234, 0x5678, 0x9ABC,
                                             0xDEF0, 0x10203040, 0x50607080);
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.metadata.cf_ldv = 10;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        const bool decrypted = parsed && image->decrypt_all(input.metadata.cpu_key);
        return require(built.has_value(), "extended CF metadata fixture builds") &&
               require(decrypted && image->system_update_0.cf.has_value(),
                       "extended CF metadata output parses and decrypts") &&
               require(image->system_update_0.cf->header.source_version == 0x1234,
                       "modified CF preserves source version through encryption") &&
               require(image->system_update_0.cf->header.source_qfe == 0x5678,
                       "modified CF preserves source QFE through encryption") &&
               require(image->system_update_0.cf->header.target_version == 0x9ABC,
                       "modified CF preserves target version through encryption") &&
               require(image->system_update_0.cf->header.target_qfe == 0xDEF0,
                       "modified CF preserves target QFE through encryption") &&
               require(image->system_update_0.cf->header.reserved == 0x10203040,
                       "modified CF preserves reserved value through encryption") &&
               require(image->system_update_0.cf->header.cg_size == 0x50607080,
                       "modified CF preserves CG size through encryption");
    }

    bool test_pairing_only_metadata_updates_every_cf_without_changing_ldv() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34});
        input.bootloaders.cf1 = decrypted_cf(0x41, {0x42, 0x43, 0x44});
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.bootloaders.cg1 = valid_system_update(0x61).second;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        const bool decrypted = parsed && image->decrypt_all(input.metadata.cpu_key);
        return require(built.has_value(), "pairing-only CF metadata fixture builds") &&
               require(decrypted && image->system_update_0.cf.has_value() &&
                           image->system_update_1.cf.has_value(),
                       "pairing-only CF metadata output parses and decrypts") &&
               require(image->system_update_0.cf->perbox.has_value() &&
                           image->system_update_1.cf->perbox.has_value(),
                       "pairing-only CF metadata output exposes both per-boxes") &&
               require(image->system_update_0.cf->perbox->lockdown_value == 0x31 &&
                           image->system_update_1.cf->perbox->lockdown_value == 0x41,
                       "pairing-only metadata leaves CF lockdown values unchanged") &&
               require(std::equal(std::begin(image->system_update_0.cf->perbox->pairing_data),
                                  std::end(image->system_update_0.cf->perbox->pairing_data),
                                  input.metadata.pairing_data.begin()) &&
                           std::equal(std::begin(image->system_update_1.cf->perbox->pairing_data),
                                      std::end(image->system_update_1.cf->perbox->pairing_data),
                                      input.metadata.pairing_data.begin()),
                       "pairing-only metadata writes all three bytes to every CF");
    }

    // A JTAG image's first update pair carries nothing of the console: its CF keeps the
    // per-box block it was supplied with (slot 0, no pairing, no LDV, no binding). The second
    // pair states slot 1, the console's pairing and LDV, and the CPU-key binding at 0x220.
    bool test_jtag_first_update_pair_stays_unbound() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        mark_jtag_smc(*input.metadata.smc);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA1})};
        input.patches = std::move(patches);
        input.bootloaders.cf0 = decrypted_cf(0, {0, 0, 0});
        input.bootloaders.cf1 = decrypted_cf(0x41, {0x42, 0x43, 0x44});
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.bootloaders.cg1 = valid_system_update(0x61).second;
        input.metadata.cf_ldv = 9;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        const bool decrypted = parsed && image->decrypt_all(input.metadata.cpu_key);
        if (!require(built.has_value(), "two-pair JTAG fixture builds") ||
            !require(decrypted && image->system_update_0.cf && image->system_update_1.cf &&
                         image->system_update_0.cf->perbox && image->system_update_1.cf->perbox,
                     "two-pair JTAG output parses and decrypts both CF per-boxes")) {
            return false;
        }
        const auto binding = [&input](const BootloaderCf& cf) {
            auto copy = cf;
            if (!copy.calc_mac(key_1bl, input.metadata.cpu_key.data())) {
                std::abort();
            }
            return std::to_array(copy.perbox->per_box_digest);
        };
        const auto& first = *image->system_update_0.cf->perbox;
        const auto& second = *image->system_update_1.cf->perbox;
        const std::array<uint8_t, 3> no_pairing{};
        const std::array<uint8_t, 16> no_binding{};
        return require(first.update_slot == 0 && first.lockdown_value == 0 &&
                           std::equal(std::begin(first.pairing_data), std::end(first.pairing_data),
                                      no_pairing.begin()),
                       "first JTAG CF states slot 0, no pairing and no LDV") &&
               require(std::equal(std::begin(first.per_box_digest), std::end(first.per_box_digest),
                                  no_binding.begin()),
                       "first JTAG CF carries no CPU-key binding") &&
               require(second.update_slot == 1 && second.lockdown_value == 9 &&
                           std::equal(std::begin(second.pairing_data),
                                      std::end(second.pairing_data),
                                      input.metadata.pairing_data.begin()),
                       "second JTAG CF states slot 1, the console pairing and its LDV") &&
               require(std::to_array(second.per_box_digest) == binding(*image->system_update_1.cf),
                       "second JTAG CF is bound to the CPU key");
    }

    bool test_pairing_only_metadata_rejects_unwritable_cf_perbox() {
        auto input = fresh_input(ImageType::SmallBlock);
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x1EF, 0x5A);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        input.bootloaders.cf0 = cf.serialize();

        const auto built = run_build(input);
        return require(!built.has_value() &&
                           built.error().code == BuildErrorCode::InvalidBootloader,
                       "pairing-only metadata reports an unwritable CF perbox structurally");
    }

    bool test_generic_header_pairing_roundtrips_for_every_bootloader() {
        constexpr uint16_t pairing = 0x1234;
        bool passed = true;

        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.pairing = pairing;
        cb.header.header.size = sizeof(generic_header);
        const auto cb_wire = cb.serialize();
        passed = require(has_big_endian_pairing(cb_wire) &&
                             BootloaderCb::parse_or_throw(cb_wire).header.header.pairing == pairing,
                         "CB generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.pairing = pairing;
        sc.header.header.size = sizeof(sc_header);
        const auto sc_wire = sc.serialize();
        passed =
            require(has_big_endian_pairing(sc_wire) &&
                        test::must(BootloaderSc::parse(sc_wire)).header.header.pairing == pairing,
                    "SC generic pairing is big-endian on wire and host-order after parse") &&
            passed;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.pairing = pairing;
        cd.header.header.size = sizeof(cd_header);
        const auto cd_wire = cd.serialize();
        passed = require(has_big_endian_pairing(cd_wire) &&
                             BootloaderCd::parse_or_throw(cd_wire).header.header.pairing == pairing,
                         "CD generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.pairing = pairing;
        ce.header.header.size = sizeof(ce_header);
        const auto ce_wire = ce.serialize();
        passed =
            require(has_big_endian_pairing(ce_wire) &&
                        test::must(BootloaderCe::parse(ce_wire)).header.header.pairing == pairing,
                    "CE generic pairing is big-endian on wire and host-order after parse") &&
            passed;

        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.pairing = pairing;
        cf.data.assign(0x200, 0);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = true;
        const auto cf_wire = cf.serialize();
        passed = require(has_big_endian_pairing(cf_wire) &&
                             BootloaderCf::parse_or_throw(cf_wire).header.header.pairing == pairing,
                         "CF generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.pairing = pairing;
        cg.header.header.size = sizeof(cg_header);
        const auto cg_wire = cg.serialize();
        passed =
            require(has_big_endian_pairing(cg_wire) &&
                        test::must(BootloaderCg::parse(cg_wire)).header.header.pairing == pairing,
                    "CG generic pairing is big-endian on wire and host-order after parse") &&
            passed;

        cf.encrypt_or_throw(key_1bl);
        const auto encrypted_cf_wire = cf.serialize();
        auto decrypted_cf = BootloaderCf::parse_or_throw(encrypted_cf_wire);
        decrypted_cf.decrypt_or_throw(key_1bl);
        passed = require(has_big_endian_pairing(encrypted_cf_wire) &&
                             decrypted_cf.header.header.pairing == pairing,
                         "CF encrypt/decrypt preserves the generic pairing endian invariant") &&
                 passed;
        return passed;
    }

    bool test_stage_specific_numeric_headers_are_host_order_and_wire_big_endian() {
        bool passed = true;

        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.size = sizeof(cb_header);
        cb.data.assign(sizeof(cb_header) - sizeof(generic_header), 0);
        constexpr size_t console_allow_offset =
            offsetof(cb_header, console_seq_allow) +
            offsetof(ConsoleTypeSeqAllow, console_sequence_allow) - sizeof(generic_header);
        cb.data[console_allow_offset] = 0x12;
        cb.data[console_allow_offset + 1] = 0x34;
        const auto parsed_cb = BootloaderCb::parse_or_throw(cb.serialize());
        passed = require(parsed_cb.header.console_seq_allow.console_sequence_allow == 0x1234,
                         "CB console sequence allowance is normalized after parse") &&
                 passed;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.size = sizeof(cd_header);
        cd.header.padding = 0x1234;
        const auto cd_wire = cd.serialize();
        passed = require(read_be16(cd_wire, offsetof(cd_header, padding)) == 0x1234 &&
                             BootloaderCd::parse_or_throw(cd_wire).header.padding == 0x1234,
                         "CD padding is host-order after parse and big-endian on wire") &&
                 passed;

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.size = sizeof(ce_header);
        ce.header.address = 0x0102030405060708ULL;
        ce.header.size = 0x11223344;
        ce.header.padding = 0x55667788;
        const auto ce_wire = ce.serialize();
        const auto parsed_ce = test::must(BootloaderCe::parse(ce_wire));
        passed =
            require(read_be64(ce_wire, offsetof(ce_header, address)) == 0x0102030405060708ULL &&
                        read_be32(ce_wire, offsetof(ce_header, size)) == 0x11223344 &&
                        read_be32(ce_wire, offsetof(ce_header, padding)) == 0x55667788 &&
                        parsed_ce.header.address == 0x0102030405060708ULL &&
                        parsed_ce.header.size == 0x11223344 &&
                        parsed_ce.header.padding == 0x55667788,
                    "CE address, size, and padding retain host/wire endian invariants") &&
            passed;

        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.size = sizeof(cg_header) + 0x40;
        cg.header.source_size = 0x10203040;
        cg.header.target_size = 0x50607080;
        cg.data.assign(0x40, 0x33);
        const auto cg_wire = cg.serialize();
        auto parsed_cg = test::must(BootloaderCg::parse(cg_wire));
        passed =
            require(
                read_be32(cg_wire, offsetof(cg_header, source_size)) == 0x10203040 &&
                    read_be32(cg_wire, offsetof(cg_header, target_size)) == 0x50607080 &&
                    parsed_cg.header.source_size == 0x10203040 &&
                    parsed_cg.header.target_size == 0x50607080,
                "CG source and target sizes are host-order after parse and big-endian on wire") &&
            passed;

        parsed_cg.decrypted = true;
        test::must(parsed_cg.encrypt(key_1bl));
        auto crypt_roundtrip_cg = test::must(BootloaderCg::parse(parsed_cg.serialize()));
        test::must(crypt_roundtrip_cg.decrypt(key_1bl));
        return require(passed && crypt_roundtrip_cg.header.source_size == 0x10203040 &&
                           crypt_roundtrip_cg.header.target_size == 0x50607080,
                       "CG encrypt/decrypt preserves normalized source and target sizes");
    }

    BootloaderCb asymmetric_decrypted_cb(uint16_t wire_console_allow) {
        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.data.assign(std::max<size_t>(0x380, sizeof(cb_header) - sizeof(generic_header)), 0);
        cb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + cb.data.size());
        constexpr size_t console_allow_offset =
            offsetof(cb_header, console_seq_allow) +
            offsetof(ConsoleTypeSeqAllow, console_sequence_allow) - sizeof(generic_header);
        cb.data[console_allow_offset] = static_cast<uint8_t>(wire_console_allow >> 8);
        cb.data[console_allow_offset + 1] = static_cast<uint8_t>(wire_console_allow);
        for (size_t index = 0; index < sizeof(cb_perbox); ++index) {
            cb.data[0x10 + index] = static_cast<uint8_t>(0x80 + index);
        }
        cb.decrypted = true;
        return cb;
    }

    bool test_cb_console_allow_host_value_serializes_without_overwriting_perbox() {
        constexpr size_t console_allow_wire_offset =
            offsetof(cb_header, console_seq_allow) +
            offsetof(ConsoleTypeSeqAllow, console_sequence_allow);
        auto cb = BootloaderCb::parse_or_throw(asymmetric_decrypted_cb(0x1357).serialize());
        const Bytes original_perbox(cb.data.begin() + 0x10,
                                    cb.data.begin() + 0x10 + sizeof(cb_perbox));
        cb.header.console_seq_allow.console_sequence_allow = 0xBEEF;
        const auto wire = cb.serialize();
        return require(cb.header.console_seq_allow.console_sequence_allow == 0xBEEF,
                       "decrypted CB exposes the asymmetric console allowance in host order") &&
               require(
                   read_be16(wire, console_allow_wire_offset) == 0xBEEF,
                   "decrypted CB serialization writes the host-order console allowance to wire") &&
               require(
                   std::equal(original_perbox.begin(), original_perbox.end(),
                              wire.begin() + sizeof(generic_header) + 0x10),
                   "serializing the CB numeric field preserves separately stored per-box bytes");
    }

    bool test_cb_console_allow_host_value_encrypts_and_roundtrips_asymmetrically() {
        auto cb = BootloaderCb::parse_or_throw(asymmetric_decrypted_cb(0x1357).serialize());
        const Bytes original_perbox(cb.data.begin() + 0x10,
                                    cb.data.begin() + 0x10 + sizeof(cb_perbox));
        cb.header.console_seq_allow.console_sequence_allow = 0xBEEF;
        cb.encrypt_or_throw(key_1bl);
        auto parsed_encrypted = BootloaderCb::parse_or_throw(cb.serialize());
        parsed_encrypted.decrypt_or_throw(key_1bl);
        return require(
                   parsed_encrypted.header.console_seq_allow.console_sequence_allow == 0xBEEF,
                   "encrypted CB roundtrip retains the host-order asymmetric console allowance") &&
               require(
                   std::equal(original_perbox.begin(), original_perbox.end(),
                              parsed_encrypted.data.begin() + 0x10),
                   "CB encryption only synchronizes its numeric console field, not per-box bytes");
    }

    bool test_direct_payload_layout_rejects_header_only_required_records() {
        FlashImage header_only_cb{};
        header_only_cb.cb_section.cb_or_A.header.header.magic = NANDBootloaderMagic::CB;
        header_only_cb.cb_section.cb_or_A.header.header.size = sizeof(generic_header);

        FlashImage header_only_cd{};
        const auto bootloaders = valid_bootloaders();
        header_only_cd.cb_section.cb_or_A = BootloaderCb::parse_or_throw(bootloaders.cb_or_a);
        header_only_cd.kernel_section.cd.header.header.magic = NANDBootloaderMagic::CD;
        header_only_cd.kernel_section.cd.header.header.size = sizeof(cd_header);

        const auto cb_layout = header_only_cb.payload_layout();
        const auto cd_layout = header_only_cd.payload_layout();
        return require(!cb_layout && cb_layout.error().message.find("CB/A") != std::string::npos,
                       "direct layout validation rejects a header-only required CB/A") &&
               require(!cd_layout && cd_layout.error().message.find("CD") != std::string::npos,
                       "direct layout validation rejects a header-only required CD");
    }

    bool test_required_chain_relationships_reject_before_serialization() {
        auto header_only_cd = fresh_input(ImageType::SmallBlock);
        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = sizeof(cd_header);
        header_only_cd.bootloaders.cd = cd.serialize();
        const auto missing_cd_payload = run_build(header_only_cd);

        auto cg0_without_cf0 = fresh_input(ImageType::SmallBlock);
        cg0_without_cf0.bootloaders.cg0 = valid_system_update(0x51).second;
        const auto orphan_cg0 = run_build(cg0_without_cf0);

        auto cg1_without_cf1 = fresh_input(ImageType::SmallBlock);
        cg1_without_cf1.bootloaders.cg1 = valid_system_update(0x61).second;
        const auto orphan_cg1 = run_build(cg1_without_cf1);

        return require(!missing_cd_payload &&
                           missing_cd_payload.error().code == BuildErrorCode::InvalidBootloader,
                       "a header-only required CD is rejected before output") &&
               require(!orphan_cg0 && orphan_cg0.error().code == BuildErrorCode::InvalidInput,
                       "CG0 without CF0 is rejected structurally") &&
               require(!orphan_cg1 && orphan_cg1.error().code == BuildErrorCode::InvalidInput,
                       "CG1 without CF1 is rejected structurally");
    }

    void set_source_date_epoch(const char* value) {
#ifdef _WIN32
        _putenv_s("SOURCE_DATE_EPOCH", value ? value : "");
#else
        if (value) {
            setenv("SOURCE_DATE_EPOCH", value, 1);
        } else {
            unsetenv("SOURCE_DATE_EPOCH");
        }
#endif
    }

    // An extended.bin or secdata.bin of the wrong length or that nothing supplied, an
    // extended.bin that opens under no key and the console's own secdata.bin when it does not
    // open are made up clean, as xeBuild 1.21 makes them up: zero but the keyvault's head in
    // extended.bin, and the console's head (or a drawn one), 1, the lockdown value and the stamp
    // in secdata.bin. A supplied secdata.bin of the right length that does not open is written
    // as it stands.
    bool test_unusable_extended_and_secdata_are_made_up_clean() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto cpu_key = input.metadata.cpu_key;
        const auto keyvault = *input.metadata.keyvault;
        input.metadata.cf_ldv = 9;
        constexpr int64_t kSeconds = 1791105722;
        const auto stamp = gxbuild3::nand::secured_file_stamp(kSeconds);
        const auto build_and_open = [&](const Input& build) -> Result<Input> {
            set_source_date_epoch("1791105722");
            const auto image = run_build(build);
            set_source_date_epoch(nullptr);
            return image ? extract_all(*image, cpu_key) : not_built;
        };
        const auto file = [](const Result<Input>& from, std::string_view name) -> const Bytes* {
            if (!from || !from->flashfs_sec) {
                return nullptr;
            }
            for (const auto& [file_name, data] : *from->flashfs_sec) {
                if (file_name == name) {
                    return &data;
                }
            }
            return nullptr;
        };
        const auto zero_from = [](const Bytes& data, size_t from) {
            return std::all_of(data.begin() + static_cast<std::ptrdiff_t>(from), data.end(),
                               [](uint8_t value) { return value == 0; });
        };
        const auto clean_extended_file = [&](const Bytes* data) {
            return data && data->size() == gxbuild3::nand::kExtendedSize &&
                   gxbuild3::nand::extended_opened(*data, cpu_key) &&
                   std::equal(keyvault.begin() + 0x10, keyvault.begin() + 0x18,
                              data->begin() + 0x10) &&
                   zero_from(*data, 0x18);
        };
        const auto clean_secdata_file = [&](const Bytes* data) {
            return data && data->size() == gxbuild3::nand::kSecdataSize &&
                   gxbuild3::nand::secdata_opened(*data, cpu_key) && (*data)[0x18] == 0x01 &&
                   (*data)[0x19] == 9 &&
                   std::all_of(data->begin() + 0x1A, data->begin() + 0x20,
                               [](uint8_t value) { return value == 0; }) &&
                   std::equal(stamp.begin(), stamp.end(), data->begin() + 0x20) &&
                   zero_from(*data, 0x28);
        };

        // Wrong lengths: the console's own secdata.bin opens, so its head is taken.
        const auto own_secdata = clear_secdata(input, 0x66);
        input.metadata.console_secured_files = {{"secdata.bin", own_secdata}};
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"extended.bin", Bytes(0x10, 0x42)}, {"secdata.bin", Bytes(0x3FF, 0x31)}};
        const auto wrong_length = build_and_open(input);
        const auto* short_secdata = file(wrong_length, "secdata.bin");

        // Nothing supplied: no console copy, so the head is drawn.
        input.metadata.console_secured_files.clear();
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"extended.bin", Bytes{}},
                                                                       {"secdata.bin", Bytes{}}};
        const auto unsupplied = build_and_open(input);

        // An extended.bin that opens under no key and the console's own secdata.bin that does
        // not open are made up clean; another secdata.bin that does not open stands.
        const Bytes unopened_secdata(gxbuild3::nand::kSecdataSize, 0x31);
        input.metadata.console_secured_files = {{"secdata.bin", unopened_secdata}};
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"extended.bin", Bytes(gxbuild3::nand::kExtendedSize, 0x42)},
            {"secdata.bin", unopened_secdata}};
        const auto unopened = build_and_open(input);
        input.flashfs_sec->back().second = Bytes(gxbuild3::nand::kSecdataSize, 0x32);
        const auto supplied_unopened = build_and_open(input);

        return require(clean_extended_file(file(wrong_length, "extended.bin")) &&
                           clean_secdata_file(short_secdata) &&
                           std::equal(own_secdata.begin() + 0x10, own_secdata.begin() + 0x18,
                                      short_secdata->begin() + 0x10),
                       "copies of the wrong length are made up clean, secdata.bin under the "
                       "console's head") &&
               require(clean_extended_file(file(unsupplied, "extended.bin")) &&
                           clean_secdata_file(file(unsupplied, "secdata.bin")),
                       "files nothing supplied are made up clean") &&
               require(clean_extended_file(file(unopened, "extended.bin")) &&
                           clean_secdata_file(file(unopened, "secdata.bin")),
                       "an extended.bin and the console's secdata.bin that do not open are made "
                       "up clean") &&
               require(file(supplied_unopened, "secdata.bin") &&
                           *file(supplied_unopened, "secdata.bin") ==
                               Bytes(gxbuild3::nand::kSecdataSize, 0x32),
                       "a supplied secdata.bin that does not open is written as it stands");
    }

    // A built FlashFS is laid as xeBuild 1.21 lays it: the CG tail first, directly past the
    // update slots, then the listed files back to back in their order, the settings blobs and
    // the root behind them, every entry stamped with the build's time plus two seconds. Its
    // table states the root as itself, the blobs free, the four settings blocks reserved and
    // the remap pool after them as nothing.
    bool test_flashfs_is_laid_as_xebuild_lays_it() {
        using BlockMapStatus = gxbuild3::nand::BlockMapStatus;
        auto input = fresh_input(ImageType::SmallBlock);
        const auto [cf0, ignored_cg0] = valid_system_update(0x51);
        BootloaderCg cg0{};
        cg0.header.header.magic = NANDBootloaderMagic::CG;
        cg0.header.header.version = 1;
        cg0.data.assign(0x10000, 0x7A);
        cg0.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg0.data.size());
        input.bootloaders.cf0 = cf0;
        input.bootloaders.cg0 = cg0.serialize();
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"zeta.bin", Bytes(0x4001, 0x5A)}, {"alpha.bin", Bytes(0x10, 0x41)}};
        *input.mobiles.slot(0x31) = Bytes(0x800, 0x31);

        // 2026-10-04 09:22:02 UTC: in UTC the entries say 09:22:04, 0x5D444AC2.
        const auto built = [&] {
            const ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105722");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        }();
        const auto image = built ? parse_image(*built) : std::nullopt;
        if (!require(image.has_value() && image->filesystem.has_value(),
                     "a FlashFS build with a CG tail parses")) {
            return false;
        }
        const auto& fs = *image->filesystem;
        const auto& entries = fs.entries();
        const std::array<std::string_view, 3> names{"sysupdate.xexp1", "zeta.bin", "alpha.bin"};
        bool listed = entries.size() == names.size();
        for (size_t i = 0; listed && i < names.size(); ++i) {
            listed = std::string_view(entries[i].filename) == names[i] &&
                     entries[i].timestamp == 0x5D444AC2;
        }
        if (!require(listed, "the CG tail is listed first, then the files in their order, each "
                             "stamped with the build's time")) {
            return false;
        }
        const size_t first = (image->header.cf_offset + 2 * 0x10000) / 0x4000;
        const auto tail = fs.get_chain(entries[0].block_number);
        const size_t root = fs.root_block();
        const auto& map = fs.blockmap();
        return require(entries[0].block_number == first &&
                           map[first - 1] == BlockMapStatus::Reserved,
                       "the CG tail starts on the first block past the update slots") &&
               require(image->system_update_0.cg_spill_blocks == tail,
                       "the CF names the CG tail's blocks") &&
               require(entries[1].block_number == first + tail.size() &&
                           entries[2].block_number == entries[1].block_number + 2,
                       "the files follow back to back") &&
               require(map[entries[2].block_number + 1] == BlockMapStatus::Free &&
                           root == entries[2].block_number + 2u,
                       "the settings blob follows the files, stated free, and the root it") &&
               require(map[root] == BlockMapStatus::Table, "the root states itself") &&
               require(map[0x3DB] == BlockMapStatus::Free &&
                           map[0x3DC] == BlockMapStatus::Reserved &&
                           map[0x3DF] == BlockMapStatus::Reserved &&
                           map[0x3E0] == BlockMapStatus::Unnamed &&
                           map[0x3FF] == BlockMapStatus::Unnamed,
                       "the settings blocks are reserved and the remap pool never named");
    }

    bool test_system_update_slot_zero_spills_and_preserves_slot_one() {
        auto input = fresh_input(ImageType::SmallBlock);
        const auto [cf0, ignored_cg0] = valid_system_update(0x51);
        const auto [cf1, cg1] = valid_system_update(0x61);
        BootloaderCg cg0{};
        cg0.header.header.magic = NANDBootloaderMagic::CG;
        cg0.header.header.version = 1;
        cg0.data.assign(0x10000, 0x7A);
        cg0.header.header.size = static_cast<uint32_t>(sizeof(cg_header) + cg0.data.size());
        input.bootloaders.cf0 = cf0;
        input.bootloaders.cg0 = cg0.serialize();
        input.bootloaders.cf1 = cf1;
        input.bootloaders.cg1 = cg1;

        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        return require(image && image->parse() && image->header.patch_slots == 2 &&
                           !image->system_update_0.cg_spill_blocks.empty() &&
                           image->system_update_1.cf && image->system_update_1.cg &&
                           opened_cg(image->system_update_0.cf->serialize(),
                                     image->system_update_0.cg->serialize()) ==
                               opened_cg(cf0, cg0.serialize()) &&
                           opened_cg(image->system_update_1.cf->serialize(),
                                     image->system_update_1.cg->serialize()) == opened_cg(cf1, cg1),
                       "slot-zero CG spills while both supplied update slots survive");
    }

    bool test_replacement_layout_overrides_a_one_slot_donor_header() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        const auto donor = run_build(donor_input);
        auto donor_image = donor ? FlashImage::read(*donor) : std::nullopt;
        const bool donor_parsed = donor_image && donor_image->parse();
        const std::array<uint8_t, 2> one_slot{{0x00, 0x01}};
        const bool donor_patched =
            donor_parsed &&
            donor_image->flash_driver.write_offset(offsetof(nand_header, patch_slots), one_slot);
        auto patched_donor =
            donor_patched ? FlashImage::read(donor_image->flash_driver.serialize()) : std::nullopt;
        const bool patched_donor_parsed = patched_donor && patched_donor->parse();

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = donor_patched ? donor_image->flash_driver.serialize() : Bytes{};
        const auto [cf0, cg0] = valid_system_update(0x51);
        const auto [cf1, cg1] = valid_system_update(0x61);
        input.bootloaders.cf0 = cf0;
        input.bootloaders.cg0 = cg0;
        input.bootloaders.cf1 = cf1;
        input.bootloaders.cg1 = cg1;

        const auto built = run_build(input);
        auto image = built ? FlashImage::read(*built) : std::nullopt;
        const bool parsed = image && image->parse();
        return require(patched_donor_parsed && patched_donor->header.patch_slots == 1,
                       "one-slot donor header fixture is created") &&
               require(built.has_value() && parsed,
                       "two-slot replacement over one-slot donor builds") &&
               require(image->header.patch_slots == 2, "replacement layout writes two patch slots "
                                                       "instead of preserving donor header") &&
               require(image->system_update_0.cf.has_value() &&
                           image->system_update_0.cg.has_value() &&
                           image->system_update_1.cf.has_value() &&
                           image->system_update_1.cg.has_value(),
                       "both replacement CF/CG slots parse from the advertised two-slot layout");
    }

    Bytes valid_ce() {
        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + 0x20);
        std::fill(std::begin(ce.header.key), std::end(ce.header.key), uint8_t{0x55});
        ce.data.assign(0x20, 0xCE);
        ce.decrypted = true;
        return ce.serialize();
    }

    BootloaderNonce filled_nonce(uint8_t value) {
        BootloaderNonce nonce{};
        nonce.fill(value);
        return nonce;
    }

    Bytes nonce_bytes(std::span<const uint8_t> bytes) {
        return Bytes(bytes.begin(), bytes.begin() + 0x10);
    }

    bool test_fresh_build_seals_stages_under_random_nonces() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.ce = valid_ce();
        const auto first = run_build(input);
        const auto second = run_build(input);
        auto one = first ? parse_image(*first) : std::nullopt;
        auto two = second ? parse_image(*second) : std::nullopt;
        if (!require(one && two && one->kernel_section.ce && two->kernel_section.ce,
                     "fresh nonce fixtures build and parse")) {
            return false;
        }
        const auto nonces = [](const FlashImage& image) {
            return std::array<Bytes, 3>{nonce_bytes(image.cb_section.cb_or_A.data),
                                        nonce_bytes(image.kernel_section.cd.header.key),
                                        nonce_bytes(image.kernel_section.ce->header.key)};
        };
        const auto first_nonces = nonces(*one);
        const auto second_nonces = nonces(*two);
        bool distinct = true;
        bool non_zero = true;
        for (size_t index = 0; index < first_nonces.size(); ++index) {
            distinct = distinct && first_nonces[index] != second_nonces[index];
            non_zero = non_zero && first_nonces[index] != Bytes(0x10, 0);
        }
        const bool decrypted = one->decrypt_all(input.metadata.cpu_key).has_value();
        return require(non_zero, "fresh CB, CD and CE take non-zero nonces") &&
               require(first_nonces[2] != Bytes(0x10, 0x55),
                       "a fresh CE does not keep its template's nonce") &&
               require(distinct, "each fresh build draws new nonces") &&
               require(decrypted && one->kernel_section.cd.data == Bytes(0x20, 0x42) &&
                           one->kernel_section.ce->data == Bytes(0x20, 0xCE),
                       "stages sealed under fresh nonces decrypt to their payloads");
    }

    bool test_donor_nonces_seal_stages_by_position_and_every_slot_alike() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.ce = valid_ce();
        input.bootloaders.cf0 = decrypted_cf(3, {0x11, 0x12, 0x13});
        input.bootloaders.cg0 = valid_system_update(0x51).second;
        input.bootloaders.cf1 = decrypted_cf(4, {0x11, 0x12, 0x13});
        input.bootloaders.cg1 = valid_system_update(0x61).second;
        DonorNonces nonces{};
        nonces.stages = {filled_nonce(0xA1), filled_nonce(0xA2), filled_nonce(0xA3),
                         filled_nonce(0xA4)};
        nonces.cf = filled_nonce(0xB1);
        nonces.cg = filled_nonce(0xC1);
        input.metadata.donor_nonces = nonces;

        const auto built = run_build(input);
        auto image = built ? parse_image(*built) : std::nullopt;
        if (!require(image && image->kernel_section.ce && image->system_update_0.cf &&
                         image->system_update_0.cg && image->system_update_1.cf &&
                         image->system_update_1.cg,
                     "donor nonce fixture builds and parses")) {
            return false;
        }
        const auto is = [](std::span<const uint8_t> bytes, uint8_t value) {
            return nonce_bytes(bytes) == Bytes(0x10, value);
        };
        const bool decrypted = image->decrypt_all(input.metadata.cpu_key).has_value();
        return require(is(image->cb_section.cb_or_A.data, 0xA1) &&
                           is(image->kernel_section.cd.header.key, 0xA3) &&
                           is(image->kernel_section.ce->header.key, 0xA4),
                       "first CB, CD and CE take the donor nonces of their positions") &&
               require(is(image->system_update_0.cf->header.fixpoint_nonce, 0xB1) &&
                           is(image->system_update_1.cf->header.fixpoint_nonce, 0xB1) &&
                           is(image->system_update_0.cg->header.key, 0xC1) &&
                           is(image->system_update_1.cg->header.key, 0xC1),
                       "every update slot takes the donor CF and CG nonces") &&
               require(decrypted && image->kernel_section.cd.data == Bytes(0x20, 0x42) &&
                           image->kernel_section.ce->data == Bytes(0x20, 0xCE),
                       "stages sealed under donor nonces decrypt to their payloads");
    }

    bool test_extraction_takes_cf_metadata_and_nonces_from_the_max_ldv_slot() {
        auto source = fresh_input(ImageType::SmallBlock);
        source.bootloaders.ce = valid_ce();
        source.bootloaders.cf0 = decrypted_cf(3, {0x11, 0x12, 0x13});
        source.bootloaders.cg0 = valid_system_update(0x51).second;
        source.bootloaders.cf1 = decrypted_cf(7, {0x11, 0x12, 0x13});
        source.bootloaders.cg1 = valid_system_update(0x61).second;
        source.metadata.pairing_data = {0x21, 0x22, 0x23};
        const auto built = run_build(source);

        // Slot 1 states its own pairing, as after an update installed under other pairing.
        auto staged = built ? parse_image(*built) : std::nullopt;
        if (!require(staged && staged->decrypt_all(source.metadata.cpu_key) &&
                         staged->system_update_1.cf && staged->system_update_1.cf->perbox,
                     "max-LDV donor fixture builds and decrypts")) {
            return false;
        }
        const std::array<uint8_t, 3> slot_one_pairing{0x31, 0x32, 0x33};
        std::copy(slot_one_pairing.begin(), slot_one_pairing.end(),
                  staged->system_update_1.cf->perbox->pairing_data);
        if (!require(staged->encrypt_all(source.metadata.cpu_key),
                     "max-LDV donor fixture re-encrypts")) {
            return false;
        }
        const auto donor = staged->write().value_or(Bytes{});
        auto donor_image = parse_image(donor);
        const auto extracted = extract_all(donor, source.metadata.cpu_key);
        const auto metadata = extract_metadata(donor, source.metadata.cpu_key);
        if (!require(donor_image && extracted && metadata && extracted->metadata.donor_nonces &&
                         metadata->donor_nonces,
                     "max-LDV donor fixture extracts")) {
            return false;
        }
        const auto& nonces = *extracted->metadata.donor_nonces;
        const auto equal = [](const std::optional<BootloaderNonce>& nonce,
                              std::span<const uint8_t> bytes) {
            return nonce && Bytes(nonce->begin(), nonce->end()) == nonce_bytes(bytes);
        };
        const bool cf_metadata = extracted->metadata.cf_ldv == 7 &&
                                 extracted->metadata.cf_pairing_data == slot_one_pairing &&
                                 metadata->cf_ldv == 7 &&
                                 metadata->cf_pairing_data == slot_one_pairing;
        const bool slot_nonces =
            equal(nonces.cf, donor_image->system_update_1.cf->header.fixpoint_nonce) &&
            equal(nonces.cg, donor_image->system_update_1.cg->header.key);
        const bool stage_order =
            equal(nonces.stages[0], donor_image->cb_section.cb_or_A.data) && !nonces.stages[1] &&
            equal(nonces.stages[2], donor_image->kernel_section.cd.header.key) &&
            equal(nonces.stages[3], donor_image->kernel_section.ce->header.key);

        auto rebuild = *extracted;
        rebuild.bootloaders = source.bootloaders;
        const auto rebuilt = run_build(rebuild);
        auto image = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        const bool rebuilt_decrypts = image && image->decrypt_all(source.metadata.cpu_key);
        return require(cf_metadata, "CF LDV and pairing come from the max-LDV donor slot") &&
               require(slot_nonces, "donor CF and CG nonces come from the max-LDV slot") &&
               require(stage_order, "donor stage nonces are read by chain position") &&
               require(
                   rebuilt_decrypts &&
                       nonce_bytes(image->cb_section.cb_or_A.data) ==
                           nonce_bytes(donor_image->cb_section.cb_or_A.data) &&
                       nonce_bytes(image->system_update_0.cf->header.fixpoint_nonce) ==
                           nonce_bytes(donor_image->system_update_1.cf->header.fixpoint_nonce) &&
                       nonce_bytes(image->system_update_1.cf->header.fixpoint_nonce) ==
                           nonce_bytes(donor_image->system_update_1.cf->header.fixpoint_nonce) &&
                       nonce_bytes(image->system_update_0.cg->header.key) ==
                           nonce_bytes(donor_image->system_update_1.cg->header.key) &&
                       nonce_bytes(image->system_update_1.cg->header.key) ==
                           nonce_bytes(donor_image->system_update_1.cg->header.key),
                   "a rebuild over the donor reuses its CB and max-LDV CF and CG nonces") &&
               require(image->system_update_0.cf->perbox &&
                           image->system_update_0.cf->perbox->lockdown_value == 7 &&
                           std::equal(slot_one_pairing.begin(), slot_one_pairing.end(),
                                      image->system_update_0.cf->perbox->pairing_data),
                       "the rebuilt CF states the max-LDV slot's LDV and pairing");
    }

    bool test_header_states_zero_pairing_and_the_board_copyright() {
        const auto copyright = [](std::string_view year) {
            const std::string text =
                "\xA9 2004-" + std::string(year) + " Microsoft Corporation. All rights reserved.";
            Bytes bytes(0x38, 0);
            std::copy(text.begin(), text.end(), bytes.begin());
            return bytes;
        };
        const auto header_copyright = [](const Bytes& image) {
            return Bytes(image.begin() + 0x10, image.begin() + 0x48);
        };

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.pairing_data = {0x63, 0xDB, 0x01};
        input.console = ConsoleType::Trinity;
        const auto trinity = run_build(input);
        if (!require(trinity.has_value(), "header fixture builds") ||
            !require((*trinity)[4] == 0 && (*trinity)[5] == 0, "header 0x04 states no pairing") ||
            !require(header_copyright(*trinity) == copyright("2010"),
                     "a fresh Trinity image states 2004-2010")) {
            return false;
        }

        // The fixture SMC names a Xenon board, so a Xenon donor is the same board.
        const auto smc = Smc::parse(*input.metadata.smc);
        input.console = ConsoleType::Xenon;
        const auto xenon = run_build(input);
        auto custom = xenon ? parse_image(*xenon) : std::nullopt;
        if (!require(smc && smc->motherboard == gxbuild3::nand::SmcMotherboard::Xenon,
                     "header fixture SMC names a Xenon board") ||
            !require(xenon && header_copyright(*xenon) == copyright("2005"),
                     "a fresh Xenon image states 2004-2005") ||
            !require(custom.has_value(), "header donor parses")) {
            return false;
        }
        const auto donor_copyright = copyright("2006");
        std::copy(donor_copyright.begin(), donor_copyright.end(), custom->header.copyright);
        const auto donor = custom->write().value_or(Bytes{});

        auto same_board = input;
        same_board.metadata.nand_image = donor;
        const auto kept = run_build(same_board);
        auto other_board = same_board;
        other_board.console = ConsoleType::Falcon;
        const auto replaced = run_build(other_board);
        if (!require(kept && header_copyright(*kept) == donor_copyright,
                     "a donor of the same board keeps its own notice") ||
            !require(replaced && header_copyright(*replaced) == copyright("2007"),
                     "a donor of another board takes the target's notice")) {
            return false;
        }

        // A JTAG Jasper states 2008 even over a Jasper donor.
        auto jasper = fresh_input(ImageType::SmallBlock);
        (*jasper.metadata.smc)[0x100] = 0x40;
        jasper.console = ConsoleType::Jasper;
        const auto retail_jasper = run_build(jasper);
        auto jasper_donor = retail_jasper ? parse_image(*retail_jasper) : std::nullopt;
        if (!require(jasper_donor.has_value(), "Jasper header donor builds and parses")) {
            return false;
        }
        std::copy(donor_copyright.begin(), donor_copyright.end(), jasper_donor->header.copyright);
        jasper.metadata.nand_image = jasper_donor->write().value_or(Bytes{});
        const auto kept_jasper = run_build(jasper);
        auto jtag = jasper;
        jtag.build_type = BuildType::Jtag;
        mark_jtag_smc(*jtag.metadata.smc);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13})};
        jtag.patches = std::move(patches);
        const auto jtag_jasper = run_build(jtag);
        return require(kept_jasper && header_copyright(*kept_jasper) == donor_copyright,
                       "a retail Jasper keeps its Jasper donor's notice") &&
               require(jtag_jasper && header_copyright(*jtag_jasper) == copyright("2008"),
                       "a JTAG Jasper over a Jasper donor states 2004-2008");
    }

    bool test_hacked_header_states_boot_flags_two_slots_and_a_zeroed_khv_tail() {
        const auto header_words = [](const BuildResult& image) {
            return image ? std::pair{read_be32(*image, 0x48), read_be32(*image, 0x4C)}
                         : std::pair{~0u, ~0u};
        };
        const auto glitch2 = [](OptionsArgs options) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Glitch2;
            input.bootloaders.cb_b = input.bootloaders.cb_or_a;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0x92})};
            input.patches = std::move(patches);
            input.options = std::move(options);
            return run_build(input);
        };
        const auto jtag = [](OptionsArgs options) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.build_type = BuildType::Jtag;
            mark_jtag_smc(*input.metadata.smc);
            InputPatches patches{};
            patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13})};
            input.patches = std::move(patches);
            input.options = std::move(options);
            return run_build(input);
        };

        // Glitch2 with no options: XeLL on eject, two slots, and the KHV patch slot (0x80000,
        // behind slot zero at 0x70000) zero after its terminator up to 0x84000, erased after.
        const auto plain = glitch2({});
        const auto khv = plain ? read_logical(*plain, 0x80010, 5) : std::nullopt;
        const auto tail = plain ? read_logical(*plain, 0x80015, 0x4000 - 0x15) : std::nullopt;
        const auto past = plain ? read_logical(*plain, 0x84000, 0x10) : std::nullopt;
        if (!require(header_words(plain) == std::pair{1u, 0x12u},
                     "a glitch2 image states 0x48 = 1 and XeLL on eject at 0x4C") ||
            !require(read_be16(*plain, 0x68) == 2, "a glitch2 image states two update slots") ||
            !require(khv == Bytes({0x92, 0xFF, 0xFF, 0xFF, 0xFF}),
                     "the KHV and its terminator open the patch slot") ||
            !require(tail && std::all_of(tail->begin(), tail->end(),
                                         [](uint8_t byte) { return byte == 0; }),
                     "the patch slot is zero from the KHV terminator to 0x4000") ||
            !require(past == Bytes(0x10, 0xFF), "the patch slot past 0x4000 stays erased")) {
            return false;
        }

        OptionsArgs buttons{};
        buttons.xellbutton = "Power";
        buttons.xellbutton2 = "eject";
        buttons.cygnos = true;
        buttons.dualboot = "kiosk";
        OptionsArgs same_button{};
        same_button.xellbutton = "power";
        same_button.xellbutton2 = "power";
        OptionsArgs nodvd{};
        nodvd.nodvd = true;
        OptionsArgs olddvd{};
        olddvd.olddvd = true;
        olddvd.demon = true;
        OptionsArgs dualboot{};
        dualboot.dualboot = "wiredx";
        OptionsArgs dualboot_on_xell{};
        dualboot_on_xell.dualboot = "eject";
        if (!require(header_words(glitch2(buttons)) == std::pair{1u, 0x00011211u},
                     "glitch2 takes both XeLL buttons and cygnos, and no dualboot") ||
            !require(header_words(glitch2(same_button)) == std::pair{1u, 0x00000011u},
                     "a second XeLL button equal to the first is dropped") ||
            !require(header_words(glitch2(nodvd)) == std::pair{1u, 0u},
                     "nodvd leaves a glitch2 image without a XeLL button") ||
            !require(header_words(jtag({})) == std::pair{1u, 0x00040012u},
                     "a JTAG image states the DVD bit and XeLL on eject") ||
            !require(header_words(jtag(nodvd)) == std::pair{1u, 0x00020000u},
                     "nodvd on JTAG states bit 2 and no XeLL button") ||
            !require(header_words(jtag(olddvd)) == std::pair{1u, 0x00010000u},
                     "olddvd on JTAG clears the DVD bits; demon states bit 1") ||
            !require(header_words(jtag(dualboot)) == std::pair{1u, 0x5A040012u},
                     "a JTAG dualboot button lands at 0x4C") ||
            !require(header_words(jtag(dualboot_on_xell)) == std::pair{1u, 0x00040012u},
                     "a dualboot button that starts XeLL is ignored")) {
            return false;
        }

        // Retail states neither word, whatever the options and whatever its donor held.
        auto donor_input = fresh_input(ImageType::SmallBlock);
        const auto donor = run_build(donor_input);
        auto donor_image = donor ? FlashImage::read(*donor) : std::nullopt;
        const std::array<uint8_t, 8> hacked{{0, 0, 0, 1, 0x11, 0x04, 0x00, 0x12}};
        const bool donor_patched =
            donor_image && donor_image->parse() &&
            donor_image->flash_driver.write_offset(offsetof(nand_header, hack_flags), hacked);
        auto retail = fresh_input(ImageType::SmallBlock);
        retail.metadata.nand_image =
            donor_patched ? donor_image->flash_driver.serialize() : Bytes{};
        retail.options = buttons;
        const auto rebuilt = run_build(retail);
        return require(donor_patched, "hacked-header donor fixture is created") &&
               require(header_words(rebuilt) == std::pair{0u, 0u},
                       "a retail image over a hacked donor states 0x48 and 0x4C zero") &&
               require(read_be16(*rebuilt, 0x68) == 2, "a retail image states two update slots");
    }

    bool test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() {
        const auto source = run_build(fresh_input(ImageType::SmallBlock));
        auto donor = source ? FlashImage::read(*source) : std::nullopt;
        if (!require(donor.has_value() && donor->parse(),
                     "source donor for header-only chain parses")) {
            return false;
        }

        BootloaderCb cb{};
        cb.header.header.magic = NANDBootloaderMagic::CB;
        cb.header.header.version = 1;
        cb.header.header.size = sizeof(generic_header);
        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = sizeof(cd_header);
        const auto cb_bytes = cb.serialize();
        const auto cd_bytes = cd.serialize();
        const bool donor_written =
            donor->flash_driver.write_offset(0x8000, Bytes(0x1000, 0)) &&
            donor->flash_driver.write_offset(0x8000, cb_bytes) &&
            donor->flash_driver.write_offset(0x8000 + cb_bytes.size(), cd_bytes);
        const auto header_only_bytes = donor->flash_driver.serialize();
        auto header_only = donor_written ? FlashImage::read(header_only_bytes) : std::nullopt;
        const bool header_only_parsed = header_only && header_only->parse();
        const bool records_are_header_only =
            header_only_parsed && header_only->cb_section.cb_or_A.data.empty() &&
            header_only->cb_section.cb_or_A.header.header.magic == NANDBootloaderMagic::CB &&
            header_only->kernel_section.cd.data.empty() &&
            header_only->kernel_section.cd.header.header.magic == NANDBootloaderMagic::CD;
        const bool cleared = records_are_header_only && header_only->clear_bootloader_chain();
        const auto cleared_bytes = cleared
                                       ? std::as_const(header_only->flash_driver)
                                             .read_offset(0x8000, cb_bytes.size() + cd_bytes.size())
                                       : std::span<const uint8_t>{};
        const bool all_zero = std::all_of(cleared_bytes.begin(), cleared_bytes.end(),
                                          [](uint8_t value) { return value == 0; });

        auto invalid_replacement = fresh_input(ImageType::SmallBlock);
        invalid_replacement.bootloaders.cd = cd_bytes;
        const auto rejected = run_build(invalid_replacement);
        return require(donor_written && records_are_header_only,
                       "raw donor exposes valid parsed header-only CB and CD records") &&
               require(cleared && all_zero,
                       "clearing a donor includes the full header-only CB and CD chain") &&
               require(!rejected && rejected.error().code == BuildErrorCode::InvalidBootloader,
                       "a replacement header-only required CD remains structurally invalid");
    }

    bool all_bytes(std::span<const uint8_t> bytes, uint8_t value) {
        return !bytes.empty() &&
               std::all_of(bytes.begin(), bytes.end(), [value](uint8_t b) { return b == value; });
    }

    // Every page from `first_page` on: 0xFF data and an erased spare.
    bool pages_are_erased(const Driver& driver, size_t first_page, size_t page_count) {
        for (size_t page = first_page; page < first_page + page_count; ++page) {
            if (!all_bytes(driver.read_page(page), 0xFF) ||
                !all_bytes(driver.read_page_spare(page), 0xFF)) {
                return false;
            }
        }
        return true;
    }

    bool test_donor_build_leaves_unlaid_space_erased() {
        const auto initial = run_build(fresh_input(ImageType::SmallBlock));
        auto donor = initial ? FlashImage::read(*initial) : std::nullopt;
        if (!require(donor.has_value(), "erased-fill donor image opens")) {
            return false;
        }

        // A donor's old data in update slot 1, in a free filesystem block and in the remap
        // pool, each block programmed with a data spare; and one block the chip marked bad.
        constexpr size_t kSlotOneBlock = 0x80000 / 0x4000;
        constexpr size_t kStaleBlock = 0x3B0;
        constexpr size_t kPoolBlock = 0x3F0;
        constexpr size_t kBadBlock = 0x3C0;
        for (const size_t block : {kSlotOneBlock, kStaleBlock, kPoolBlock}) {
            BlockMetadata stale{};
            stale.logical_block_id = static_cast<uint16_t>(block);
            stale.block_type = 0x28;
            if (!require(donor->flash_driver.write_block(block, Bytes(0x4000, 0x5A)),
                         "the donor's old data is laid")) {
                return false;
            }
            donor->flash_driver.write_block_metadata(block, stale);
        }
        donor->flash_driver.mark_bad_block(kBadBlock);

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = donor->flash_driver.serialize();
        const auto built = run_build(input);
        const auto image = built ? parse_image(*built) : std::nullopt;
        if (!require(image.has_value(), "a build over a donor with old data parses")) {
            return false;
        }
        const auto& driver = image->flash_driver;
        const size_t pages = driver.pages_per_block();

        // The header block is zero from the header to the SMC; the boot chain's last 16 KiB
        // block is zero past its end; the rest up to the first update slot is erased.
        const auto smc_offset = driver.read_clean(0x7C, 4);
        const size_t smc_at = smc_offset.size() == 4
                                  ? (size_t(smc_offset[0]) << 24) | (size_t(smc_offset[1]) << 16) |
                                        (size_t(smc_offset[2]) << 8) | smc_offset[3]
                                  : 0;
        size_t chain_end = 0x8000;
        const auto account = [&chain_end](const auto& bootloader) {
            chain_end += (bootloader.serialize().size() + 0xF) & ~size_t{0xF};
        };
        account(image->cb_section.cb_or_A);
        if (image->cb_section.cb_x) {
            account(*image->cb_section.cb_x);
        }
        if (image->cb_section.cb_B) {
            account(*image->cb_section.cb_B);
        }
        if (image->cb_section.sc) {
            account(*image->cb_section.sc);
        }
        account(image->kernel_section.cd);
        if (image->kernel_section.ce) {
            account(*image->kernel_section.ce);
        }
        const size_t pad_end = (chain_end + 0x3FFF) / 0x4000 * 0x4000;

        return require(smc_at > 0x80 && all_bytes(driver.read_clean(0x80, smc_at - 0x80), 0),
                       "the header block is zero from the header to the SMC") &&
               require(pad_end < 0x70000 &&
                           all_bytes(driver.read_clean(chain_end, pad_end - chain_end), 0),
                       "the boot chain's last block is zero past the chain") &&
               require(pages_are_erased(driver, pad_end / 512, (0x70000 - pad_end) / 512),
                       "the blocks between the chain and the first update slot stay erased") &&
               require(pages_are_erased(driver, kSlotOneBlock * pages, 4 * pages),
                       "an unused update slot 1 is erased, not zeroed or left to the donor") &&
               require(pages_are_erased(driver, kStaleBlock * pages, pages),
                       "a donor's old filesystem block is erased") &&
               require(pages_are_erased(driver, kPoolBlock * pages, pages),
                       "a donor's remap-pool block is erased") &&
               require(driver.is_bad_block(kBadBlock), "a block marked bad keeps its mark");
    }

    bool test_emmc_build_leaves_anchor_tails_and_unused_blocks_erased() {
        using gxbuild3::nand::CoronaConfig;
        const auto built = run_build(fresh_input(ImageType::Emmc));
        if (!require(built.has_value() && built->size() == 0x3000000, "an eMMC image builds")) {
            return false;
        }
        const std::span<const uint8_t> bytes(*built);
        bool ok = true;
        for (const size_t anchor : CoronaConfig::kOffsets) {
            ok = require(all_bytes(bytes.subspan(anchor + CoronaConfig::kSize,
                                                 CoronaConfig::kSpan - CoronaConfig::kSize),
                                   0),
                         "an anchor's span is zero after its structure") &&
                 require(all_bytes(bytes.subspan(anchor + CoronaConfig::kSpan,
                                                 CoronaConfig::kBlockSize - CoronaConfig::kSpan),
                                   0xFF),
                         "an anchor's block is erased past its span") &&
                 ok;
        }
        return require(all_bytes(bytes.subspan(0x80000, 0x10000), 0xFF),
                       "an unused eMMC update slot 1 is erased") &&
               require(all_bytes(bytes.subspan(0xB00 * 0x4000, 0x4000), 0xFF),
                       "an unused eMMC block is erased") &&
               ok;
    }

    bool test_bigblock_flashfs_stamps_only_the_clusters_it_fills() {
        auto input = fresh_input(ImageType::BigBlock);
        input.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"small.bin", Bytes(0x100, 0x6B)}};
        const auto built = run_build(input);
        const auto image = built ? parse_image(*built) : std::nullopt;
        const auto entry =
            image && image->filesystem ? image->filesystem->stat("small.bin") : std::nullopt;
        if (!require(entry.has_value(), "a big-block image with one small file parses")) {
            return false;
        }
        const auto& driver = image->flash_driver;
        const size_t clusters_per_block = driver.block_size_clean() / 0x4000;
        const size_t file_cluster = entry->block_number;
        const size_t first_cluster = file_cluster / clusters_per_block * clusters_per_block;
        bool rest_erased = true;
        for (size_t cluster = first_cluster; cluster < first_cluster + clusters_per_block;
             ++cluster) {
            if (cluster != file_cluster && !pages_are_erased(driver, cluster * 32, 32)) {
                rest_erased = false;
            }
        }
        return require(driver.interpret_cluster(file_cluster).block_type == 0x2A,
                       "the file's cluster carries the big-block data stamp") &&
               require(rest_erased, "the rest of the file's big block stays erased");
    }

    // A plaintext devkit chain as a release ships it: SB, SC, SD and SE with zero nonces and
    // a recognizable body each. SE states build 17489.
    InputBootloaders devkit_bootloaders() {
        BootloaderCb sb{};
        sb.header.header.magic = NANDBootloaderMagic::SB;
        sb.header.header.version = 10375;
        // Long enough to hold a whole CB header, so its per-box block reads back.
        sb.data.assign(0x400, 0);
        std::fill(sb.data.begin() + 0x100, sb.data.end(), 0x5B);
        sb.header.header.size = static_cast<uint32_t>(sizeof(generic_header) + sb.data.size());
        sb.decrypted = true;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.version = 17489;
        sc.data.assign(0x48, 0x5C);
        sc.header.header.size = static_cast<uint32_t>(sizeof(sc_header) + sc.data.size());
        sc.decrypted = true;

        BootloaderCd sd{};
        sd.header.header.magic = NANDBootloaderMagic::SD;
        sd.header.header.version = 17489;
        sd.data.assign(0x30, 0x5D);
        sd.header.header.size = static_cast<uint32_t>(sizeof(cd_header) + sd.data.size());
        sd.decrypted = true;

        BootloaderCe se{};
        se.header.header.magic = NANDBootloaderMagic::SE;
        se.header.header.version = 17489;
        se.data.assign(0x42, 0x5E);
        se.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + se.data.size());
        se.decrypted = true;

        InputBootloaders bootloaders{};
        bootloaders.cb_or_a = sb.serialize();
        bootloaders.sc = sc.serialize();
        bootloaders.cd = sd.serialize();
        bootloaders.ce = se.serialize();
        return bootloaders;
    }

    Input devkit_input(ImageType image_type) {
        auto input = fresh_input(image_type);
        input.build_type = BuildType::Devkit;
        input.console = ConsoleType::Jasper;
        input.bootloaders = devkit_bootloaders();
        input.metadata.pairing_data = {0x12, 0x34, 0x56};
        return input;
    }

    std::array<uint8_t, 16> hmac_key(std::span<const uint8_t> parent,
                                     std::span<const uint8_t> nonce) {
        uint8_t digest[20];
        ExCryptHmacSha(parent.data(), static_cast<uint32_t>(parent.size()), nonce.data(),
                       static_cast<uint32_t>(nonce.size()), nullptr, 0, nullptr, 0, digest, 20);
        std::array<uint8_t, 16> key{};
        std::copy_n(digest, key.size(), key.begin());
        return key;
    }

    // A stage opened by hand: its nonce at 0x10 keys RC4 over everything from 0x20.
    Bytes open_stage(Bytes stage, std::span<const uint8_t> key) {
        ExCryptRc4(key.data(), static_cast<uint32_t>(key.size()), stage.data() + 0x20,
                   static_cast<uint32_t>(stage.size() - 0x20));
        return stage;
    }

    bool test_devkit_chain_is_sealed_from_the_zero_secret() {
        const auto input = devkit_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x4200000,
                     "a small-block devkit image is 64 MB with spare")) {
            return false;
        }

        const auto header = read_logical(*built, 0, 0x80);
        const uint32_t chain_end = 0x8000 + align_16(uint32_t(input.bootloaders.cb_or_a.size())) +
                                   align_16(uint32_t(input.bootloaders.sc->size())) +
                                   align_16(uint32_t(input.bootloaders.cd.size())) +
                                   align_16(uint32_t(input.bootloaders.ce->size()));
        const uint32_t slot = (chain_end + 0x3FFF) & ~uint32_t{0x3FFF};
        const std::string_view copyright =
            header ? std::string_view(reinterpret_cast<const char*>(header->data() + 0x10), 0x37)
                   : std::string_view{};
        if (!require(header && read_be16(*header, 0x02) == 17489,
                     "the devkit header states the SE build") ||
            !require(read_be16(*header, 0x04) == 0x8000,
                     "the devkit header states 0x8000 at 0x04") ||
            !require(copyright.find("2004-2010") != std::string_view::npos,
                     "the devkit header states 2010 on a Jasper") ||
            !require(read_be32(*header, 0x0C) == slot && read_be32(*header, 0x64) == slot,
                     "the first slot follows the chain at the next erase block") ||
            !require(read_be16(*header, 0x68) == 2 && read_be32(*header, 0x70) == 0x10000,
                     "the devkit header states two slots of 0x10000") ||
            !require(read_be32(*header, 0x48) == 0 && read_be32(*header, 0x4C) == 0,
                     "a devkit image states no hack or boot flags")) {
            return false;
        }

        size_t at = 0x8000;
        const auto stored = [&](const Bytes& supplied) {
            auto bytes = read_logical(*built, at, supplied.size());
            at += align_16(static_cast<uint32_t>(supplied.size()));
            return bytes.value_or(Bytes{});
        };
        const auto sb = stored(input.bootloaders.cb_or_a);
        const auto sc = stored(*input.bootloaders.sc);
        const auto sd = stored(input.bootloaders.cd);
        const auto se = stored(*input.bootloaders.ce);
        const auto nonce = [](const Bytes& stage) {
            return std::span<const uint8_t>(stage).subspan(0x10, 0x10);
        };
        const std::array<uint8_t, 16> zero{};
        const auto k_sb = hmac_key(std::span(key_1bl), nonce(sb));
        const auto k_sc = hmac_key(zero, nonce(sc));
        const auto k_sd = hmac_key(k_sc, nonce(sd));
        const auto k_se = hmac_key(k_sd, nonce(se));
        const auto sb_plain = open_stage(sb, k_sb);
        const auto body_equal = [](const Bytes& opened, const Bytes& supplied, size_t from) {
            return opened.size() == supplied.size() &&
                   std::equal(opened.begin() + from, opened.end(), supplied.begin() + from);
        };
        return require(body_equal(sb_plain, input.bootloaders.cb_or_a, 0x40),
                       "SB opens under HMAC(1BL key, nonce)") &&
               require(std::equal(sb_plain.begin() + 0x20, sb_plain.begin() + 0x23,
                                  input.metadata.pairing_data.begin()),
                       "SB carries the console's pairing") &&
               require(!zero_between(sb_plain, 0x30, 0x40),
                       "SB binds the SMC in its per-box digest") &&
               require(body_equal(open_stage(sc, k_sc), *input.bootloaders.sc, 0x20),
                       "SC opens under HMAC(16 zero bytes, nonce)") &&
               require(body_equal(open_stage(sd, k_sd), input.bootloaders.cd, 0x20),
                       "SD opens under HMAC(SC key, nonce)") &&
               require(body_equal(open_stage(se, k_se), *input.bootloaders.ce, 0x20),
                       "SE opens under HMAC(SD key, nonce)");
    }

    bool test_devkit_image_reads_back_and_rebuilds_its_chain() {
        const auto input = devkit_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        const auto extracted = built ? extract_all(*built, input.metadata.cpu_key) : not_built;
        if (!require(extracted.has_value(), "a devkit image parses and opens") ||
            !require(extracted->build_type == BuildType::Devkit &&
                         extracted->image_type == ImageType::NewSmallBlock,
                     "a devkit image reads back as a small-block devkit image") ||
            !require(extracted->bootloaders.sc && extracted->bootloaders.ce,
                     "the whole SB/SC/SD/SE chain reads back")) {
            return false;
        }
        // An opened stage runs to its 16-byte boundary; the rounding reads back zero.
        const auto tail_equal = [](const Bytes& opened, const Bytes& supplied) {
            return opened.size() == align_16(static_cast<uint32_t>(supplied.size())) &&
                   std::equal(supplied.begin() + 0x40, supplied.end(), opened.begin() + 0x40) &&
                   zero_between(opened, supplied.size(), opened.size());
        };
        if (!require(tail_equal(extracted->bootloaders.cb_or_a, input.bootloaders.cb_or_a) &&
                         tail_equal(*extracted->bootloaders.sc, *input.bootloaders.sc) &&
                         tail_equal(extracted->bootloaders.cd, input.bootloaders.cd) &&
                         tail_equal(*extracted->bootloaders.ce, *input.bootloaders.ce),
                     "every stage reads back as the plaintext it was built from") ||
            !require(extracted->metadata.pairing_data == input.metadata.pairing_data,
                     "the SB's pairing reads back")) {
            return false;
        }

        // Rebuilt over itself, every stage keeps the nonce at its position, so the sealed chain
        // comes out byte for byte.
        const auto rebuilt = run_build(*extracted);
        const auto header = read_logical(*built, 0, 0x80);
        const uint32_t slot = header ? read_be32(*header, 0x64) : 0;
        const auto chain = read_logical(*built, 0, slot);
        const auto rebuilt_chain = rebuilt ? read_logical(*rebuilt, 0, slot) : std::nullopt;
        return require(rebuilt.has_value() && rebuilt->size() == built->size(),
                       "an extracted devkit image builds again in its own shape") &&
               require(chain && rebuilt_chain && chain == rebuilt_chain,
                       "the header, SMC, keyvault and sealed chain rebuild byte for byte");
    }

    bool test_devkit_nonces_come_from_donor_positions() {
        auto input = devkit_input(ImageType::BigBlock);
        DonorNonces donor{};
        for (size_t index = 0; index < donor.stages.size(); ++index) {
            BootloaderNonce nonce{};
            nonce.fill(static_cast<uint8_t>(0xA0 + index));
            donor.stages[index] = nonce;
        }
        input.metadata.donor_nonces = donor;
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x4200000,
                     "a big-block devkit image builds")) {
            return false;
        }
        size_t at = 0x8000;
        bool ok = true;
        const std::array<const Bytes*, 4> stages{&input.bootloaders.cb_or_a, &*input.bootloaders.sc,
                                                 &input.bootloaders.cd, &*input.bootloaders.ce};
        for (size_t index = 0; index < stages.size(); ++index) {
            const auto nonce = read_logical(*built, at + 0x10, 0x10);
            ok = ok && nonce && std::all_of(nonce->begin(), nonce->end(), [index](uint8_t b) {
                     return b == 0xA0 + index;
                 });
            at += align_16(static_cast<uint32_t>(stages[index]->size()));
        }
        const auto header = read_logical(*built, 0, 0x80);
        return require(ok, "SB, SC, SD and SE take the donor's CB_A, CB_B, CD and CE nonces") &&
               require(header && read_be32(*header, 0x64) == 0x20000 &&
                           read_be32(*header, 0x70) == 0x20000,
                       "a big-block devkit slot follows the chain at the next 0x20000 block");
    }

    // A 16 MB donor gives a devkit image its nonces and console data; the image itself is the
    // 64 MB shape the console's spare layout takes.
    bool test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor() {
        auto donor_input = fresh_input(ImageType::NewSmallBlock);
        // A donor's nonces are read off a chain that reaches CE.
        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.version = 1;
        ce.data.assign(0x20, 0x45);
        ce.header.header.size = static_cast<uint32_t>(sizeof(ce_header) + ce.data.size());
        ce.decrypted = true;
        donor_input.bootloaders.ce = ce.serialize();
        const auto donor = run_build(donor_input);
        if (!require(donor.has_value() && donor->size() == 0x1080000, "16 MB donor builds")) {
            return false;
        }
        auto input = devkit_input(ImageType::NewSmallBlock);
        input.metadata.nand_image = *donor;
        const auto built = run_build(input);
        auto image = built ? parse_image(*built) : std::nullopt;
        const auto donor_cb = read_logical(*donor, 0x8010, 0x10);
        const auto sb_nonce = built ? read_logical(*built, 0x8010, 0x10) : std::nullopt;
        return require(built.has_value() && built->size() == 0x4200000 && image.has_value(),
                       "the devkit image is 64 MB beside a 16 MB donor") &&
               require(image->flash_driver.driver_mode() == Driver::DriverMode::NewSmall,
                       "it keeps the donor's spare layout") &&
               require(image->build_type == BuildType::Devkit, "it reads back as devkit") &&
               require(donor_cb && sb_nonce && donor_cb == sb_nonce,
                       "its SB takes the donor's first CB nonce");
    }

    bool test_raw_patches_are_written_last_and_bounded() {
        auto input = devkit_input(ImageType::NewSmallBlock);
        input.raw_patches.push_back(InputRawPatch{"reason.bin", 0x4E, Bytes{0x12}});
        input.raw_patches.push_back(InputRawPatch{"khv.bin", 0xE4000, Bytes(0x20, 0x77)});
        const auto built = run_build(input);
        const auto reason = built ? read_logical(*built, 0x4E, 1) : std::nullopt;
        const auto khv = built ? read_logical(*built, 0xE4000, 0x20) : std::nullopt;
        if (!require(reason == Bytes{0x12}, "a raw patch overwrites the header byte it names") ||
            !require(khv == Bytes(0x20, 0x77), "a raw patch lands at its clean offset")) {
            return false;
        }
        auto outside = devkit_input(ImageType::NewSmallBlock);
        outside.raw_patches.push_back(InputRawPatch{"far.bin", 0x3FFFFFF, Bytes{1, 2}});
        const auto refused = run_build(outside);
        return require(!refused && refused.error().code == BuildErrorCode::SerializationFailure,
                       "a raw patch running past the image is refused");
    }

    // A devgl image: the devkit chain with the glitch2m patch file's CD section on its SD, the SD
    // signed again with a throwaway SB key, and fuses and KHV patches in the second slot.
    Bytes devgl_khv() {
        Bytes khv;
        append_be32(khv, 0x00001000);
        append_be32(khv, 2);
        append_be32(khv, 0x60000000);
        append_be32(khv, 0x4E800020);
        return khv;
    }

    uint32_t devgl_sd_patch_address(const Input& input) {
        return static_cast<uint32_t>(input.bootloaders.cd.size() + 0x10);
    }

    Input devgl_input(ImageType image_type) {
        auto input = devkit_input(image_type);
        input.build_type = BuildType::Devgl;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"patches_g2mjasper.bin",
                           glitch_patchset(0x20, 0xA1B2C3D4, devgl_sd_patch_address(input),
                                           0x10203040, devgl_khv())};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.fuses = Bytes(0x60, 0xF5);
        input.payloads = std::move(payloads);
        input.sb_private_key = xe_rsa_test::shared_private_key();
        return input;
    }

    bool test_devgl_image_patches_and_signs_its_sd() {
        const auto input = devgl_input(ImageType::NewSmallBlock);
        const auto built = run_build(input);
        if (!require(built.has_value() && built->size() == 0x1080000,
                     "a Jasper devgl image keeps the console's 16 MB shape")) {
            return false;
        }
        const auto header = read_logical(*built, 0, 0x80);
        const std::string_view copyright =
            header ? std::string_view(reinterpret_cast<const char*>(header->data() + 0x10), 0x37)
                   : std::string_view{};
        if (!require(header && read_be16(*header, 0x02) == 0x0760 && read_be16(*header, 0x04) == 0,
                     "the devgl header states 0x0760 and no 0x8000") ||
            !require(read_be32(*header, 0x48) == 1 && read_be32(*header, 0x4C) == 0x12,
                     "a devgl image states the hack flag and the eject XeLL button") ||
            !require(read_be32(*header, 0x0C) == 0xD0000 && read_be32(*header, 0x64) == 0xD0000,
                     "the first slot is stated at 0xD0000") ||
            !require(read_be16(*header, 0x68) == 2 && read_be32(*header, 0x70) == 0x10000,
                     "two slots of 0x10000") ||
            !require(copyright.find("2004-2009") != std::string_view::npos,
                     "a Jasper devgl image states the Jasper year")) {
            return false;
        }

        const uint32_t sd_size = align_16(devgl_sd_patch_address(input) + 4);
        size_t at = 0x8000;
        const auto stored = [&](size_t size) {
            auto bytes = read_logical(*built, at, size);
            at += align_16(static_cast<uint32_t>(size));
            return bytes.value_or(Bytes{});
        };
        const auto sb = stored(input.bootloaders.cb_or_a.size());
        const auto sc = stored(input.bootloaders.sc->size());
        const auto sd = stored(sd_size);
        const auto nonce = [](const Bytes& stage) {
            return std::span<const uint8_t>(stage).subspan(0x10, 0x10);
        };
        const std::array<uint8_t, 16> zero{};
        const auto k_sc = hmac_key(zero, nonce(sc));
        const auto sb_plain = open_stage(sb, hmac_key(std::span(key_1bl), nonce(sb)));
        const auto sd_plain = open_stage(sd, hmac_key(k_sc, nonce(sd)));
        const auto key = gxbuild3::utils::XeRsaPrivateKey::parse(*input.sb_private_key);
        const auto slot = read_logical(*built, 0xE0000, 0x60 + devgl_khv().size() + 4);
        auto expected_slot = Bytes(0x60, 0xF5);
        const auto khv = devgl_khv();
        expected_slot.insert(expected_slot.end(), khv.begin(), khv.end());
        append_be32(expected_slot, 0xFFFFFFFF);
        const auto image = parse_image(*built);
        return require(zero_between(sb_plain, 0x20, 0x40) &&
                           std::equal(sb_plain.begin() + 0x40, sb_plain.end(),
                                      input.bootloaders.cb_or_a.begin() + 0x40),
                       "the SB is zero-paired and carries no patch") &&
               require(read_be32(sd_plain, 0x0C) == sd_size &&
                           read_be32(sd_plain, devgl_sd_patch_address(input)) == 0x10203040,
                       "the SD carries the CD patch section and states its patched size") &&
               require(key && gxbuild3::utils::verify_sd_signature(sd_plain, key->public_key()),
                       "the patched SD is signed with the SB private key") &&
               require(slot == expected_slot,
                       "the fuses and KHV patches fill the second slot at 0xE0000") &&
               require(image && image->build_type == BuildType::Devgl,
                       "the image reads back as devgl");
    }

    bool test_big_block_devgl_slots_follow_the_big_block_step() {
        const auto built = run_build(devgl_input(ImageType::BigBlock));
        const auto header = built ? read_logical(*built, 0, 0x80) : std::nullopt;
        const auto fuses = built ? read_logical(*built, 0x100000, 0x60) : std::nullopt;
        return require(header && read_be32(*header, 0x64) == 0xE0000 &&
                           read_be32(*header, 0x70) == 0x20000,
                       "a big-block devgl image states its first slot at 0xE0000") &&
               require(fuses == Bytes(0x60, 0xF5), "its fuses go to 0x100000");
    }

    bool test_devgl_needs_a_well_formed_sb_private_key() {
        auto missing = devgl_input(ImageType::NewSmallBlock);
        missing.sb_private_key.reset();
        auto malformed = devgl_input(ImageType::NewSmallBlock);
        malformed.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
        const auto refused_missing = run_build(missing);
        const auto refused_malformed = run_build(malformed);
        return require(!refused_missing &&
                           refused_missing.error().code == BuildErrorCode::InvalidInput &&
                           refused_missing.error().message.find("SB private key") !=
                               std::string::npos,
                       "a devgl build without the SB private key is refused") &&
               require(!refused_malformed &&
                           refused_malformed.error().code == BuildErrorCode::InvalidInput,
                       "a devgl build with a malformed key is refused");
    }

    std::string sha1_hex(std::span<const uint8_t> bytes) {
        std::array<uint8_t, 20> digest{};
        ExCryptSha(bytes.data(), static_cast<uint32_t>(bytes.size()), nullptr, 0, nullptr, 0,
                   digest.data(), static_cast<uint32_t>(digest.size()));
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const uint8_t byte : digest) {
            out.push_back(digits[byte >> 4]);
            out.push_back(digits[byte & 0x0F]);
        }
        return out;
    }

    // Every nonce run_build would otherwise draw: the four boot-chain positions, CF and CG.
    DonorNonces pinned_donor_nonces() {
        DonorNonces nonces{};
        nonces.stages = {filled_nonce(0xA1), filled_nonce(0xA2), filled_nonce(0xA3),
                         filled_nonce(0xA4)};
        nonces.cf = filled_nonce(0xB1);
        nonces.cg = filled_nonce(0xC1);
        return nonces;
    }

    // The synthetic input of one run_build digest. Retail and glitch2 carry a CE and a CF/CG
    // slot; glitch2 also a CB_B, a patch file and a XeLL. Devkit and devgl are the devkit chain.
    Input digest_input(ImageType image_type, BuildType build_type) {
        Input input{};
        switch (build_type) {
            case BuildType::Devkit:
                input = devkit_input(image_type);
                break;
            case BuildType::Devgl:
                input = devgl_input(image_type);
                break;
            case BuildType::Glitch2: {
                input = fresh_input(image_type);
                input.build_type = BuildType::Glitch2;
                input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                input.bootloaders.ce = valid_ce();
                const auto [cf, cg] = valid_system_update(0x61);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                InputPatches patches{};
                patches.automatic = InputPatchFile{
                    "automatic", glitch_patchset(0x20, 0xA1B2C3D4, 0x30, 0x10203040, Bytes{0xA5})};
                input.patches = std::move(patches);
                InputPayloads payloads{};
                payloads.xell = valid_xell();
                input.payloads = std::move(payloads);
                break;
            }
            default: {
                input = fresh_input(image_type);
                input.build_type = build_type;
                input.bootloaders.ce = valid_ce();
                const auto [cf, cg] = valid_system_update(0x51);
                input.bootloaders.cf0 = cf;
                input.bootloaders.cg0 = cg;
                break;
            }
        }
        input.metadata.donor_nonces = pinned_donor_nonces();
        return input;
    }

    // run_build output digests (tests/golden/run_build_digests.txt): SmallBlock, NewSmallBlock,
    // BigBlock and Emmc crossed with retail, glitch2, devkit and devgl, each built twice under a
    // pinned build time (SOURCE_DATE_EPOCH in UTC) with every donor nonce filled so no nonce is
    // drawn. The two builds must be byte-identical; the SHA-1 of the output goes to the golden.
    bool test_run_build_output_digests(const gxbuild3::test::GoldenOptions& options) {
        constexpr std::array layouts{std::pair{ImageType::SmallBlock, "small"},
                                     std::pair{ImageType::NewSmallBlock, "newsmall"},
                                     std::pair{ImageType::BigBlock, "big"},
                                     std::pair{ImageType::Emmc, "emmc"}};
        constexpr std::array builds{
            std::pair{BuildType::Retail, "retail"}, std::pair{BuildType::Glitch2, "glitch2"},
            std::pair{BuildType::Devkit, "devkit"}, std::pair{BuildType::Devgl, "devgl"}};

        const auto build_pinned = [](const Input& input) {
            const ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };

        std::string rendered;
        size_t total = 0;
        size_t identical = 0;
        bool ok = true;
        for (const auto& [image_type, layout_name] : layouts) {
            for (const auto& [build_type, build_name] : builds) {
                ++total;
                const std::string label = std::string{layout_name} + '.' + build_name;
                const auto input = digest_input(image_type, build_type);
                const auto first = build_pinned(input);
                const auto second = build_pinned(input);
                if (!first || !second) {
                    rendered += label + " error=" +
                                (first ? second.error().message : first.error().message) + '\n';
                    ok = require(false, label + " builds") && ok;
                    continue;
                }
                if (!require(*first == *second, label + " builds byte-identically twice")) {
                    rendered += label + " nondeterministic\n";
                    ok = false;
                    continue;
                }
                ++identical;
                char size[32];
                std::snprintf(size, sizeof(size), "0x%zx", first->size());
                rendered += label + " size=" + size + " sha1=" + sha1_hex(*first) + '\n';
            }
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_digests", rendered);
        std::cout << "run_build digests: built twice and identical " << identical << '/' << total
                  << ", compared " << (matched ? identical : 0) << '/' << total
                  << " with tests/golden/run_build_digests.txt\n";
        return require(matched, "run_build output digests match the golden") && ok;
    }

    // Every public extract_* projection (tests/ExtractProjection.hpp) of two run_build digest
    // outputs, against tests/golden/extract_projections_synthetic.txt:
    //   small.glitch2             CB_A + CB_B, CE, CF/CG in slot 0, patch file and XeLL;
    //   newsmall.devkit           the SB/SC/SD/SE chain, where extract_all_info states the SC
    //                             decrypted while extract_some_info reads it sealed;
    //   newsmall.devkit.zero-key  the same image under the all-zero CPU key: its keyvault was
    //                             sealed under the test console's key, stays sealed, and
    //                             extract_all leaves it out (extract_metadata refuses).
    // Each image is built twice under the pinned build time and donor nonces, and each image
    // is projected twice; both must be identical. The mydata dump's projections live in
    // gxbuild3_orchestration_golden_tests (tests/golden/extract_projections_mydata.txt).
    bool test_extract_projection_snapshots(const gxbuild3::test::GoldenOptions& options) {
        const auto build_pinned = [](const Input& input) {
            const ScopedTimeZone utc{"UTC0"};
            set_source_date_epoch("1791105724");
            auto result = run_build(input);
            set_source_date_epoch(nullptr);
            return result;
        };
        const auto cpu_key = valid_cpu_key();
        const std::array<uint8_t, 16> zero_key{};
        struct Case {
            std::string_view label;
            ImageType image_type;
            BuildType build_type;
            bool zero_cpu_key;
        };
        constexpr std::array cases{
            Case{"small.glitch2", ImageType::SmallBlock, BuildType::Glitch2, false},
            Case{"newsmall.devkit", ImageType::NewSmallBlock, BuildType::Devkit, false},
            Case{"newsmall.devkit.zero-key", ImageType::NewSmallBlock, BuildType::Devkit, true},
        };

        std::string rendered;
        size_t stable = 0;
        size_t comparisons = 0;
        size_t agreements = 0;
        bool ok = true;
        for (const auto& c : cases) {
            const std::string label{c.label};
            const auto input = digest_input(c.image_type, c.build_type);
            const auto first = build_pinned(input);
            const auto second = build_pinned(input);
            if (!first || !second) {
                rendered += label + " build-error=" +
                            (first ? second.error().message : first.error().message) + '\n';
                ok = require(false, label + " builds") && ok;
                continue;
            }
            if (!require(*first == *second, label + " builds byte-identically twice")) {
                rendered += label + " nondeterministic-build\n";
                ok = false;
                continue;
            }
            const std::span<const uint8_t> key =
                c.zero_cpu_key ? std::span<const uint8_t>(zero_key) : std::span(cpu_key);
            const auto once =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            const auto twice =
                gxbuild3::test::projection::render_extract_projections(label, *first, key);
            comparisons += once.comparisons;
            agreements += once.agreements;
            for (const auto& what : once.disagreements) {
                ok = require(false, what + " renders the same as the core's span overload") && ok;
            }
            if (require(once.text == twice.text, label + " projects identically twice")) {
                ++stable;
            } else {
                ok = false;
            }
            rendered += once.text;
        }
        const bool matched =
            gxbuild3::test::check_golden(options, "extract_projections_synthetic", rendered);
        std::cout << "extract projections: inputs stable " << stable << '/' << cases.size()
                  << ", overloads and shims agreed " << agreements << '/' << comparisons
                  << ", compared " << (matched ? stable : 0) << '/' << cases.size()
                  << " with tests/golden/extract_projections_synthetic.txt\n";
        return require(matched, "synthetic extract projections match the golden") && ok;
    }

    std::string_view build_error_code_name(BuildErrorCode code) {
        switch (code) {
            case BuildErrorCode::InvalidInput:
                return "InvalidInput";
            case BuildErrorCode::InvalidDonor:
                return "InvalidDonor";
            case BuildErrorCode::InvalidSmc:
                return "InvalidSmc";
            case BuildErrorCode::InvalidKeyvault:
                return "InvalidKeyvault";
            case BuildErrorCode::InvalidBootloader:
                return "InvalidBootloader";
            case BuildErrorCode::PatchFailure:
                return "PatchFailure";
            case BuildErrorCode::EncryptionFailure:
                return "EncryptionFailure";
            case BuildErrorCode::SerializationFailure:
                return "SerializationFailure";
            case BuildErrorCode::Internal:
                return "Internal";
        }
        return "unknown";
    }

    // A 16-byte CPU key that fails the fuse ECC check, so only the steps that seal under the key
    // refuse it.
    Bytes invalid_cpu_key() {
        return Bytes(16, 0xFF);
    }

    Input glitch_input(BuildType build_type, Bytes patchset) {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = build_type;
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", std::move(patchset)};
        input.patches = std::move(patches);
        return input;
    }

    Input jtag_input(Bytes section4) {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        input.metadata.smc = make_jtag_smc(0x11);
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(section4)};
        input.patches = std::move(patches);
        return input;
    }

    // One glitch patch file section of a single entry, then the delimiter.
    void append_patch_entry(Bytes& bytes, uint32_t address, uint32_t word) {
        append_be32(bytes, address);
        append_be32(bytes, 1);
        append_be32(bytes, word);
        append_be32(bytes, 0xFFFFFFFF);
    }

    // run_build failure exits (tests/golden/run_build_failures.txt): one input per exit that an
    // Input can reach, in run_build's stage order (validation, signing key, donor, SMC, keyvault,
    // boot chain, patch file, SD signing, extra stages, metadata and nonces, patch slots,
    // payloads and layout, FlashFS, encryption, write). Each line pins the BuildErrorCode and the
    // whole describe() message, outermost context first, so moving code between functions cannot
    // reorder or drop a context layer unseen. The exits only a fault could reach are listed at
    // the end of the golden as not covered.
    bool test_run_build_failure_exits_keep_code_and_message(
        const gxbuild3::test::GoldenOptions& options) {
        struct Case {
            std::string_view label;
            Input (*input)();
        };
        const std::array cases{
            Case{"validate.cpu-key-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key.pop_back();
                     return input;
                 }},
            Case{"validate.devgl-without-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key.reset();
                     return input;
                 }},
            Case{"devgl.malformed-sb-key",
                 [] {
                     auto input = devgl_input(ImageType::NewSmallBlock);
                     input.sb_private_key = Bytes(gxbuild3::utils::kXeRsa2048PrivateKeySize, 0);
                     return input;
                 }},
            Case{"donor.not-a-nand",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = Bytes(0x10, 0x5A);
                     return input;
                 }},
            Case{"donor.wrong-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {});
                     const auto wrong_key = different_valid_cpu_key(input.metadata.cpu_key);
                     input.metadata.cpu_key.assign(wrong_key.begin(), wrong_key.end());
                     return input;
                 }},
            Case{"smc.too-short",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.smc = Bytes(0x10, 0x11);
                     return input;
                 }},
            Case{"smc.jtag-over-a-clean-smc",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.metadata.smc = make_smc(0x11);
                     return input;
                 }},
            Case{"keyvault.wrong-length",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.keyvault = Bytes(0x10, 0x22);
                     return input;
                 }},
            Case{"chain.orphan-cg0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg0 = valid_system_update(0x51).second;
                     return input;
                 }},
            Case{"chain.orphan-cg1",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cg1 = valid_system_update(0x61).second;
                     return input;
                 }},
            Case{"bootloaders.malformed-cb",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cb_or_a = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"bootloaders.malformed-cf0",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.bootloaders.cf0 = Bytes{0x43, 0x46, 0x00};
                     return input;
                 }},
            Case{"bootloaders.cd-without-payload",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCd cd{};
                     cd.header.header.magic = NANDBootloaderMagic::CD;
                     cd.header.header.version = 1;
                     cd.header.header.size = sizeof(cd_header);
                     input.bootloaders.cd = cd.serialize();
                     return input;
                 }},
            Case{"bootloaders.glitch3-without-cb-x",
                 [] {
                     auto input = glitch_input(BuildType::Glitch3,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"bootloaders.glitch1-with-cb-b",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     input.bootloaders.cb_b = input.bootloaders.cb_or_a;
                     return input;
                 }},
            Case{"patch.malformed-patch-file",
                 [] {
                     Bytes patchset;
                     append_be32(patchset, 0x20);
                     append_be32(patchset, 1);
                     append_be32(patchset, 0);
                     append_be32(patchset, 0xFFFFFFFF);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.glitch2-without-cb-b",
                 [] {
                     return glitch_input(BuildType::Glitch2,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                 }},
            Case{"patch.cb-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     append_patch_entry(patchset, 0x30, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.cd-past-32-bit-space",
                 [] {
                     Bytes patchset;
                     append_patch_entry(patchset, 0x20, 0);
                     append_patch_entry(patchset, 0xFFFFFFFC, 0);
                     patchset.push_back(0xA0);
                     return glitch_input(BuildType::Glitch, std::move(patchset));
                 }},
            Case{"patch.chain-over-capacity",
                 [] {
                     return glitch_input(BuildType::Glitch, glitch_patchset(0x70000, 0xDEADBEEF,
                                                                            0x30, 0, Bytes{0xA0}));
                 }},
            Case{"extra.malformed-jtag-cb",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cb = Bytes{0x43, 0x42, 0x00};
                     return input;
                 }},
            Case{"extra.malformed-jtag-cd",
                 [] {
                     auto input = jtag_input(Bytes{0x13, 0x13});
                     input.bootloaders.extra_cd = Bytes{0x43, 0x44, 0x00};
                     return input;
                 }},
            Case{"metadata.cb-without-per-box",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     BootloaderCb cb{};
                     cb.header.header.magic = NANDBootloaderMagic::CB;
                     cb.header.header.version = 1;
                     cb.header.header.size = sizeof(generic_header);
                     input.bootloaders.cb_or_a = cb.serialize();
                     return input;
                 }},
            Case{"slots.jtag-patch-over-0x4000", [] { return jtag_input(Bytes(0x4001, 0x44)); }},
            Case{"slots.khv-over-its-slot",
                 [] {
                     return glitch_input(BuildType::Glitch,
                                         glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55)));
                 }},
            Case{"payloads.malformed-xell",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     InputPayloads payloads{};
                     payloads.xell = Bytes(0x40000, 0);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"layout.xell-over-the-rebooter",
                 [] {
                     auto input = glitch_input(BuildType::Glitch,
                                               glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0}));
                     InputPayloads payloads{};
                     payloads.xell = valid_xell();
                     payloads.rebooter = Bytes(0x1000, 0x71);
                     input.payloads = std::move(payloads);
                     return input;
                 }},
            Case{"flashfs.add-a-257th-file",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
                     for (size_t index = 0; index < 257; ++index) {
                         input.flashfs_sec->emplace_back("f" + std::to_string(index), Bytes{});
                     }
                     return input;
                 }},
            Case{"encrypt.invalid-cpu-key",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.cpu_key = invalid_cpu_key();
                     return input;
                 }},
            Case{"write.mobile-over-a-block",
                 [] {
                     auto input = fresh_input(ImageType::SmallBlock);
                     input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x800, 2)}});
                     *input.mobiles.slot(0x32) = Bytes(0x4001, 9);
                     return input;
                 }},
        };
        // The exits no Input reaches; only a fault seam could, and none is added.
        constexpr std::array<std::pair<std::string_view, std::string_view>, 19> uncovered{{
            {"donor.read", "FlashImage::read refuses only an empty dump, which run_build skips"},
            {"chain.clear-donor-records",
             "needs a parsed donor whose boot chain runs past its own image; none is built"},
            {"smc.reboot-patch",
             "apply_signature_patch fails only on a null buffer or a bad built-in pattern"},
            {"patch.missing-section",
             "the glitch patch file parser always yields the first, CD and KHV sections"},
            {"patch.cb-apply", "the chain capacity check bounds the patched CB, and an aligned "
                               "patched stage always parses again"},
            {"patch.cb-b-apply", "as patch.cb-apply, for the CB_B"},
            {"patch.cd-apply", "as patch.cb-apply, for the CD"},
            {"sd.sign", "a key that parses (n = pq, consistent exponents) signs and verifies, and "
                        "an SD is never shorter than its 0x260-byte header"},
            {"sd.reparse", "the signed SD keeps the size it parsed with"},
            {"nonces.open-cg", "a CG that parsed opens: prepare_payload repeats the parse's check"},
            {"slots.khv-missing", "the glitch patch file parser always yields a KHV section"},
            {"flashfs.data-limit", "every layout leaves 1..0xFFFF FlashFS blocks"},
            {"flashfs.first-block",
             "no layout lays its fixed payloads past the FlashFS data limit"},
            {"flashfs.format", "every layout's block count fits the FlashFS block map"},
            {"flashfs.reserve-tail", "the tail lies inside the formatted block map"},
            {"flashfs.reserve-bad-block", "a freshly formatted map holds only free or reserved "
                                          "blocks below the data limit"},
            {"flashfs.reserve-payload-blocks",
             "the fixed payload ranges lie inside the formatted block map"},
            {"flashfs.seal-secured-file",
             "sealing fails only on a CPU key that is not 16 bytes, which validation refuses"},
            {"internal.std-exception",
             "run_build's catch: only a std exception (an allocation failure) reaches it"},
        }};

        std::string rendered;
        size_t refused = 0;
        bool ok = true;
        for (const auto& test_case : cases) {
            const std::string label{test_case.label};
            const auto input = test_case.input();
            const auto first = run_build(input);
            const auto second = run_build(input);
            if (first || second) {
                rendered += label + " built\n";
                ok = require(false, label + " is refused") && ok;
                continue;
            }
            if (!require(first.error().code == second.error().code &&
                             first.error().message == second.error().message,
                         label + " is refused the same way twice")) {
                rendered += label + " nondeterministic\n";
                ok = false;
                continue;
            }
            ++refused;
            rendered += label + " code=" + std::string{build_error_code_name(first.error().code)} +
                        " message=" + first.error().message + '\n';
        }
        for (const auto& [label, reason] : uncovered) {
            rendered += "not-covered " + std::string{label} + ": " + std::string{reason} + '\n';
        }
        const bool matched = gxbuild3::test::check_golden(options, "run_build_failures", rendered);
        std::cout << "run_build failure exits: refused " << refused << '/' << cases.size()
                  << ", compared " << (matched ? refused : 0) << '/' << cases.size()
                  << " with tests/golden/run_build_failures.txt, " << uncovered.size()
                  << " exits not covered\n";
        return require(matched, "run_build failure exits match the golden") && ok;
    }
} // namespace

int main(int argc, char** argv) {
    const auto golden = gxbuild3::test::golden_options(argc, argv);
    if (!golden) {
        return 2;
    }
    bool passed = true;
    passed = test_run_build_output_digests(*golden) && passed;
    passed = test_extract_projection_snapshots(*golden) && passed;
    passed = test_run_build_failure_exits_keep_code_and_message(*golden) && passed;
    passed = test_glitch_patches_resize_cb_and_cd_and_update_declared_sizes() && passed;
    passed = test_glitch2_targets_cbb() && passed;
    passed = test_glitch2m_cd_patch_states_the_16_byte_aligned_size() && passed;
    passed = test_glitch_types_patch_a_clean_retail_smc() && passed;
    passed = test_noblpatch_skips_bootloader_mutation_but_writes_khv() && passed;
    passed = test_nopatch_skips_only_the_named_stages() && passed;
    passed = test_jtag_patchset_is_serialized_at_fixed_region() && passed;
    passed = test_jtag_flows_payload_and_extra_bootloaders() && passed;
    passed = test_jtag_window_padding_is_programmed_like_xebuild() && passed;
    passed = test_jtag_refuses_a_clean_smc() && passed;
    passed = test_patch_regions_reject_overflow() && passed;
    passed = test_runbuild_rejects_retail_and_devkit_addon_patch_data() && passed;
    passed = test_devkit_chain_is_sealed_from_the_zero_secret() && passed;
    passed = test_devkit_image_reads_back_and_rebuilds_its_chain() && passed;
    passed = test_devkit_nonces_come_from_donor_positions() && passed;
    passed = test_devkit_image_takes_its_own_shape_beside_a_16_mb_donor() && passed;
    passed = test_raw_patches_are_written_last_and_bounded() && passed;
    passed = test_devgl_image_patches_and_signs_its_sd() && passed;
    passed = test_big_block_devgl_slots_follow_the_big_block_step() && passed;
    passed = test_devgl_needs_a_well_formed_sb_private_key() && passed;
    passed = test_glitch_patch_region_does_not_overwrite_mobile_data() && passed;
    passed = test_glitch_patch_uses_header_overlay_anchor() && passed;
    passed = test_bigblock_glitch_uses_big_patch_stride() && passed;
    passed = test_glitch_patch_is_disjoint_from_rebooter_without_xell() && passed;
    passed = test_jtag_xell_without_rebooter_preserves_patches_and_uses_fixed_offset() && passed;
    passed = test_glitch_xell_shifts_patchslots_on_small_and_big_layouts() && passed;
    passed = test_small_glitch_xell_rejects_fixed_payload_collisions() && passed;
    passed = test_donor_transition_rejects_retained_glitch_xell_collision() && passed;
    passed = test_fixed_payloads_roundtrip_in_valid_jtag_layout() && passed;
    passed = test_small_glitch_patch_base_xell_owns_overlapping_fixed_payload_offsets() && passed;
    passed = test_patch_base_xell_ownership_never_falls_back_to_an_internal_jtag_elf() && passed;
    passed = test_big_and_emmc_glitch_do_not_infer_jtag_inside_xell() && passed;
    passed = test_bigblock_glitch_xell_anchors_at_patch_base_and_shifts_cf() && passed;
    passed = test_unambiguous_jtag_xell_preserves_fixed_payload_extraction() && passed;
    passed = test_boot_chain_collision_is_rejected_for_unpatched_payload_layouts() && passed;
    passed = test_bootloader_patch_end_is_bounded_by_boot_chain_layout() && passed;
    passed = test_invalid_input_returns_structured_error() && passed;
    passed = test_emmc_lays_four_anchor_mobiles_and_drops_the_rest() && passed;
    passed = test_emmc_donor_lays_four_anchor_mobiles_and_drops_the_rest() && passed;
    passed = test_nand_donor_accepts_high_mobile_when_requested_type_is_emmc() && passed;
    passed = test_donor_overlays_replace_explicit_values_and_preserve_mobile_slots() && passed;
    passed = test_mobile_overlay_replaces_longer_donor_mobile_without_stale_tail() && passed;
    passed = test_mobile_overlay_longer_than_one_block_is_refused() && passed;
    passed = test_extracted_plaintext_keyvault_reencrypts_for_a_fresh_layout() && passed;
    passed = test_donor_rejects_a_different_structurally_valid_cpu_key() && passed;
    passed = test_payload_must_match_its_0x200_size_contract() && passed;
    passed = test_extract_all_preserves_complete_donor_baseline() && passed;
    passed = test_extract_some_info_reads_public_nand_metadata_without_cpu_key() && passed;
    passed = test_extract_all_info_reports_the_detected_block_type() && passed;
    passed = test_extraction_reports_a_cd_record_shorter_than_its_header() && passed;
    passed = test_extraction_cores_return_their_reason_and_the_shims_return_nullopt() && passed;
    passed = test_extract_all_info_reads_the_fcrt_flag_big_endian() && passed;
    passed = test_extract_all_info_pins_the_keyvault_summary_at_its_offsets() && passed;
    passed = test_sc_survives_extraction_and_backing_cleared_layout_override() && passed;
    passed = test_decrypt_all_distinguishes_encrypted_and_zero_key_plaintext_sc() && passed;
    passed = test_fresh_layouts_match_requested_image_types() && passed;
    passed = test_header_0x74_stays_zero_on_fresh_and_rewritten_images() && passed;
    passed = test_bigblock_flashfs_formats_and_roundtrips_an_empty_overlay() && passed;
    passed = test_bigblock_flashfs_roundtrips_a_file_larger_than_16_kib() && passed;
    passed = test_secure_flashfs_files_roundtrip_through_extract_and_rebuild() && passed;
    passed = test_secured_flashfs_files_are_sealed_for_the_console() && passed;
    passed = test_a_damaged_fcrt_is_written_as_its_failed_opening() && passed;
    passed = test_unusable_extended_and_secdata_are_made_up_clean() && passed;
    passed = test_big_block_donor_retains_flashfs_without_replacement() && passed;
    passed = test_flashfs_overlay_outranks_a_higher_sequence_donor_root() && passed;
    passed = test_serialized_mobile_overlay_skips_a_bad_donor_block() && passed;
    passed = test_mobile_allocation_rejects_smc_tail_overlap() && passed;
    passed = test_flashfs_allocation_reports_exhaustion_before_the_smc_tail() && passed;
    passed = test_serialized_flashfs_retains_an_empty_file() && passed;
    passed = test_serialized_mobile_does_not_overlap_fixed_payloads() && passed;
    passed = test_serialized_flashfs_does_not_overlap_fixed_payloads() && passed;
    passed = test_fixed_payloads_reject_noncanonical_sizes() && passed;
    passed = test_flashfs_directory_serialization_capacity() && passed;
    passed = test_bigblock_flashfs_overlay_handles_the_24_bit_sequence_limit() && passed;
    passed = test_emmc_mobile_slots_roundtrip_and_an_empty_input_removes_donor_data() && passed;
    passed = test_emmc_takes_each_anchor_mobile_alone_and_drops_each_other_type() && passed;
    passed = test_settings_blocks_follow_the_console_into_another_layout() && passed;
    passed = test_serialized_mobile_overlays_preserve_absent_slots_for_nand_layouts() && passed;
    passed = test_extraction_roundtrips_serialized_bootloaders_and_payloads() && passed;
    passed = test_metadata_overrides_reach_final_patched_cb_b_and_cf0() && passed;
    passed = test_metadata_override_requires_writable_cb_perbox() && passed;
    passed = test_present_unwritable_cb_b_remains_metadata_authoritative() && passed;
    passed = test_donor_bootloader_chain_is_replaced_by_input_presence() && passed;
    passed = test_donor_cf_span_is_cleared_when_replacement_omits_cg() && passed;
    passed = test_header_only_donor_ce_is_cleared_when_input_omits_it() && passed;
    passed = test_rebuilt_donor_uses_actual_cf_slot_base_for_each_build_type() && passed;
    passed = test_metadata_cf_roundtrip_preserves_extended_header_fields() && passed;
    passed = test_pairing_only_metadata_updates_every_cf_without_changing_ldv() && passed;
    passed = test_jtag_first_update_pair_stays_unbound() && passed;
    passed = test_pairing_only_metadata_rejects_unwritable_cf_perbox() && passed;
    passed = test_generic_header_pairing_roundtrips_for_every_bootloader() && passed;
    passed = test_stage_specific_numeric_headers_are_host_order_and_wire_big_endian() && passed;
    passed = test_cb_console_allow_host_value_serializes_without_overwriting_perbox() && passed;
    passed = test_cb_console_allow_host_value_encrypts_and_roundtrips_asymmetrically() && passed;
    passed = test_direct_payload_layout_rejects_header_only_required_records() && passed;
    passed = test_required_chain_relationships_reject_before_serialization() && passed;
    passed = test_system_update_slot_zero_spills_and_preserves_slot_one() && passed;
    passed = test_flashfs_is_laid_as_xebuild_lays_it() && passed;
    passed = test_replacement_layout_overrides_a_one_slot_donor_header() && passed;
    passed = test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() && passed;
    passed = test_fresh_build_seals_stages_under_random_nonces() && passed;
    passed = test_donor_nonces_seal_stages_by_position_and_every_slot_alike() && passed;
    passed = test_extraction_takes_cf_metadata_and_nonces_from_the_max_ldv_slot() && passed;
    passed = test_header_states_zero_pairing_and_the_board_copyright() && passed;
    passed = test_hacked_header_states_boot_flags_two_slots_and_a_zeroed_khv_tail() && passed;
    passed = test_donor_build_leaves_unlaid_space_erased() && passed;
    passed = test_emmc_build_leaves_anchor_tails_and_unused_blocks_erased() && passed;
    passed = test_bigblock_flashfs_stamps_only_the_clusters_it_fills() && passed;
    passed = test_zero_cpu_key_zero_pairs_a_cb_b_chain() && passed;
    passed = test_zero_cpu_key_leaves_the_donor_keyvault_sealed() && passed;
    return passed ? 0 : 1;
}
