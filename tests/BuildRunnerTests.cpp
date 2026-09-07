#include "BuildRunner.hpp"
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

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using gxbuild3::NAND::BlockMetadata;
using gxbuild3::NAND::Driver;
using gxbuild3::NAND::FlashImage;
using gxbuild3::NAND::Keyvault;
using gxbuild3::NAND::MobileData;
using gxbuild3::NAND::Smc;

namespace {

    using Bytes = std::vector<uint8_t>;

    bool require(bool condition, std::string_view message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    }

    std::array<uint8_t, 16> valid_cpu_key() {
        for (size_t bit_count = 0; bit_count <= 106; ++bit_count) {
            std::array<uint8_t, 16> candidate{};
            for (size_t bit = 0; bit < bit_count; ++bit) {
                candidate[bit / 8] |= static_cast<uint8_t>(1U << (bit % 8));
            }
            XeCryptUidEccEncode(candidate.data());
            if (gxbuild3::NAND::cpukey_valid(candidate)) {
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
        if (gxbuild3::NAND::cpukey_valid(candidate) &&
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

    Bytes canonical_keyvault(std::span<const uint8_t> cpu_key, Bytes plaintext) {
        return keyvault_decrypt(cpu_key, keyvault_encrypt(cpu_key, plaintext));
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
        cf.data.assign(0x200, marker);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        cf.decrypted = false;
        std::fill(std::begin(cf.header.cg_key), std::end(cf.header.cg_key),
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
        cf.data.assign(0x200, 0);
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

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
        if (!require(extracted.has_value(), "patched glitch image builds and extracts")) {
            return false;
        }

        const auto& cb = extracted->bootloaders.cb_or_a;
        const auto& cd = extracted->bootloaders.cd;
        return require(cb.size() >= cb_patch_address + 4 &&
                           read_be32(cb, cb_patch_address) == 0xA1B2C3D4,
                       "CB grows to and contains the greatest patched end") &&
               require(read_be32(cb, 0x0C) == cb_patch_address + 4,
                       "CB big-endian declared size follows patched bytes") &&
               require(cd.size() >= cd_patch_address + 4 &&
                           read_be32(cd, cd_patch_address) == 0x10203040,
                       "CD grows to and contains the greatest patched end") &&
               require(read_be32(cd, 0x0C) == cd_patch_address + 4,
                       "CD big-endian declared size follows patched bytes");
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

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
        if (!require(extracted.has_value() && extracted->bootloaders.cb_b.has_value(),
                     "Glitch2 CBB image builds and extracts")) {
            return false;
        }
        return require(extracted->bootloaders.cb_b->size() >= cbb_patch_address + 4 &&
                           read_be32(*extracted->bootloaders.cb_b, cbb_patch_address) == 0xCAFEBABE,
                       "Glitch2 applies section one to CBB") &&
               require(read_be32(*extracted->bootloaders.cb_b, 0x0C) == cbb_patch_address + 4,
                       "CBB big-endian declared size follows patched bytes");
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

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
        const auto khv = built ? read_logical(*built, 0x90000, 3) : std::nullopt;
        return require(extracted.has_value() &&
                           extracted->bootloaders.cb_or_a.size() == original_cb_size,
                       "noblpatch leaves CB size unchanged") &&
               require(khv == Bytes({0xA0, 0xA1, 0xA2}),
                       "noblpatch still writes merged KHV bytes after both patch slots");
    }

    bool test_jtag_patchset_is_serialized_at_fixed_region() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
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

        const auto built = RunBuild(input);
        const auto raw = built ? read_logical(*built, 0x91000, expected.size()) : std::nullopt;
        return require(built.has_value(), "JTAG patchset image builds") &&
               require(raw == expected, "merged JTAG patchset is byte-exact at 0x91000");
    }

    bool test_patch_regions_reject_overflow() {
        auto jtag = fresh_input(ImageType::SmallBlock);
        jtag.build_type = BuildType::Jtag;
        InputPatches jtag_patches{};
        jtag_patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes(0x4001, 0x44))};
        jtag.patches = std::move(jtag_patches);
        const auto jtag_result = RunBuild(jtag);

        auto glitch = fresh_input(ImageType::SmallBlock);
        glitch.build_type = BuildType::Glitch;
        InputPatches glitch_patches{};
        glitch_patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes(0xFFF1, 0x55))};
        glitch.patches = std::move(glitch_patches);
        const auto glitch_result = RunBuild(glitch);

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
            const auto result = RunBuild(input);
            if (!require(!result && result.error().code == BuildErrorCode::InvalidInput,
                         "RunBuild rejects retail and devkit add-on patch data")) {
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

        Bytes expected_mobile(33 * 0x4000);
        for (size_t index = 0; index < expected_mobile.size(); ++index) {
            expected_mobile[index] = static_cast<uint8_t>((index * 17U + 0x39U) & 0xFFU);
        }
        *input.mobiles.slot(0x31) = expected_mobile;

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
        return require(extracted.has_value() && *extracted->mobiles.slot(0x31) == expected_mobile,
                       "glitch patch reservation prevents overwriting mobile data");
    }

    bool test_glitch_patch_follows_xell_and_patch_slots() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);

        const auto built = RunBuild(input);
        const auto khv = built ? read_logical(*built, 0xD0000, 1) : std::nullopt;
        const auto xell_magic = built ? read_logical(*built, 0x70000, 4) : std::nullopt;
        return require(built.has_value(), "glitch patch and XeLL image builds") &&
               require(khv == Bytes({0xA0}),
                       "glitch KHV follows the XeLL reservation and both patch slots") &&
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

        const auto built = RunBuild(input);
        const auto first = built ? read_logical(*built, 0x100000, 1) : std::nullopt;
        return require(built.has_value(), "big-block glitch accepts payload above small stride") &&
               require(first == Bytes({0xB4}),
                       "big-block KHV follows two 0x20000-byte patch slots");
    }

    bool test_glitch_patch_rejects_rebooter_overlap() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch;
        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA0})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.rebooter = Bytes(0x1000, 0x71);
        input.payloads = std::move(payloads);

        const auto built = RunBuild(input);
        return require(!built && built.error().code == BuildErrorCode::PatchFailure,
                       "glitch KHV cannot overwrite the reserved rebooter payload");
    }

    bool test_jtag_xell_without_rebooter_preserves_patches_and_uses_fixed_offset() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0x13, 0x14})};
        input.patches = patches;
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        input.payloads = std::move(payloads);

        const auto merged = BinaryParser::ParseAndMergePatchSet(patches, BuildType::Jtag);
        const auto expected = merged ? BinaryParser::SerializePatchSet(*merged) : Bytes{};
        const auto built = RunBuild(input);
        const auto written_patch =
            built ? read_logical(*built, 0x91000, expected.size()) : std::nullopt;
        const auto xell_magic = built ? read_logical(*built, 0x95060, 4) : std::nullopt;
        return require(built.has_value(), "JTAG patch plus XeLL image builds") &&
               require(written_patch == expected, "JTAG patch bytes survive beside XeLL") &&
               require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}),
                       "JTAG XeLL always starts at 0x95060");
    }

    bool test_glitch_xell_shifts_patchslots_on_small_and_big_layouts() {
        struct Case {
            ImageType image_type;
            size_t slot0;
            size_t slot1;
            size_t khv;
        };
        const std::array cases{
            Case{ImageType::SmallBlock, 0xB0000, 0xC0000, 0xD0000},
            Case{ImageType::BigBlock, 0x100000, 0x120000, 0x140000},
        };

        for (const auto& test_case : cases) {
            auto input = fresh_input(test_case.image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA5})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);
            const auto [cf0, cg0] = valid_system_update(0x61);
            const auto [cf1, cg1] = valid_system_update(0x71);
            input.bootloaders.cf0 = cf0;
            input.bootloaders.cg0 = cg0;
            input.bootloaders.cf1 = cf1;
            input.bootloaders.cg1 = cg1;

            const auto built = RunBuild(input);
            const auto slot0_cf =
                built ? read_logical(*built, test_case.slot0, cf0.size()) : std::nullopt;
            const auto slot0_cg =
                built ? read_logical(*built, test_case.slot0 + ((cf0.size() + 0x0F) & ~0x0F),
                                     cg0.size())
                      : std::nullopt;
            const auto slot1_cf =
                built ? read_logical(*built, test_case.slot1, cf1.size()) : std::nullopt;
            const auto slot1_cg =
                built ? read_logical(*built, test_case.slot1 + ((cf1.size() + 0x0F) & ~0x0F),
                                     cg1.size())
                      : std::nullopt;
            const auto khv = built ? read_logical(*built, test_case.khv, 1) : std::nullopt;
            const auto xell_magic =
                built
                    ? read_logical(*built,
                                   test_case.image_type == ImageType::BigBlock ? 0xC0000 : 0x70000,
                                   4)
                    : std::nullopt;
            std::optional<FlashImage> parsed;
            if (built) {
                parsed = FlashImage::read(*built);
                if (parsed && !parsed->parse()) {
                    parsed.reset();
                }
            }
            if (!require(built.has_value(), "glitch XeLL and patch slots build") ||
                !require(slot0_cf.has_value() && slot0_cg == cg0,
                         "shifted slot zero serializes CF and preserves CG bytes") ||
                !require(slot1_cf.has_value() && slot1_cg == cg1,
                         "shifted slot one serializes CF and preserves CG bytes") ||
                !require(khv == Bytes({0xA5}), "KHV follows both shifted patch slots") ||
                !require(xell_magic == Bytes({0x7F, 'E', 'L', 'F'}), "XeLL remains intact") ||
                !require(parsed.has_value() && parsed->system_update_0.cf.has_value() &&
                             parsed->system_update_0.cg.has_value() &&
                             parsed->system_update_1.cf.has_value() &&
                             parsed->system_update_1.cg.has_value() &&
                             parsed->header.cf_offset == test_case.slot0,
                         "shifted CF/CG slots parse from the serialized header")) {
                return false;
            }
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

            const auto built = RunBuild(input);
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
        InputPatches donor_patches{};
        donor_patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA1})};
        donor_input.patches = std::move(donor_patches);
        InputPayloads donor_payloads{};
        donor_payloads.rebooter = Bytes(0x1000, 0x71);
        donor_payloads.fuses = Bytes(0x60, 0x72);
        donor_payloads.xell = valid_xell();
        donor_input.payloads = std::move(donor_payloads);
        const auto donor = RunBuild(donor_input);
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

        const auto built = RunBuild(input);
        return require(!built && built.error().code == BuildErrorCode::InvalidInput,
                       "donor transition rejects retained payload collision") &&
               require(!built || built.error().message.find("XeLL overlaps rebooter") !=
                                     std::string::npos,
                       "donor transition reports the retained XeLL and rebooter collision");
    }

    bool test_fixed_payloads_roundtrip_in_valid_jtag_and_bigblock_glitch_layouts() {
        struct Case {
            ImageType image_type;
            BuildType build_type;
            InputPatchFile automatic;
            size_t xell_offset;
        };
        const std::array cases{
            Case{ImageType::SmallBlock, BuildType::Jtag,
                 InputPatchFile{"automatic", jtag_patchset(Bytes{0xA3})}, 0x95060},
            Case{ImageType::BigBlock, BuildType::Glitch,
                 InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA4})},
                 0xC0000},
        };

        for (const auto& test_case : cases) {
            const std::string layout_name =
                test_case.build_type == BuildType::Jtag ? "JTAG" : "big-block Glitch";
            auto input = fresh_input(test_case.image_type);
            input.build_type = test_case.build_type;
            InputPatches patches{};
            patches.automatic = test_case.automatic;
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(0x1000, 0x71);
            payloads.fuses = Bytes(0x60, 0x72);
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = RunBuild(input);
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

    bool test_bigblock_and_emmc_glitch_retain_disjoint_fixed_payloads() {
        struct Case {
            ImageType image_type;
            std::string_view name;
        };
        const std::array cases{Case{ImageType::BigBlock, "big-block"},
                               Case{ImageType::Emmc, "eMMC"}};

        for (const auto& test_case : cases) {
            auto input = fresh_input(test_case.image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xA6})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            payloads.xell->at(0x3FFFF) = 0xD7;
            payloads.rebooter = Bytes(0x1000, 0xD8);
            payloads.fuses = Bytes(0x60, 0xD9);
            input.payloads = std::move(payloads);

            const auto built = RunBuild(input);
            auto parsed = built ? FlashImage::read(*built) : std::nullopt;
            const bool parsed_ok = parsed && parsed->parse();
            const auto extracted =
                built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
            const auto rebuilt = extracted ? RunBuild(*extracted) : BuildResult{};
            const auto rebuilt_xell =
                rebuilt ? read_logical(*rebuilt, 0xC0000, input.payloads->xell->size())
                        : std::nullopt;
            const auto rebuilt_rebooter =
                rebuilt ? read_logical(*rebuilt, 0x90000, input.payloads->rebooter->size())
                        : std::nullopt;
            const auto rebuilt_fuses =
                rebuilt ? read_logical(*rebuilt, 0x95000, input.payloads->fuses->size())
                        : std::nullopt;

            if (!require(built.has_value() && parsed_ok,
                         std::string(test_case.name) + " Glitch fixture builds and parses") ||
                !require(
                    extracted.has_value() && extracted->payloads &&
                        extracted->payloads->xell == input.payloads->xell &&
                        extracted->payloads->rebooter == input.payloads->rebooter &&
                        extracted->payloads->fuses == input.payloads->fuses,
                    std::string(test_case.name) +
                        " Glitch ExtractAll retains patch-base XeLL and disjoint fixed payloads") ||
                !require(rebuilt_xell == input.payloads->xell &&
                             rebuilt_rebooter == input.payloads->rebooter &&
                             rebuilt_fuses == input.payloads->fuses,
                         std::string(test_case.name) +
                             " Glitch ExtractAll rebuild preserves every retained payload")) {
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

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
        return require(extracted.has_value() && extracted->payloads && extracted->payloads->xell &&
                           *extracted->payloads->xell == *input.payloads->xell,
                       "small-block Glitch ExtractAll retains patch-base XeLL bytes at 0x20000 and "
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

            const auto built = RunBuild(input);
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
                modified ? ExtractAll(image->flash_driver.serialize(), input.metadata.cpu_key)
                         : std::nullopt;

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

    bool test_big_and_emmc_shifted_patch_base_allow_disjoint_jtag_xell_fallback() {
        const std::array image_types{ImageType::BigBlock, ImageType::Emmc};
        for (const auto image_type : image_types) {
            auto input = fresh_input(image_type);
            input.build_type = BuildType::Glitch;
            InputPatches patches{};
            patches.automatic =
                InputPatchFile{"automatic", glitch_patchset(0x20, 0, 0x30, 0, Bytes{0xAB})};
            input.patches = std::move(patches);
            InputPayloads payloads{};
            payloads.xell = valid_xell();
            input.payloads = std::move(payloads);

            const auto built = RunBuild(input);
            auto image = built ? FlashImage::read(*built) : std::nullopt;
            const Bytes invalid_patch_base{0, 0, 0, 0};
            const auto jtag_xell = valid_xell();
            const bool modified = image && image->parse() &&
                                  image->flash_driver.write_offset(0xC0000, invalid_patch_base) &&
                                  image->flash_driver.write_offset(0x95060, jtag_xell);
            const auto extracted =
                modified ? ExtractAll(image->flash_driver.serialize(), input.metadata.cpu_key)
                         : std::nullopt;
            if (!require(modified,
                         "big/eMMC shifted patch-base fixture is modified successfully") ||
                !require(extracted && extracted->payloads && extracted->payloads->xell &&
                             (*extracted->payloads->xell)[0] == 0x7F,
                         "a disjoint Big/eMMC JTAG XeLL remains independently recoverable")) {
                return false;
            }
        }
        return true;
    }

    bool test_unambiguous_jtag_xell_preserves_fixed_payload_extraction() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Jtag;
        InputPatches patches{};
        patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA8})};
        input.patches = std::move(patches);
        InputPayloads payloads{};
        payloads.xell = valid_xell();
        payloads.rebooter = Bytes(0x1000, 0x81);
        payloads.fuses = Bytes(0x60, 0x82);
        input.payloads = std::move(payloads);

        const auto built = RunBuild(input);
        const auto extracted = built ? ExtractAll(*built, input.metadata.cpu_key) : std::nullopt;
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

            const auto built = RunBuild(input);
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

        const auto built = RunBuild(input);
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
        const auto hostile_result = RunBuild(hostile);
        return require(!hostile_result &&
                           hostile_result.error().code == BuildErrorCode::PatchFailure,
                       "near-UINT32_MAX patch end is rejected without allocation");
    }

    Bytes make_donor(const Input& source,
                     std::initializer_list<std::pair<uint8_t, Bytes>> mobiles) {
        FlashImage donor{};
        donor.flash_driver = Driver(Driver::ImageSize::Smallblock, Driver::DriverMode::Small);
        donor.smc = Smc::parse(*source.metadata.smc);
        donor.keyvault = Keyvault::parse(*source.metadata.keyvault);
        donor.keyvault->encrypted = false;
        if (!donor.keyvault->encrypt(source.metadata.cpu_key)) {
            std::abort();
        }
        donor.cb_section.cb_or_A = BootloaderCb::parse(source.bootloaders.cb_or_a);
        donor.cb_section.sc = BootloaderSc::parse(*source.bootloaders.sc);
        donor.kernel_section.cd = BootloaderCd::parse(source.bootloaders.cd);
        if (!donor.encrypt_all(source.metadata.cpu_key)) {
            std::abort();
        }
        donor.mobile_data = MobileData{};
        for (const auto& [block_type, bytes] : mobiles) {
            *donor.mobile_data->get_slot(block_type) = bytes;
        }
        return donor.write();
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

        const auto built = RunBuild(input);
        return require(!built.has_value(), "invalid input is rejected") &&
               require(built.error().code == BuildErrorCode::InvalidInput,
                       "invalid input has an InvalidInput build error");
    }

    bool test_emmc_rejects_mobile_slots_without_corona_metadata_fields() {
        auto input = fresh_input(ImageType::Emmc);
        *input.mobiles.slot(0x33) = Bytes{3};
        const auto built = RunBuild(input);
        return require(!built.has_value(), "eMMC rejects unsupported mobile slots") &&
               require(built.error().code == BuildErrorCode::InvalidInput,
                       "unsupported eMMC mobile has an input error");
    }

    bool test_emmc_donor_rejects_each_high_mobile_when_requested_type_is_mismatched() {
        const auto donor = RunBuild(fresh_input(ImageType::Emmc));
        if (!require(donor.has_value(), "eMMC donor fixture builds")) {
            return false;
        }

        for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            *input.mobiles.slot(block_type) = Bytes{block_type};
            const auto built = RunBuild(input);
            if (!require(!built.has_value(), "effective eMMC geometry rejects high mobile slot") ||
                !require(built.error().code == BuildErrorCode::InvalidInput,
                         "effective eMMC geometry returns InvalidInput") ||
                !require(built.error().message ==
                             "eMMC Corona metadata supports mobile slots 0x31 and 0x32 only",
                         "effective eMMC geometry reports the ruled Corona limitation")) {
                return false;
            }
        }
        return true;
    }

    bool test_nand_donor_accepts_high_mobile_when_requested_type_is_emmc() {
        auto input = fresh_input(ImageType::Emmc);
        input.metadata.nand_image = make_donor(input, {});
        *input.mobiles.slot(0x33) = Bytes{0x33, 0xCC};

        const auto built = RunBuild(input);
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

        const auto built = RunBuild(input);
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
        input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x20000, 2)}});
        *input.mobiles.slot(0x32) = Bytes(0x10000, 9);

        const auto built = RunBuild(input);
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

    bool test_mobile_overlay_clears_donor_size_when_replacement_exceeds_uint16() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = make_donor(input, {{0x32, Bytes(0x8000, 2)}});
        *input.mobiles.slot(0x32) = Bytes(0x14000, 9);

        const auto built = RunBuild(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        return require(built.has_value(), "large mobile overlay build succeeds") &&
               require(parsed.has_value() && parsed->mobile_data.has_value() &&
                           parsed->mobile_data->x32.has_value(),
                       "large mobile overlay reparses") &&
               require(parsed->mobile_data->x32 == *input.mobiles.slot(0x32),
                       "large mobile replacement clears the donor size metadata");
    }

    bool test_extracted_plaintext_keyvault_reencrypts_for_a_fresh_layout() {
        auto source = fresh_input(ImageType::SmallBlock);
        for (size_t i = 0; i < source.metadata.keyvault->size(); ++i) {
            (*source.metadata.keyvault)[i] = static_cast<uint8_t>(i);
        }
        source.metadata.keyvault =
            canonical_keyvault(source.metadata.cpu_key, *source.metadata.keyvault);
        const auto donor = make_donor(source, {});
        auto extracted = ExtractAll(donor, source.metadata.cpu_key);
        if (!require(extracted.has_value() &&
                         extracted->metadata.keyvault == source.metadata.keyvault,
                     "extraction exposes the canonical plaintext keyvault")) {
            return false;
        }

        extracted->metadata.nand_image.reset();
        const auto rebuilt = RunBuild(*extracted);
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
        const auto built = RunBuild(input);
        return require(!built.has_value(), "wrong valid CPU key rejects donor") &&
               require(built.error().code == BuildErrorCode::InvalidDonor,
                       "wrong valid CPU key maps to InvalidDonor");
    }

    bool test_custom_payload_is_rejected_without_an_on_disk_format_contract() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.payloads = InputPayloads{};
        input.payloads->payload = Bytes{0xC0, 0xDE};

        const auto built = RunBuild(input);
        return require(!built.has_value(), "custom payload is rejected") &&
               require(built.error().code == BuildErrorCode::InvalidInput,
                       "custom payload returns InvalidInput") &&
               require(
                   built.error().message ==
                       "Custom payload is unsupported because no on-disk format contract exists",
                   "custom payload explains the missing format contract");
    }

    bool test_extract_all_preserves_complete_donor_baseline() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {{0x31, Bytes{3}}, {0x39, Bytes{9}}});

        const auto extracted = ExtractAll(donor, source.metadata.cpu_key);
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

    bool test_sc_survives_extraction_and_backing_cleared_layout_override() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto donor = make_donor(source, {});
        auto extracted = ExtractAll(donor, source.metadata.cpu_key);
        if (!require(extracted.has_value() && extracted->bootloaders.sc == source.bootloaders.sc,
                     "extraction preserves exact SC bytes"))
            return false;
        extracted->metadata.nand_image.reset();
        extracted->image_type = ImageType::BigBlock;
        const auto rebuilt = RunBuild(*extracted);
        auto parsed = rebuilt ? parse_image(*rebuilt) : std::nullopt;
        return require(parsed.has_value() && parsed->cb_section.sc.has_value() &&
                           parsed->cb_section.sc->serialize() == *source.bootloaders.sc,
                       "SC survives backing-cleared layout override");
    }

    bool test_decrypt_all_distinguishes_encrypted_and_zero_key_plaintext_sc() {
        auto encrypted_source = fresh_input(ImageType::SmallBlock);
        auto cb_for_key = BootloaderCb::parse(encrypted_source.bootloaders.cb_or_a);
        cb_for_key.encrypt(key_1bl);
        auto encrypted_sc = BootloaderSc::parse(*encrypted_source.bootloaders.sc);
        const auto expected_encrypted_sc_data = encrypted_sc.data;
        encrypted_sc.decrypted = true;
        encrypted_sc.encrypt(cb_for_key.derived_key->data());
        encrypted_source.bootloaders.sc = encrypted_sc.serialize();

        const auto encrypted_build = RunBuild(encrypted_source);
        auto encrypted_image = encrypted_build ? FlashImage::read(*encrypted_build) : std::nullopt;
        const bool encrypted_parsed = encrypted_image && encrypted_image->parse();
        const bool encrypted_decrypted =
            encrypted_parsed && encrypted_image->decrypt_all(encrypted_source.metadata.cpu_key);

        auto plaintext_source = fresh_input(ImageType::SmallBlock);
        const auto expected_plaintext_sc = *plaintext_source.bootloaders.sc;
        const auto plaintext_build = RunBuild(plaintext_source);
        const auto plaintext_extracted =
            plaintext_build ? ExtractAll(*plaintext_build, plaintext_source.metadata.cpu_key)
                            : std::nullopt;

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
            const auto built = RunBuild(fresh_input(image_type));
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

    bool test_bigblock_flashfs_formats_and_roundtrips_an_empty_overlay() {
        auto input = fresh_input(ImageType::BigBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{};
        const auto built = RunBuild(input);
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
        const auto built = RunBuild(input);
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

    bool test_secure_flashfs_files_roundtrip_through_extract_and_rebuild() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"secdata.bin", Bytes(0x20, 0x31)}, {"extended.bin", Bytes(0x20, 0x42)}};
        const auto built = RunBuild(input);
        if (!require(built.has_value(), "secure FlashFS build succeeds")) {
            return false;
        }
        auto extracted = ExtractAll(*built, input.metadata.cpu_key);
        if (!require(extracted.has_value() && extracted->flashfs_sec == input.flashfs_sec,
                     "extraction returns plaintext secure FlashFS files")) {
            return false;
        }
        extracted->metadata.nand_image.reset();
        const auto rebuilt = RunBuild(*extracted);
        if (!require(rebuilt.has_value(), "secure FlashFS rebuild succeeds")) {
            return false;
        }
        const auto roundtrip = ExtractAll(*rebuilt, input.metadata.cpu_key);
        return require(roundtrip.has_value() && roundtrip->flashfs_sec == input.flashfs_sec,
                       "secure FlashFS files survive extract and rebuild");
    }

    bool test_flashfs_overlay_outranks_a_higher_sequence_donor_root() {
        auto first = fresh_input(ImageType::SmallBlock);
        first.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"first.bin", Bytes{1}}};
        const auto first_build = RunBuild(first);
        if (!require(first_build.has_value(), "initial FlashFS donor build succeeds")) {
            return false;
        }

        auto higher_sequence_donor = fresh_input(ImageType::SmallBlock);
        higher_sequence_donor.metadata.nand_image = *first_build;
        higher_sequence_donor.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"donor-old.bin", Bytes{2}}};
        const auto donor_bytes = RunBuild(higher_sequence_donor);
        const auto parsed_donor = donor_bytes ? parse_image(*donor_bytes) : std::nullopt;
        if (!require(parsed_donor.has_value() && parsed_donor->filesystem.has_value() &&
                         parsed_donor->filesystem->version() > 1,
                     "serialized donor FlashFS has a version higher than the fresh default")) {
            return false;
        }

        auto overlay = fresh_input(ImageType::SmallBlock);
        overlay.metadata.nand_image = *donor_bytes;
        overlay.flashfs_sec =
            std::vector<std::pair<std::string, Bytes>>{{"replacement.bin", Bytes{7, 8, 9}}};
        const auto built = RunBuild(overlay);
        const auto parsed = built ? parse_image(*built) : std::nullopt;
        if (!require(parsed.has_value() && parsed->filesystem.has_value(),
                     "FlashFS overlay output parses")) {
            return false;
        }
        const auto replacement = parsed->filesystem->get_file("replacement.bin");
        return require(replacement == Bytes({7, 8, 9}),
                       "FlashFS overlay selects the exact replacement contents") &&
               require(!parsed->filesystem->get_file("donor-old.bin").has_value(),
                       "stale donor FlashFS root cannot win selection");
    }

    bool test_serialized_mobile_overlay_skips_a_bad_donor_block() {
        const auto initial = RunBuild(fresh_input(ImageType::SmallBlock));
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
        const auto built = RunBuild(overlay);
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
        auto input = fresh_input(ImageType::SmallBlock);
        constexpr size_t first_mobile_block = 4;
        constexpr size_t smc_tail_start = 0x3DC;
        *input.mobiles.slot(0x31) = Bytes((smc_tail_start - first_mobile_block + 1) * 0x4000, 0x31);

        const auto built = RunBuild(input);
        return require(!built.has_value(), "mobile allocation cannot enter the SMC tail") &&
               require(built.error().code == BuildErrorCode::SerializationFailure,
                       "SMC-tail mobile allocation reports SerializationFailure");
    }

    bool test_flashfs_allocation_reports_exhaustion_before_the_smc_tail() {
        auto input = fresh_input(ImageType::SmallBlock);
        constexpr size_t first_flashfs_block = 0x50;
        constexpr size_t smc_tail_start = 0x3DC;
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{
            {"fills-tail.bin", Bytes((smc_tail_start - first_flashfs_block + 1) * 0x4000, 0xA5)}};

        const auto built = RunBuild(input);
        return require(!built.has_value(), "FlashFS allocation cannot enter the SMC tail") &&
               require(built.error().code == BuildErrorCode::SerializationFailure,
                       "FlashFS tail exhaustion reports SerializationFailure");
    }

    bool test_serialized_flashfs_retains_an_empty_file() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"empty.bin", Bytes{}}};
        const auto built = RunBuild(input);
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

        // The unreserved range begins at block 4; 50 blocks would formerly cover every
        // payload block from the rebooter at 0x90000 through XeLL at 0x95060.
        *input.mobiles.slot(0x31) = Bytes(50 * 0x4000, 0x31);
        const auto built = RunBuild(input);
        const auto parsed = built ? parse_image(*built) : std::nullopt;

        return require(built.has_value(), "mobile and fixed payload image builds") &&
               require(parsed.has_value() && parsed->mobile_data.has_value() &&
                           parsed->mobile_data->x31 == *input.mobiles.slot(0x31),
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

        const auto built = RunBuild(input);
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
        const std::array<size_t, 4> invalid_rebooter_sizes{{0x0FFF, 0x1001, 0, 0x2000}};
        for (const auto size : invalid_rebooter_sizes) {
            auto input = fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.rebooter = Bytes(size, 0x71);
            input.payloads = std::move(payloads);
            const auto built = RunBuild(input);
            if (!require(!built.has_value(), "noncanonical rebooter size is rejected") ||
                !require(built.error().code == BuildErrorCode::InvalidInput,
                         "noncanonical rebooter size is an input error")) {
                return false;
            }
        }

        const std::array<size_t, 4> invalid_fuse_sizes{{0x5F, 0x61, 0, 0x100}};
        for (const auto size : invalid_fuse_sizes) {
            auto input = fresh_input(ImageType::SmallBlock);
            InputPayloads payloads{};
            payloads.fuses = Bytes(size, 0x72);
            input.payloads = std::move(payloads);
            const auto built = RunBuild(input);
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
        const auto full_build = RunBuild(full);
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
        const auto overflow_build = RunBuild(overflow);
        return require(!overflow_build.has_value(), "257 FlashFS entries are rejected") &&
               require(overflow_build.error().code == BuildErrorCode::SerializationFailure,
                       "FlashFS directory overflow returns SerializationFailure");
    }

    bool test_bigblock_flashfs_overlay_handles_the_24_bit_sequence_limit() {
        auto first = fresh_input(ImageType::BigBlock);
        first.flashfs_sec = std::vector<std::pair<std::string, Bytes>>{{"donor-old.bin", Bytes{2}}};
        const auto first_build = RunBuild(first);
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
        const auto built = RunBuild(overlay);
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
        const auto donor_bytes = RunBuild(donor_input);
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
        const auto rebuilt = RunBuild(removal);
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

    bool test_emmc_rejects_each_mobile_slot_without_corona_metadata() {
        for (uint8_t block_type = 0x33; block_type <= 0x39; ++block_type) {
            auto input = fresh_input(ImageType::Emmc);
            *input.mobiles.slot(block_type) = Bytes{block_type};
            const auto built = RunBuild(input);
            if (!require(!built.has_value(), "eMMC rejects unsupported mobile input") ||
                !require(built.error().code == BuildErrorCode::InvalidInput,
                         "unsupported eMMC mobile returns InvalidInput") ||
                !require(built.error().message ==
                             "eMMC Corona metadata supports mobile slots 0x31 and 0x32 only",
                         "unsupported eMMC mobile explains Corona metadata limitation")) {
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
            const auto donor_bytes = RunBuild(donor_input);
            if (!require(donor_bytes.has_value(), "serialized NAND mobile donor builds")) {
                return false;
            }

            auto overlay = fresh_input(layout);
            overlay.metadata.nand_image = *donor_bytes;
            *overlay.mobiles.slot(0x39) = Bytes{0xA9, 0x39};
            const auto rebuilt = RunBuild(overlay);
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

    bool test_extraction_roundtrips_serialized_bootloaders_and_payloads() {
        auto source = fresh_input(ImageType::SmallBlock);
        const auto bootloader_donor = make_donor(source, {});
        auto bootloaders = ExtractAll(bootloader_donor, source.metadata.cpu_key);
        const auto extracted_cd =
            bootloaders ? BootloaderCd::parse(bootloaders->bootloaders.cd) : BootloaderCd{};
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
        const auto bootloader_rebuilt = RunBuild(*bootloaders);
        const auto bootloader_roundtrip =
            bootloader_rebuilt ? ExtractAll(*bootloader_rebuilt, bootloaders->metadata.cpu_key)
                               : std::nullopt;
        const auto roundtrip_cd = bootloader_roundtrip
                                      ? BootloaderCd::parse(bootloader_roundtrip->bootloaders.cd)
                                      : BootloaderCd{};
        if (!require(bootloader_roundtrip.has_value() &&
                         bootloader_roundtrip->bootloaders.cb_or_a == source.bootloaders.cb_or_a,
                     "rebuilt CB/A remains serialized-identical") ||
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
        const auto donor_bytes = RunBuild(source);
        auto payload_extracted =
            donor_bytes ? ExtractAll(*donor_bytes, source.metadata.cpu_key) : std::nullopt;
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
        const auto rebuilt = RunBuild(*payload_extracted);
        const auto roundtrip =
            rebuilt ? ExtractAll(*rebuilt, payload_extracted->metadata.cpu_key) : std::nullopt;
        return require(roundtrip.has_value() && roundtrip->payloads.has_value() &&
                           roundtrip->payloads->rebooter == source.payloads->rebooter,
                       "rebuilt rebooter remains serialized-identical") &&
               require(roundtrip->payloads.has_value() &&
                           roundtrip->payloads->fuses == source.payloads->fuses,
                       "rebuilt virtual fuses remain serialized-identical");
    }

    bool test_metadata_overrides_reach_final_patched_cb_b_and_all_cf_slots() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.build_type = BuildType::Glitch2;
        auto cb_a = BootloaderCb::parse(input.bootloaders.cb_or_a);
        if (!cb_a.parse_perbox()) {
            std::abort();
        }
        cb_a.perbox->lockdown_value = 0x11;
        cb_a.perbox->pairing_data[0] = 0x12;
        cb_a.perbox->pairing_data[1] = 0x13;
        cb_a.perbox->pairing_data[2] = 0x14;
        cb_a.serialize_perbox();
        input.bootloaders.cb_or_a = cb_a.serialize();

        auto cb_b = BootloaderCb::parse(input.bootloaders.cb_or_a);
        if (!cb_b.parse_perbox()) {
            std::abort();
        }
        cb_b.perbox->lockdown_value = 0x21;
        cb_b.perbox->pairing_data[0] = 0x22;
        cb_b.perbox->pairing_data[1] = 0x23;
        cb_b.perbox->pairing_data[2] = 0x24;
        cb_b.serialize_perbox();
        input.bootloaders.cb_b = cb_b.serialize();
        input.bootloaders.cf0 = decrypted_cf(0x31, {0x32, 0x33, 0x34});
        input.bootloaders.cf1 = decrypted_cf(0x41, {0x42, 0x43, 0x44});
        const auto update0 = valid_system_update(0x51);
        const auto update1 = valid_system_update(0x61);
        input.bootloaders.cg0 = update0.second;
        input.bootloaders.cg1 = update1.second;
        input.metadata.cb_ldv = 9;
        input.metadata.cf_ldv = 10;
        input.metadata.pairing_data = {0xA1, 0xB2, 0xC3};

        InputPatches patches{};
        patches.automatic =
            InputPatchFile{"automatic", glitch_patchset(0x100, 0x11223344, 0x30, 0, Bytes{0x91})};
        input.patches = std::move(patches);

        const auto built = RunBuild(input);
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
                           image->system_update_1.cf.has_value(),
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
                           image->system_update_1.cf->perbox->lockdown_value == 10 &&
                           std::equal(std::begin(image->system_update_0.cf->perbox->pairing_data),
                                      std::end(image->system_update_0.cf->perbox->pairing_data),
                                      input.metadata.pairing_data.begin()) &&
                           std::equal(std::begin(image->system_update_1.cf->perbox->pairing_data),
                                      std::end(image->system_update_1.cf->perbox->pairing_data),
                                      input.metadata.pairing_data.begin()),
                       "every supplied CF receives the winning LDV and pairing bytes");
    }

    bool test_metadata_override_requires_writable_cb_perbox() {
        auto input = fresh_input(ImageType::SmallBlock);
        input.bootloaders.cb_or_a = Bytes(sizeof(generic_header), 0);
        const auto built = RunBuild(input);
        return require(!built.has_value() &&
                           built.error().code == BuildErrorCode::InvalidBootloader,
                       "unwritable selected CB perbox is a structured bootloader error");
    }

    bool test_present_unwritable_cb_b_remains_metadata_authoritative() {
        auto input = fresh_input(ImageType::SmallBlock);
        auto cb_a = BootloaderCb::parse(input.bootloaders.cb_or_a);
        cb_a.data[0x260] = 0x01;
        cb_a.decrypted = false;
        input.bootloaders.cb_or_a = cb_a.serialize();

        BootloaderCb cb_b{};
        cb_b.header.header.magic = NANDBootloaderMagic::CB;
        cb_b.header.header.version = 1;
        cb_b.header.header.size = sizeof(generic_header);
        input.bootloaders.cb_b = cb_b.serialize();

        const auto built = RunBuild(input);
        return require(
            !built.has_value() && built.error().code == BuildErrorCode::InvalidBootloader,
            "a present header-only CB_B is authoritative and fails metadata structurally");
    }

    bool test_donor_bootloader_chain_is_replaced_by_input_presence() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        auto donor_cb = BootloaderCb::parse(donor_input.bootloaders.cb_or_a);
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

        const auto donor = RunBuild(donor_input);
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

        const auto built = RunBuild(input);
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
        const auto donor = RunBuild(donor_input);
        if (!require(donor.has_value(), "donor CF/CG fixture builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.bootloaders.cf0 = donor_cf; // Same size as the donor CF.
        input.bootloaders.cg0.reset();
        const auto built = RunBuild(input);
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
        const auto donor = RunBuild(donor_input);
        if (!require(donor.has_value(), "header-only CE donor fixture builds")) {
            return false;
        }

        auto input = fresh_input(ImageType::SmallBlock);
        input.metadata.nand_image = *donor;
        input.bootloaders.ce.reset();
        const auto built = RunBuild(input);
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
        const auto donor = RunBuild(donor_input);
        if (!require(donor.has_value(), "shifted donor fixture builds")) {
            return false;
        }

        struct Case {
            BuildType type;
            size_t expected_slot;
            size_t expected_xell;
        };
        const std::array cases{Case{BuildType::Retail, 0xB0000, 0x70000},
                               Case{BuildType::Devkit, 0xB0000, 0x70000},
                               Case{BuildType::Jtag, 0x70000, 0x95060}};
        for (const auto& test_case : cases) {
            auto input = fresh_input(ImageType::SmallBlock);
            input.metadata.nand_image = *donor;
            input.build_type = test_case.type;
            const auto [cf, cg] =
                valid_system_update(static_cast<uint8_t>(0x60 + test_case.expected_slot / 0x10000));
            input.bootloaders.cf0 = cf;
            input.bootloaders.cg0 = cg;
            if (test_case.type == BuildType::Jtag) {
                InputPatches patches{};
                patches.automatic = InputPatchFile{"automatic", jtag_patchset(Bytes{0xA1})};
                input.patches = std::move(patches);
            }

            const auto built = RunBuild(input);
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
                !require(cg_bytes == cg, "replacement CG remains intact beside fixed payloads") ||
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

        const auto built = RunBuild(input);
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

        const auto built = RunBuild(input);
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

    bool test_pairing_only_metadata_rejects_unwritable_cf_perbox() {
        auto input = fresh_input(ImageType::SmallBlock);
        BootloaderCf cf{};
        cf.header.header.magic = NANDBootloaderMagic::CF;
        cf.header.header.version = 1;
        cf.data.assign(0x1EF, 0x5A);
        cf.header.header.size = static_cast<uint32_t>(sizeof(cf_header) + cf.data.size());
        input.bootloaders.cf0 = cf.serialize();

        const auto built = RunBuild(input);
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
                             BootloaderCb::parse(cb_wire).header.header.pairing == pairing,
                         "CB generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderSc sc{};
        sc.header.header.magic = NANDBootloaderMagic::SC;
        sc.header.header.pairing = pairing;
        sc.header.header.size = sizeof(sc_header);
        const auto sc_wire = sc.serialize();
        passed = require(has_big_endian_pairing(sc_wire) &&
                             BootloaderSc::parse(sc_wire).header.header.pairing == pairing,
                         "SC generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.pairing = pairing;
        cd.header.header.size = sizeof(cd_header);
        const auto cd_wire = cd.serialize();
        passed = require(has_big_endian_pairing(cd_wire) &&
                             BootloaderCd::parse(cd_wire).header.header.pairing == pairing,
                         "CD generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.pairing = pairing;
        ce.header.header.size = sizeof(ce_header);
        const auto ce_wire = ce.serialize();
        passed = require(has_big_endian_pairing(ce_wire) &&
                             BootloaderCe::parse(ce_wire).header.header.pairing == pairing,
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
                             BootloaderCf::parse(cf_wire).header.header.pairing == pairing,
                         "CF generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        BootloaderCg cg{};
        cg.header.header.magic = NANDBootloaderMagic::CG;
        cg.header.header.pairing = pairing;
        cg.header.header.size = sizeof(cg_header);
        const auto cg_wire = cg.serialize();
        passed = require(has_big_endian_pairing(cg_wire) &&
                             BootloaderCg::parse(cg_wire).header.header.pairing == pairing,
                         "CG generic pairing is big-endian on wire and host-order after parse") &&
                 passed;

        cf.encrypt(key_1bl);
        const auto encrypted_cf_wire = cf.serialize();
        auto decrypted_cf = BootloaderCf::parse(encrypted_cf_wire);
        decrypted_cf.decrypt(key_1bl);
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
        const auto parsed_cb = BootloaderCb::parse(cb.serialize());
        passed = require(parsed_cb.header.console_seq_allow.console_sequence_allow == 0x1234,
                         "CB console sequence allowance is normalized after parse") &&
                 passed;

        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.size = sizeof(cd_header);
        cd.header.padding = 0x1234;
        const auto cd_wire = cd.serialize();
        passed = require(read_be16(cd_wire, offsetof(cd_header, padding)) == 0x1234 &&
                             BootloaderCd::parse(cd_wire).header.padding == 0x1234,
                         "CD padding is host-order after parse and big-endian on wire") &&
                 passed;

        BootloaderCe ce{};
        ce.header.header.magic = NANDBootloaderMagic::CE;
        ce.header.header.size = sizeof(ce_header);
        ce.header.address = 0x0102030405060708ULL;
        ce.header.size = 0x11223344;
        ce.header.padding = 0x55667788;
        const auto ce_wire = ce.serialize();
        const auto parsed_ce = BootloaderCe::parse(ce_wire);
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
        auto parsed_cg = BootloaderCg::parse(cg_wire);
        passed =
            require(
                read_be32(cg_wire, offsetof(cg_header, source_size)) == 0x10203040 &&
                    read_be32(cg_wire, offsetof(cg_header, target_size)) == 0x50607080 &&
                    parsed_cg.header.source_size == 0x10203040 &&
                    parsed_cg.header.target_size == 0x50607080,
                "CG source and target sizes are host-order after parse and big-endian on wire") &&
            passed;

        parsed_cg.decrypted = true;
        parsed_cg.encrypt(key_1bl);
        auto crypt_roundtrip_cg = BootloaderCg::parse(parsed_cg.serialize());
        crypt_roundtrip_cg.decrypt(key_1bl);
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
        auto cb = BootloaderCb::parse(asymmetric_decrypted_cb(0x1357).serialize());
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
        auto cb = BootloaderCb::parse(asymmetric_decrypted_cb(0x1357).serialize());
        const Bytes original_perbox(cb.data.begin() + 0x10,
                                    cb.data.begin() + 0x10 + sizeof(cb_perbox));
        cb.header.console_seq_allow.console_sequence_allow = 0xBEEF;
        cb.encrypt(key_1bl);
        auto parsed_encrypted = BootloaderCb::parse(cb.serialize());
        parsed_encrypted.decrypt(key_1bl);
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
        header_only_cd.cb_section.cb_or_A = BootloaderCb::parse(bootloaders.cb_or_a);
        header_only_cd.kernel_section.cd.header.header.magic = NANDBootloaderMagic::CD;
        header_only_cd.kernel_section.cd.header.header.size = sizeof(cd_header);

        const auto cb_error = header_only_cb.payload_layout_error();
        const auto cd_error = header_only_cd.payload_layout_error();
        return require(cb_error.has_value() && cb_error->find("CB/A") != std::string::npos,
                       "direct layout validation rejects a header-only required CB/A") &&
               require(cd_error.has_value() && cd_error->find("CD") != std::string::npos,
                       "direct layout validation rejects a header-only required CD");
    }

    bool test_required_chain_relationships_reject_before_serialization() {
        auto header_only_cd = fresh_input(ImageType::SmallBlock);
        BootloaderCd cd{};
        cd.header.header.magic = NANDBootloaderMagic::CD;
        cd.header.header.version = 1;
        cd.header.header.size = sizeof(cd_header);
        header_only_cd.bootloaders.cd = cd.serialize();
        const auto missing_cd_payload = RunBuild(header_only_cd);

        auto cg0_without_cf0 = fresh_input(ImageType::SmallBlock);
        cg0_without_cf0.bootloaders.cg0 = valid_system_update(0x51).second;
        const auto orphan_cg0 = RunBuild(cg0_without_cf0);

        auto cg1_without_cf1 = fresh_input(ImageType::SmallBlock);
        cg1_without_cf1.bootloaders.cg1 = valid_system_update(0x61).second;
        const auto orphan_cg1 = RunBuild(cg1_without_cf1);

        return require(!missing_cd_payload &&
                           missing_cd_payload.error().code == BuildErrorCode::InvalidBootloader,
                       "a header-only required CD is rejected before output") &&
               require(!orphan_cg0 && orphan_cg0.error().code == BuildErrorCode::InvalidInput,
                       "CG0 without CF0 is rejected structurally") &&
               require(!orphan_cg1 && orphan_cg1.error().code == BuildErrorCode::InvalidInput,
                       "CG1 without CF1 is rejected structurally");
    }

    bool test_system_update_slot_zero_overflow_rejects_a_supplied_slot_one() {
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

        const auto built = RunBuild(input);
        return require(!built && built.error().code == BuildErrorCode::InvalidInput,
                       "slot-zero overflow does not silently discard a supplied slot one");
    }

    bool test_replacement_layout_overrides_a_one_slot_donor_header() {
        auto donor_input = fresh_input(ImageType::SmallBlock);
        const auto donor = RunBuild(donor_input);
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

        const auto built = RunBuild(input);
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

    bool test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() {
        const auto source = RunBuild(fresh_input(ImageType::SmallBlock));
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
        const auto rejected = RunBuild(invalid_replacement);
        return require(donor_written && records_are_header_only,
                       "raw donor exposes valid parsed header-only CB and CD records") &&
               require(cleared && all_zero,
                       "clearing a donor includes the full header-only CB and CD chain") &&
               require(!rejected && rejected.error().code == BuildErrorCode::InvalidBootloader,
                       "a replacement header-only required CD remains structurally invalid");
    }

} // namespace

int main() {
    bool passed = true;
    passed = test_glitch_patches_resize_cb_and_cd_and_update_declared_sizes() && passed;
    passed = test_glitch2_targets_cbb() && passed;
    passed = test_noblpatch_skips_bootloader_mutation_but_writes_khv() && passed;
    passed = test_jtag_patchset_is_serialized_at_fixed_region() && passed;
    passed = test_patch_regions_reject_overflow() && passed;
    passed = test_runbuild_rejects_retail_and_devkit_addon_patch_data() && passed;
    passed = test_glitch_patch_region_does_not_overwrite_mobile_data() && passed;
    passed = test_glitch_patch_follows_xell_and_patch_slots() && passed;
    passed = test_bigblock_glitch_uses_big_patch_stride() && passed;
    passed = test_glitch_patch_rejects_rebooter_overlap() && passed;
    passed = test_jtag_xell_without_rebooter_preserves_patches_and_uses_fixed_offset() && passed;
    passed = test_glitch_xell_shifts_patchslots_on_small_and_big_layouts() && passed;
    passed = test_small_glitch_xell_rejects_fixed_payload_collisions() && passed;
    passed = test_donor_transition_rejects_retained_glitch_xell_collision() && passed;
    passed = test_fixed_payloads_roundtrip_in_valid_jtag_and_bigblock_glitch_layouts() && passed;
    passed = test_bigblock_and_emmc_glitch_retain_disjoint_fixed_payloads() && passed;
    passed = test_small_glitch_patch_base_xell_owns_overlapping_fixed_payload_offsets() && passed;
    passed = test_patch_base_xell_ownership_never_falls_back_to_an_internal_jtag_elf() && passed;
    passed = test_big_and_emmc_shifted_patch_base_allow_disjoint_jtag_xell_fallback() && passed;
    passed = test_unambiguous_jtag_xell_preserves_fixed_payload_extraction() && passed;
    passed = test_boot_chain_collision_is_rejected_for_unpatched_payload_layouts() && passed;
    passed = test_bootloader_patch_end_is_bounded_by_boot_chain_layout() && passed;
    passed = test_invalid_input_returns_structured_error() && passed;
    passed = test_emmc_rejects_mobile_slots_without_corona_metadata_fields() && passed;
    passed = test_emmc_donor_rejects_each_high_mobile_when_requested_type_is_mismatched() && passed;
    passed = test_nand_donor_accepts_high_mobile_when_requested_type_is_emmc() && passed;
    passed = test_donor_overlays_replace_explicit_values_and_preserve_mobile_slots() && passed;
    passed = test_mobile_overlay_replaces_longer_donor_mobile_without_stale_tail() && passed;
    passed = test_mobile_overlay_clears_donor_size_when_replacement_exceeds_uint16() && passed;
    passed = test_extracted_plaintext_keyvault_reencrypts_for_a_fresh_layout() && passed;
    passed = test_donor_rejects_a_different_structurally_valid_cpu_key() && passed;
    passed = test_custom_payload_is_rejected_without_an_on_disk_format_contract() && passed;
    passed = test_extract_all_preserves_complete_donor_baseline() && passed;
    passed = test_sc_survives_extraction_and_backing_cleared_layout_override() && passed;
    passed = test_decrypt_all_distinguishes_encrypted_and_zero_key_plaintext_sc() && passed;
    passed = test_fresh_layouts_match_requested_image_types() && passed;
    passed = test_bigblock_flashfs_formats_and_roundtrips_an_empty_overlay() && passed;
    passed = test_bigblock_flashfs_roundtrips_a_file_larger_than_16_kib() && passed;
    passed = test_secure_flashfs_files_roundtrip_through_extract_and_rebuild() && passed;
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
    passed = test_emmc_rejects_each_mobile_slot_without_corona_metadata() && passed;
    passed = test_serialized_mobile_overlays_preserve_absent_slots_for_nand_layouts() && passed;
    passed = test_extraction_roundtrips_serialized_bootloaders_and_payloads() && passed;
    passed = test_metadata_overrides_reach_final_patched_cb_b_and_all_cf_slots() && passed;
    passed = test_metadata_override_requires_writable_cb_perbox() && passed;
    passed = test_present_unwritable_cb_b_remains_metadata_authoritative() && passed;
    passed = test_donor_bootloader_chain_is_replaced_by_input_presence() && passed;
    passed = test_donor_cf_span_is_cleared_when_replacement_omits_cg() && passed;
    passed = test_header_only_donor_ce_is_cleared_when_input_omits_it() && passed;
    passed = test_rebuilt_donor_uses_actual_cf_slot_base_for_each_build_type() && passed;
    passed = test_metadata_cf_roundtrip_preserves_extended_header_fields() && passed;
    passed = test_pairing_only_metadata_updates_every_cf_without_changing_ldv() && passed;
    passed = test_pairing_only_metadata_rejects_unwritable_cf_perbox() && passed;
    passed = test_generic_header_pairing_roundtrips_for_every_bootloader() && passed;
    passed = test_stage_specific_numeric_headers_are_host_order_and_wire_big_endian() && passed;
    passed = test_cb_console_allow_host_value_serializes_without_overwriting_perbox() && passed;
    passed = test_cb_console_allow_host_value_encrypts_and_roundtrips_asymmetrically() && passed;
    passed = test_direct_payload_layout_rejects_header_only_required_records() && passed;
    passed = test_required_chain_relationships_reject_before_serialization() && passed;
    passed = test_system_update_slot_zero_overflow_rejects_a_supplied_slot_one() && passed;
    passed = test_replacement_layout_overrides_a_one_slot_donor_header() && passed;
    passed = test_clear_bootloader_chain_clears_header_only_cb_and_cd_records() && passed;
    return passed ? 0 : 1;
}
