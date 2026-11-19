// run_build's secured FlashFS files (src/BuildRunner.cpp, src/nand/objects/SecuredFiles.cpp):
// extended.bin and secdata.bin in the clear round-trip through extract_all and a rebuild,
// crl.bin, extended.bin and a clear fcrt.bin are sealed for the console, a damaged fcrt.bin is
// written as its failed opening (xeBuild 1.21), and an unusable extended.bin or secdata.bin is
// made up clean (build time pinned to 1791105722 in UTC0). The clear fixtures are sealed here with
// GxCrypt's own primitives, independently of src/. One ctest entry per case (each runs
// run_build).

#include "BuildRunner.hpp"
#include "excrypt.h"
#include "nand/objects/SecuredFiles.hpp"
#include "support/Env.hpp"
#include "support/Expect.hpp"
#include "support/builders/Inputs.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::orchestration {
    namespace {

        using test::Bytes;

        using FlashFsFiles = std::vector<std::pair<std::string, Bytes>>;

        // An extended.bin in the clear behind the nonce its plaintext derives, its head the
        // keyvault's.
        Bytes clear_extended(const Input& input, uint8_t fill) {
            const auto& cpu_key = input.metadata.cpu_key;
            Bytes plain(nand::kExtendedSize - 0x10, fill);
            std::copy_n(input.metadata.keyvault->begin() + 0x10, 8, plain.begin());
            const uint8_t tail[2] = {0x07, 0x12};
            uint8_t digest[20]{};
            ExCryptHmacSha(cpu_key.data(), 16, plain.data(), static_cast<uint32_t>(plain.size()),
                           tail, 2, nullptr, 0, digest, sizeof(digest));
            Bytes out(0x10 + plain.size());
            std::copy_n(digest, 0x10, out.begin());
            std::copy(plain.begin(), plain.end(), out.begin() + 0x10);
            return out;
        }

        // A secdata.bin in the clear behind the nonce its plaintext derives.
        Bytes clear_secdata(const Input& input, uint8_t fill) {
            const auto& cpu_key = input.metadata.cpu_key;
            Bytes plain(nand::kSecdataSize - 0x10, fill);
            uint8_t digest[20]{};
            ExCryptHmacSha(cpu_key.data(), 16, plain.data(), static_cast<uint32_t>(plain.size()),
                           nullptr, 0, nullptr, 0, digest, sizeof(digest));
            Bytes out(0x10 + plain.size());
            std::copy_n(digest, 0x10, out.begin());
            std::copy(plain.begin(), plain.end(), out.begin() + 0x10);
            return out;
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
            ExCryptSha(out.data() + 0x150, static_cast<uint32_t>(length - 0x150), nullptr, 0,
                       nullptr, 0, out.data() + 0x0C, 20);
            return out;
        }

        // The body of an fcrt.bin in the clear: the vector at 0x100, 0x0140 at 0x11E and the
        // sealed part from 0x140, its SHA-1 at 0x12C not yet written.
        Bytes clear_fcrt() {
            Bytes fcrt(0x4000);
            std::fill(fcrt.begin() + 0x100, fcrt.begin() + 0x110, uint8_t{0x6C});
            fcrt[0x11E] = 0x01;
            fcrt[0x11F] = 0x40;
            for (size_t at = 0x140; at < fcrt.size(); ++at) {
                fcrt[at] = static_cast<uint8_t>(at * 3 + 1);
            }
            return fcrt;
        }

        // The FlashFS file `name` of an extracted input, or null when it has none.
        const Bytes* flashfs_file(const std::optional<Input>& from, std::string_view name) {
            if (!from || !from->flashfs_sec) {
                return nullptr;
            }
            for (const auto& [file_name, data] : *from->flashfs_sec) {
                if (file_name == name) {
                    return &data;
                }
            }
            return nullptr;
        }

        // Builds `input` and extracts the image under its CPU key into `extracted`; names the
        // step that failed.
        ::testing::AssertionResult build_and_extract(const Input& input,
                                                     std::optional<Input>& extracted) {
            const auto built = run_build(input);
            if (!built) {
                return ::testing::AssertionFailure()
                       << "run_build failed: " << test::describe_error(built.error());
            }
            auto opened = extract_all(*built, input.metadata.cpu_key);
            if (!opened) {
                return ::testing::AssertionFailure()
                       << "extract_all failed: " << test::describe_error(opened.error());
            }
            extracted = std::move(*opened);
            return ::testing::AssertionSuccess();
        }

        std::span<const uint8_t> at(const Bytes& bytes, size_t offset, size_t length) {
            return std::span<const uint8_t>(bytes).subspan(offset, length);
        }

        TEST(SecuredFlashFs, SecureFilesRoundTripThroughExtractAndRebuild) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto& cpu_key = input.metadata.cpu_key;
            const auto extended = clear_extended(input, 0x42);
            const auto secdata = clear_secdata(input, 0x31);
            input.flashfs_sec = FlashFsFiles{{"secdata.bin", secdata}, {"extended.bin", extended}};
            std::optional<Input> extracted;
            ASSERT_TRUE(build_and_extract(input, extracted))
                << "secure FlashFS build succeeds; extraction returns plaintext secure FlashFS "
                   "files";
            const auto* first_extended = flashfs_file(extracted, "extended.bin");
            ASSERT_NE(first_extended, nullptr)
                << "extraction returns plaintext secure FlashFS files";
            EXPECT_BYTES_EQ(extended, *first_extended)
                << "extraction returns plaintext secure FlashFS files";
            const auto* first_secdata = flashfs_file(extracted, "secdata.bin");
            ASSERT_NE(first_secdata, nullptr)
                << "extraction returns plaintext secure FlashFS files";
            EXPECT_TRUE(nand::secdata_opened(*first_secdata, cpu_key))
                << "extraction returns plaintext secure FlashFS files";
            ASSERT_GE(first_secdata->size(), 0x18u);
            EXPECT_BYTES_EQ(at(secdata, 0x10, 8), at(*first_secdata, 0x10, 8))
                << "extraction returns plaintext secure FlashFS files";

            extracted->metadata.nand_image.reset();
            std::optional<Input> roundtrip;
            ASSERT_TRUE(build_and_extract(*extracted, roundtrip))
                << "secure FlashFS rebuild succeeds; secure FlashFS files survive extract and "
                   "rebuild";
            const auto* second_extended = flashfs_file(roundtrip, "extended.bin");
            ASSERT_NE(second_extended, nullptr)
                << "secure FlashFS files survive extract and rebuild";
            EXPECT_BYTES_EQ(extended, *second_extended)
                << "secure FlashFS files survive extract and rebuild";
            const auto* second_secdata = flashfs_file(roundtrip, "secdata.bin");
            ASSERT_NE(second_secdata, nullptr)
                << "secure FlashFS files survive extract and rebuild";
            EXPECT_TRUE(nand::secdata_opened(*second_secdata, cpu_key))
                << "secure FlashFS files survive extract and rebuild";
            ASSERT_GE(second_secdata->size(), secdata.size());
            EXPECT_BYTES_EQ(at(secdata, 0x10, 8), at(*second_secdata, 0x10, 8))
                << "secure FlashFS files survive extract and rebuild";
            EXPECT_BYTES_EQ(at(secdata, 0x28, secdata.size() - 0x28),
                            at(*second_secdata, 0x28, secdata.size() - 0x28))
                << "secure FlashFS files survive extract and rebuild";
        }

        TEST(SecuredFlashFs, SecuredFilesAreSealedForTheConsole) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto& cpu_key = input.metadata.cpu_key;
            input.metadata.cf_ldv = 9;
            const auto clear_crl = clear_signed_record("CRLP", 0xA00);
            const nand::CrlSealing own_sealing{{0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
                                                0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF},
                                               {0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
                                                0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12}};
            const auto own_crl = nand::reseal_crl(clear_crl, cpu_key, own_sealing, {0, 3});
            ASSERT_OK(own_crl) << "the console's crl.bin fixture seals";
            const auto extended = clear_extended(input, 0x5A);

            // fcrt.bin in the clear: the vector at 0x100, the sealed part from 0x140 and its SHA-1
            // at 0x12C.
            auto fcrt = clear_fcrt();
            ExCryptSha(fcrt.data() + 0x140, static_cast<uint32_t>(fcrt.size() - 0x140), nullptr, 0,
                       nullptr, 0, fcrt.data() + 0x12C, 20);

            input.metadata.console_secured_files = {{"crl.bin", *own_crl}};
            input.flashfs_sec = FlashFsFiles{
                {"crl.bin", clear_crl}, {"extended.bin", extended}, {"fcrt.bin", fcrt}};
            std::optional<Input> extracted;
            ASSERT_TRUE(build_and_extract(input, extracted))
                << "a build with secured files extracts";
            ASSERT_TRUE(extracted->flashfs_sec.has_value())
                << "a build with secured files extracts";
            const auto* crl = flashfs_file(extracted, "crl.bin");
            const auto* opened_extended = flashfs_file(extracted, "extended.bin");
            const auto* sealed_fcrt = flashfs_file(extracted, "fcrt.bin");
            ASSERT_TRUE(crl && opened_extended && sealed_fcrt)
                << "the three files are in the image";

            const auto sealing = nand::crl_sealing(*crl, cpu_key);
            alignas(16) EXCRYPT_AES_STATE state{};
            ExCryptAesKey(&state, own_sealing.file_key.data());
            auto feed = own_sealing.iv;
            Bytes body(crl->size() - 0x140);
            ExCryptAesCbc(&state, crl->data() + 0x140, static_cast<uint32_t>(body.size()),
                          body.data(), feed.data(), 0);
            ExCryptAesKey(&state, cpu_key.data());
            std::array<uint8_t, 16> fcrt_feed{};
            std::copy_n(fcrt.begin() + 0x100, fcrt_feed.size(), fcrt_feed.begin());
            Bytes fcrt_body(fcrt.size() - 0x140);
            ASSERT_GE(sealed_fcrt->size(), fcrt.size());
            ExCryptAesCbc(&state, sealed_fcrt->data() + 0x140,
                          static_cast<uint32_t>(fcrt_body.size()), fcrt_body.data(),
                          fcrt_feed.data(), 0);
            const auto& keyvault = *input.metadata.keyvault;

            ASSERT_OK(sealing) << "crl.bin is sealed under the console's own vector and file key";
            EXPECT_BYTES_EQ(own_sealing.iv, sealing->iv)
                << "crl.bin is sealed under the console's own vector and file key";
            EXPECT_BYTES_EQ(own_sealing.file_key, sealing->file_key)
                << "crl.bin is sealed under the console's own vector and file key";
            EXPECT_EQ(body[0x0F], 9) << "crl.bin states the CF lockdown value";
            ASSERT_LE(body.size() - 0x10, clear_crl.size() - 0x150);
            EXPECT_BYTES_EQ(at(clear_crl, 0x150, body.size() - 0x10),
                            at(body, 0x10, body.size() - 0x10))
                << "crl.bin keeps the supplied content";
            ASSERT_EQ(extracted->metadata.console_secured_files.size(), 1u)
                << "extraction keeps the console's own crl.bin";
            EXPECT_BYTES_EQ(*crl, extracted->metadata.console_secured_files.front().second)
                << "extraction keeps the console's own crl.bin";
            EXPECT_TRUE(nand::extended_opened(*opened_extended, cpu_key))
                << "extended.bin carries the nonce its plaintext derives";
            EXPECT_BYTES_EQ(at(keyvault, 0x10, 8), at(*opened_extended, 0x10, 8))
                << "extended.bin's head is the keyvault's";
            EXPECT_BYTES_EQ(at(fcrt, 0, 0x140), at(*sealed_fcrt, 0, 0x140))
                << "fcrt.bin in the clear is sealed under the CPU key and its own vector";
            EXPECT_FALSE(*sealed_fcrt == fcrt)
                << "fcrt.bin in the clear is sealed under the CPU key and its own vector";
            EXPECT_BYTES_EQ(at(fcrt, 0x140, fcrt_body.size()), fcrt_body)
                << "fcrt.bin in the clear is sealed under the CPU key and its own vector";
        }

        // An fcrt.bin that is neither in the clear nor opens under the CPU key is written as
        // xeBuild 1.21 writes it: its header as supplied and its sealed part as the failed opening
        // left it. The console's own copy is carried as it stands.
        TEST(SecuredFlashFs, ADamagedFcrtIsWrittenAsItsFailedOpening) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto& cpu_key = input.metadata.cpu_key;
            auto damaged = clear_fcrt();
            // No hash at 0x12C holds, in the clear or opened.
            std::fill(damaged.begin() + 0x12C, damaged.begin() + 0x140, uint8_t{0xEE});
            alignas(16) EXCRYPT_AES_STATE state{};
            ExCryptAesKey(&state, cpu_key.data());
            std::array<uint8_t, 16> feed{};
            std::copy_n(damaged.begin() + 0x100, feed.size(), feed.begin());
            Bytes failed_opening = damaged;
            ExCryptAesCbc(&state, damaged.data() + 0x140,
                          static_cast<uint32_t>(damaged.size() - 0x140),
                          failed_opening.data() + 0x140, feed.data(), 0);

            input.flashfs_sec = FlashFsFiles{{"fcrt.bin", damaged}};
            std::optional<Input> supplied_build;
            ASSERT_TRUE(build_and_extract(input, supplied_build))
                << "a supplied damaged fcrt.bin is written as its failed opening";
            const auto* supplied = flashfs_file(supplied_build, "fcrt.bin");
            input.metadata.console_secured_files = {{"fcrt.bin", damaged}};
            std::optional<Input> own_build;
            ASSERT_TRUE(build_and_extract(input, own_build))
                << "the console's own fcrt.bin that does not open is carried as it stands";
            const auto* own = flashfs_file(own_build, "fcrt.bin");

            ASSERT_NE(supplied, nullptr)
                << "a supplied damaged fcrt.bin is written as its failed opening";
            EXPECT_BYTES_EQ(failed_opening, *supplied)
                << "a supplied damaged fcrt.bin is written as its failed opening";
            EXPECT_FALSE(*supplied == damaged)
                << "a supplied damaged fcrt.bin is written as its failed opening";
            ASSERT_NE(own, nullptr)
                << "the console's own fcrt.bin that does not open is carried as it stands";
            EXPECT_BYTES_EQ(damaged, *own)
                << "the console's own fcrt.bin that does not open is carried as it stands";
        }

        // Whether `data` is an extended.bin made up clean: kExtendedSize bytes that open under
        // the CPU key, the keyvault's head at 0x10 and zero from 0x18.
        ::testing::AssertionResult clean_extended_file(const Bytes* data,
                                                       std::span<const uint8_t> cpu_key,
                                                       const Bytes& keyvault) {
            if (!data) {
                return ::testing::AssertionFailure() << "extended.bin is absent";
            }
            if (data->size() != nand::kExtendedSize) {
                return ::testing::AssertionFailure()
                       << "extended.bin is 0x" << std::hex << data->size() << " bytes";
            }
            if (!nand::extended_opened(*data, cpu_key)) {
                return ::testing::AssertionFailure() << "extended.bin does not open";
            }
            if (!std::equal(keyvault.begin() + 0x10, keyvault.begin() + 0x18,
                            data->begin() + 0x10)) {
                return ::testing::AssertionFailure() << "extended.bin's head is not the keyvault's";
            }
            if (!std::all_of(data->begin() + 0x18, data->end(),
                             [](uint8_t value) { return value == 0; })) {
                return ::testing::AssertionFailure() << "extended.bin is not zero from 0x18";
            }
            return ::testing::AssertionSuccess();
        }

        // Whether `data` is a secdata.bin made up clean: kSecdataSize bytes that open under the
        // CPU key, 1 at 0x18, the lockdown value 9 at 0x19, zero to 0x20, the stamp at 0x20 and
        // zero from 0x28.
        ::testing::AssertionResult clean_secdata_file(const Bytes* data,
                                                      std::span<const uint8_t> cpu_key,
                                                      const std::array<uint8_t, 8>& stamp) {
            if (!data) {
                return ::testing::AssertionFailure() << "secdata.bin is absent";
            }
            if (data->size() != nand::kSecdataSize) {
                return ::testing::AssertionFailure()
                       << "secdata.bin is 0x" << std::hex << data->size() << " bytes";
            }
            if (!nand::secdata_opened(*data, cpu_key)) {
                return ::testing::AssertionFailure() << "secdata.bin does not open";
            }
            if ((*data)[0x18] != 0x01 || (*data)[0x19] != 9 ||
                !std::all_of(data->begin() + 0x1A, data->begin() + 0x20,
                             [](uint8_t value) { return value == 0; })) {
                return ::testing::AssertionFailure()
                       << "secdata.bin does not state 1 and the lockdown value 9 at 0x18";
            }
            if (!std::equal(stamp.begin(), stamp.end(), data->begin() + 0x20)) {
                return ::testing::AssertionFailure() << "secdata.bin does not carry the stamp";
            }
            if (!std::all_of(data->begin() + 0x28, data->end(),
                             [](uint8_t value) { return value == 0; })) {
                return ::testing::AssertionFailure() << "secdata.bin is not zero from 0x28";
            }
            return ::testing::AssertionSuccess();
        }

        // An extended.bin or secdata.bin of the wrong length or that nothing supplied, an
        // extended.bin that opens under no key and the console's own secdata.bin when it does not
        // open are made up clean, as xeBuild 1.21 makes them up: zero but the keyvault's head in
        // extended.bin, and the console's head (or a drawn one), 1, the lockdown value and the
        // stamp in secdata.bin. A supplied secdata.bin of the right length that does not open is
        // written as it stands.
        TEST(SecuredFlashFs, UnusableExtendedAndSecdataAreMadeUpClean) {
            auto input = test::fresh_input(ImageType::SmallBlock);
            const auto cpu_key = input.metadata.cpu_key;
            const auto keyvault = *input.metadata.keyvault;
            input.metadata.cf_ldv = 9;
            constexpr int64_t kSeconds = 1791105722;
            const auto stamp = nand::secured_file_stamp(kSeconds);
            const auto build_and_open = [](const Input& build, std::optional<Input>& opened) {
                const test::PinnedBuildTime pin{"1791105722", "UTC0"};
                return build_and_extract(build, opened);
            };

            // Wrong lengths: the console's own secdata.bin opens, so its head is taken.
            const auto own_secdata = clear_secdata(input, 0x66);
            input.metadata.console_secured_files = {{"secdata.bin", own_secdata}};
            input.flashfs_sec = FlashFsFiles{{"extended.bin", Bytes(0x10, 0x42)},
                                             {"secdata.bin", Bytes(0x3FF, 0x31)}};
            std::optional<Input> wrong_length;
            ASSERT_TRUE(build_and_open(input, wrong_length))
                << "copies of the wrong length are made up clean, secdata.bin under the console's "
                   "head";

            // Nothing supplied: no console copy, so the head is drawn.
            input.metadata.console_secured_files.clear();
            input.flashfs_sec = FlashFsFiles{{"extended.bin", Bytes{}}, {"secdata.bin", Bytes{}}};
            std::optional<Input> unsupplied;
            ASSERT_TRUE(build_and_open(input, unsupplied))
                << "files nothing supplied are made up clean";

            // An extended.bin that opens under no key and the console's own secdata.bin that does
            // not open are made up clean; another secdata.bin that does not open stands.
            const Bytes unopened_secdata(nand::kSecdataSize, 0x31);
            input.metadata.console_secured_files = {{"secdata.bin", unopened_secdata}};
            input.flashfs_sec = FlashFsFiles{{"extended.bin", Bytes(nand::kExtendedSize, 0x42)},
                                             {"secdata.bin", unopened_secdata}};
            std::optional<Input> unopened;
            ASSERT_TRUE(build_and_open(input, unopened))
                << "an extended.bin and the console's secdata.bin that do not open are made up "
                   "clean";
            input.flashfs_sec->back().second = Bytes(nand::kSecdataSize, 0x32);
            std::optional<Input> supplied_unopened;
            ASSERT_TRUE(build_and_open(input, supplied_unopened))
                << "a supplied secdata.bin that does not open is written as it stands";

            const auto* short_secdata = flashfs_file(wrong_length, "secdata.bin");
            EXPECT_TRUE(
                clean_extended_file(flashfs_file(wrong_length, "extended.bin"), cpu_key, keyvault))
                << "copies of the wrong length are made up clean";
            ASSERT_TRUE(clean_secdata_file(short_secdata, cpu_key, stamp))
                << "copies of the wrong length are made up clean";
            EXPECT_BYTES_EQ(at(own_secdata, 0x10, 8), at(*short_secdata, 0x10, 8))
                << "secdata.bin of the wrong length is made up under the console's head";
            EXPECT_TRUE(
                clean_extended_file(flashfs_file(unsupplied, "extended.bin"), cpu_key, keyvault))
                << "files nothing supplied are made up clean";
            EXPECT_TRUE(clean_secdata_file(flashfs_file(unsupplied, "secdata.bin"), cpu_key, stamp))
                << "files nothing supplied are made up clean";
            EXPECT_TRUE(
                clean_extended_file(flashfs_file(unopened, "extended.bin"), cpu_key, keyvault))
                << "an extended.bin and the console's secdata.bin that do not open are made up "
                   "clean";
            EXPECT_TRUE(clean_secdata_file(flashfs_file(unopened, "secdata.bin"), cpu_key, stamp))
                << "an extended.bin and the console's secdata.bin that do not open are made up "
                   "clean";
            const auto* standing = flashfs_file(supplied_unopened, "secdata.bin");
            ASSERT_NE(standing, nullptr)
                << "a supplied secdata.bin that does not open is written as it stands";
            EXPECT_BYTES_EQ(Bytes(nand::kSecdataSize, 0x32), *standing)
                << "a supplied secdata.bin that does not open is written as it stands";
        }

    } // namespace
} // namespace gxbuild3::orchestration
