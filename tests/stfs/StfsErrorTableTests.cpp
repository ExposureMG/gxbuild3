// The exact ErrorCode of every malformed-container case, one hand-named row each in today's
// order: open-time refusals of StfsContainer::open, extraction-time ones of
// extract_file_by_name and extract_all, and the free extract_file / extract_file_to_disk
// functions. Each row builds its package only when it runs, so instantiation does no I/O. Two
// rows also pin a piece of the message ("(0xAB)", "escapes").
//
// The /dev/full row is its own instantiation, NeedsDevFull/StfsErrorCode, outside the
// Row/StfsErrorCode bundle: it skips where /dev/full is missing, which the fixture's SetUp
// decides from the row's needs_dev_full flag (no Row/ row sets it).

#include "PirsPackage.hpp"
#include "stfs/FileExtractor.hpp"
#include "stfs/MetadataParser.hpp"
#include "stfs/StfsContainer.hpp"
#include "support/Expect.hpp"
#include "support/Scratch.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace gxbuild3::stfs {
    namespace {

        namespace fs = std::filesystem;
        using pirs::Bytes;
        using pirs::data_offset;
        using pirs::entry_offset;
        using pirs::hash_offset;
        using pirs::kVolumeDescriptor;
        using pirs::make_package;
        using pirs::pattern;
        using pirs::put_be;
        using pirs::put_le;

        // The Result of any call as Result<>: the error kept, the value dropped.
        template <class T> Result<> outcome(const Result<T>& result) {
            if (result) {
                return {};
            }
            return std::unexpected(result.error());
        }

        // A failed precondition of a row: Internal, which no row expects, so the row fails
        // with this text.
        std::unexpected<Error> precondition_failed(std::string_view what, const Error& error) {
            return std::unexpected(
                Error{ErrorCode::Internal, std::string(what) + ": " + error.describe()});
        }

        // The container keeps a view of `bytes`; it is dropped before this returns.
        Result<> open_error(const Bytes& bytes) {
            return outcome(StfsContainer::open(bytes));
        }

        Result<> extract_by_name_error(const Bytes& bytes, std::string_view name) {
            const auto container = StfsContainer::open(bytes);
            if (!container) {
                return precondition_failed("open unexpectedly failed", container.error());
            }
            return outcome(container->extract_file_by_name(name));
        }

        Result<> extract_all_error(const Bytes& bytes) {
            const auto container = StfsContainer::open(bytes);
            if (!container) {
                return precondition_failed("open unexpectedly failed", container.error());
            }
            const test::ScratchDir dir;
            return container->extract_all(dir.path() / "out");
        }

        Bytes with_magic(Bytes bytes, std::string_view magic) {
            for (std::size_t i = 0; i < 4; ++i) {
                bytes[i] = static_cast<std::byte>(magic[i]);
            }
            return bytes;
        }

        Bytes pirs_buffer(std::size_t size) {
            return with_magic(Bytes(size, std::byte{0}), "PIRS");
        }

        Bytes one_file() {
            return make_package({{"a.bin", pattern(10, 1)}});
        }

        Bytes patched(std::size_t offset, std::uint64_t value, std::size_t width, bool big_endian) {
            auto bytes = one_file();
            if (big_endian) {
                put_be(bytes, offset, value, width);
            } else {
                put_le(bytes, offset, value, width);
            }
            return bytes;
        }

        Result<> free_extract(const Bytes& bytes, Magic magic, bool verify) {
            const auto container = StfsContainer::open(bytes);
            if (!container) {
                return precondition_failed("the synthetic package opens", container.error());
            }
            const auto meta = parse_metadata(bytes);
            if (!meta) {
                return precondition_failed("parse_metadata accepts the synthetic package",
                                           meta.error());
            }
            const auto* vd = std::get_if<StfsVolumeDescriptor>(&meta->volume_descriptor);
            if (vd == nullptr) {
                return std::unexpected(
                    Error{ErrorCode::Internal, "synthetic package has an STFS descriptor"});
            }
            return outcome(extract_file(bytes, container->entries().at(0), magic, 0xA000, verify,
                                        &vd->top_hash_table_hash, pirs::total_blocks(bytes)));
        }

        Result<> free_to_disk(const Bytes& bytes, const fs::path& path) {
            const auto container = StfsContainer::open(bytes);
            if (!container) {
                return precondition_failed("the synthetic package opens", container.error());
            }
            return extract_file_to_disk(bytes, container->entries().at(0), Magic::PIRS, 0xA000,
                                        path);
        }

        struct ErrorRow {
            std::string name;
            std::string what; // the old table's text, printed with a failure
            ErrorCode expected;
            std::function<Result<>()> run;
            std::string_view must_contain = {};
            bool needs_dev_full = false;
        };
        GX_PRINT_ROW_AS_NAME(ErrorRow)

        Result<> open_name_length(std::uint8_t length) {
            auto bytes = one_file();
            bytes[entry_offset(0) + 0x28] = static_cast<std::byte>(0x40 | length);
            return open_error(bytes);
        }

        Result<> open_named(const std::string& name) {
            return open_error(make_package({{name, pattern(10, 1)}}));
        }

        std::vector<ErrorRow> error_rows() {
            std::vector<ErrorRow> rows;
            // Open-time.
            rows.push_back({"OpenCONMagicFullSizeBuffer", "open: CON magic, full-size buffer",
                            ErrorCode::Malformed,
                            [] { return open_error(with_magic(one_file(), "CON ")); }});
            rows.push_back({"OpenLIVEMagicFullSizeBuffer", "open: LIVE magic, full-size buffer",
                            ErrorCode::Malformed,
                            [] { return open_error(with_magic(one_file(), "LIVE")); }});
            rows.push_back({"Open0x100ByteNonPIRSBuffer", "open: 0x100-byte non-PIRS buffer",
                            ErrorCode::Malformed,
                            [] { return open_error(Bytes(0x100, std::byte{0x5A})); }});
            rows.push_back({"Open0x100BytePIRSBuffer", "open: 0x100-byte PIRS buffer",
                            ErrorCode::Truncated, [] { return open_error(pirs_buffer(0x100)); }});
            rows.push_back({"Open0x1000BytePIRSBuffer", "open: 0x1000-byte PIRS buffer",
                            ErrorCode::Truncated, [] { return open_error(pirs_buffer(0x1000)); }});
            rows.push_back({"OpenHeaderSize0x100", "open: header_size 0x100", ErrorCode::Malformed,
                            [] { return open_error(patched(0x340, 0x100u, 4, true)); }});
            rows.push_back({"OpenHeaderSize0x100000", "open: header_size 0x100000",
                            ErrorCode::Malformed,
                            [] { return open_error(patched(0x340, 0x100000u, 4, true)); }});
            rows.push_back({"OpenHeaderSize0xFFFFF000", "open: header_size 0xFFFFF000",
                            ErrorCode::Malformed,
                            [] { return open_error(patched(0x340, 0xFFFFF000u, 4, true)); }});
            rows.push_back({"OpenDescriptorType1", "open: descriptor_type 1",
                            ErrorCode::Unsupported,
                            [] { return open_error(patched(0x3A9, 1u, 4, true)); }});
            rows.push_back({"OpenDescriptorType2", "open: descriptor_type 2",
                            ErrorCode::Unsupported,
                            [] { return open_error(patched(0x3A9, 2u, 4, true)); }});
            rows.push_back({"OpenFileTableBlockCount0x0", "open: file table block count 0x0",
                            ErrorCode::Malformed, [] {
                                return open_error(patched(kVolumeDescriptor + 0x03, 0u, 2, false));
                            }});
            rows.push_back(
                {"OpenFileTableBlockCount0x8000", "open: file table block count 0x8000",
                 ErrorCode::Malformed,
                 [] { return open_error(patched(kVolumeDescriptor + 0x03, 0x8000u, 2, false)); }});
            rows.push_back({"OpenBlockSeparationBit0Clear", "open: block_separation bit 0 clear",
                            ErrorCode::Unsupported, [] {
                                auto bytes = one_file();
                                bytes[kVolumeDescriptor + 0x02] = std::byte{0x00};
                                return open_error(bytes);
                            }});
            rows.push_back({"OpenTableCount2WithA1BlockChain",
                            "open: table count 2 with a 1-block chain", ErrorCode::Truncated, [] {
                                return open_error(patched(kVolumeDescriptor + 0x03, 2, 2, false));
                            }});
            rows.push_back({"OpenNameLength0x29", "open: name_length 0x29", ErrorCode::Malformed,
                            [] { return open_name_length(0x29); }});
            rows.push_back({"OpenNameLength0x3F", "open: name_length 0x3F", ErrorCode::Malformed,
                            [] { return open_name_length(0x3F); }});
            rows.push_back({"OpenNameStartingWithNUL", "open: name starting with NUL",
                            ErrorCode::Malformed, [] {
                                auto bytes = one_file();
                                bytes[entry_offset(0)] = std::byte{0};
                                return open_error(bytes);
                            }});
            rows.push_back({"OpenNameASlashB", "open: name \"a/b\"", ErrorCode::Malformed,
                            [] { return open_named("a/b"); }});
            rows.push_back({"OpenNameABackslashB", "open: name \"a\\\\b\"", ErrorCode::Malformed,
                            [] { return open_named("a\\b"); }});
            rows.push_back({"OpenNameDotDotEscaped", "open: name \"../escaped\"",
                            ErrorCode::Malformed, [] { return open_named("../escaped"); }});

            // Extraction-time.
            rows.push_back({"ExtractFileByNameBroken2BlockChain",
                            "extract_file_by_name: broken 2-block chain", ErrorCode::Truncated, [] {
                                auto bytes = make_package({{"a.bin", pattern(0x1800, 1), false}});
                                put_be(bytes, hash_offset(1) + 0x15, 0xFFFFFF, 3);
                                return extract_by_name_error(bytes, "a.bin");
                            }});
            rows.push_back({"ExtractFileByNameHashStatus0xAB",
                            "extract_file_by_name: hash status 0xAB", ErrorCode::Malformed,
                            [] {
                                auto bytes = make_package({{"a.bin", pattern(10, 1), false}});
                                bytes[hash_offset(1) + 0x14] = std::byte{0xAB};
                                return extract_by_name_error(bytes, "a.bin");
                            },
                            "(0xAB)"});
            rows.push_back({"ExtractFileByNameConsecutiveBlocksAllocatedTooSmall",
                            "extract_file_by_name: consecutive blocks_allocated too small",
                            ErrorCode::Malformed, [] {
                                auto bytes = make_package({{"a.bin", pattern(0x2800, 6), true}});
                                put_le(bytes, entry_offset(0) + 0x29, 2, 3);
                                return extract_by_name_error(bytes, "a.bin");
                            }});
            rows.push_back({"ExtractFileByNameConsecutiveStartingBlock0xFFFFFE",
                            "extract_file_by_name: consecutive starting_block 0xFFFFFE",
                            ErrorCode::OutOfRange, [] {
                                auto bytes = make_package({{"a.bin", pattern(0x2800, 6), true}});
                                put_le(bytes, entry_offset(0) + 0x2F, 0xFFFFFE, 3);
                                return extract_by_name_error(bytes, "a.bin");
                            }});
            rows.push_back({"ExtractFileByNameConsecutive0xFFFFFFBlocksSize0xFFFFFFFF",
                            "extract_file_by_name: consecutive 0xFFFFFF blocks, size 0xFFFFFFFF",
                            ErrorCode::OutOfRange, [] {
                                auto bytes = make_package({{"a.bin", pattern(0x10, 6), true}});
                                put_le(bytes, entry_offset(0) + 0x29, 0xFFFFFF, 3);
                                put_be(bytes, entry_offset(0) + 0x34, 0xFFFFFFFF, 4);
                                return extract_by_name_error(bytes, "a.bin");
                            }});
            rows.push_back({"ExtractAllParentSelfReference", "extract_all: parent self-reference",
                            ErrorCode::Malformed, [] {
                                return extract_all_error(
                                    make_package({{"a.bin", pattern(10, 1), true, 0}}));
                            }});
            rows.push_back({"ExtractAllParentForwardReference",
                            "extract_all: parent forward reference", ErrorCode::Malformed, [] {
                                return extract_all_error(make_package(
                                    {{"a", {}, true, 1, true}, {"b", {}, true, 0, true}}));
                            }});
            rows.push_back(
                {"ExtractAllDotDotDirectory", "extract_all: .. directory",
                 ErrorCode::InvalidArgument,
                 [] {
                     return extract_all_error(make_package(
                         {{"..", {}, true, -1, true}, {"escaped", pattern(10, 2), true, 0}}));
                 },
                 "escapes"});
            rows.push_back({"FreeExtractFileMagicCON", "free extract_file: Magic::CON",
                            ErrorCode::Unsupported,
                            [] { return free_extract(one_file(), Magic::CON, false); }});
            rows.push_back({"FreeExtractFileVerifyCorruptDataBlock",
                            "free extract_file: verify, corrupt data block",
                            ErrorCode::HashMismatch, [] {
                                auto bytes = one_file();
                                bytes[data_offset(1) + 0x800] ^= std::byte{0x01};
                                return free_extract(bytes, Magic::PIRS, true);
                            }});
            rows.push_back({"FreeExtractFileVerifyCorruptHashTable",
                            "free extract_file: verify, corrupt hash table",
                            ErrorCode::HashMismatch, [] {
                                auto bytes = one_file();
                                bytes[hash_offset(5) + 0x3] ^= std::byte{0x01};
                                return free_extract(bytes, Magic::PIRS, true);
                            }});
            // Today's row 32, "free extract_file_to_disk: /dev/full", is dev_full_rows().
            rows.push_back({"FreeExtractFileToDiskUnopenablePath",
                            "free extract_file_to_disk: unopenable path", ErrorCode::IoError, [] {
                                const test::ScratchDir dir;
                                return free_to_disk(one_file(), dir.path() / "no" / "dir" / "x");
                            }});
            return rows;
        }

        std::vector<ErrorRow> dev_full_rows() {
            return {{"FreeExtractFileToDiskDevFull",
                     "free extract_file_to_disk: /dev/full",
                     ErrorCode::IoError,
                     [] { return free_to_disk(one_file(), "/dev/full"); },
                     {},
                     true}};
        }

        class StfsErrorCode : public ::testing::TestWithParam<ErrorRow> {
          protected:
            void SetUp() override {
                if (GetParam().needs_dev_full && !fs::exists("/dev/full")) {
                    GTEST_SKIP() << "no /dev/full";
                }
            }
        };

        TEST_P(StfsErrorCode, FailsWithItsPinnedCode) {
            const auto& row = GetParam();
            const auto result = row.run();
            EXPECT_ERROR(result, row.expected) << row.what;
            if (!row.must_contain.empty()) {
                EXPECT_ERROR_HAS(result, row.expected, row.must_contain) << row.what;
            }
        }

        INSTANTIATE_TEST_SUITE_P(Row, StfsErrorCode, ::testing::ValuesIn(error_rows()),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(NeedsDevFull, StfsErrorCode, ::testing::ValuesIn(dev_full_rows()),
                                 test::RowName{});

    } // namespace
} // namespace gxbuild3::stfs
