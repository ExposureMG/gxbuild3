#include "nand/objects/Xboxupd.hpp"

#include "Wire.hpp"
#include "nand/bootloaders/Common.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

#include <cstddef>

namespace gxbuild3::nand {
    namespace {

        // xboxupd.bin is a CF image followed by a CG image. Only the header words below are
        // read, never a whole cf_header (0x30 bytes): the up-front Truncated check stays at
        // 0x20, the smallest CF or CG this split accepts, which also covers the CF cg_size word.
        constexpr std::size_t kBootloaderHeaderSize = 0x20;

        constexpr std::size_t kMagicOffset = offsetof(generic_header, magic);
        constexpr std::size_t kSizeOffset = offsetof(generic_header, size);
        constexpr std::size_t kCgSizeOffset = offsetof(cf_header, cg_size);
        static_assert(kMagicOffset == 0x00);
        static_assert(kSizeOffset == 0x0C);
        static_assert(offsetof(cf_header, header) == 0x00);
        static_assert(kCgSizeOffset == 0x1C);
        static_assert(kCgSizeOffset + sizeof(wire::be32) <= kBootloaderHeaderSize);

    } // namespace

    Result<XboxupdParts> split_xboxupd_raw(std::span<const uint8_t> xboxupd_bytes) {
        if (xboxupd_bytes.size() < kBootloaderHeaderSize) {
            return fail(ErrorCode::Truncated, "xboxupd buffer too small to split ({} bytes)",
                        xboxupd_bytes.size());
        }

        const auto cf_magic_field =
            wire::read<wire::be16>(xboxupd_bytes, kMagicOffset, "xboxupd CF magic");
        if (!cf_magic_field) {
            return std::unexpected(std::move(cf_magic_field.error()));
        }
        const uint16_t cf_magic = cf_magic_field->get();
        if ((cf_magic & 0x0FFF) != 0x346) {
            return fail(ErrorCode::Malformed,
                        "CF header not found in xboxupd (magic=0x{:04X}). invalid xboxupd.bin?",
                        cf_magic);
        }

        const auto cf_size_field =
            wire::read<wire::be32>(xboxupd_bytes, kSizeOffset, "xboxupd CF size");
        if (!cf_size_field) {
            return std::unexpected(std::move(cf_size_field.error()));
        }
        const uint32_t cf_size = cf_size_field->get();
        if (cf_size < kBootloaderHeaderSize) {
            return fail(ErrorCode::Malformed, "invalid CF size 0x{:X} in xboxupd", cf_size);
        }
        if (xboxupd_bytes.size() < cf_size) {
            return fail(ErrorCode::Truncated,
                        "xboxupd buffer too small to contain full CF (CF size 0x{:X}, buffer "
                        "size 0x{:X})",
                        cf_size, xboxupd_bytes.size());
        }

        const auto cg_size_field =
            wire::read<wire::be32>(xboxupd_bytes, kCgSizeOffset, "xboxupd CG size");
        if (!cg_size_field) {
            return std::unexpected(std::move(cg_size_field.error()));
        }
        const uint32_t cg_size = cg_size_field->get();
        const std::size_t cg_offset = cf_size;
        if (cg_size < kBootloaderHeaderSize) {
            return fail(ErrorCode::Malformed, "invalid CG size 0x{:X} in xboxupd", cg_size);
        }
        if (xboxupd_bytes.size() < (cg_offset + cg_size)) {
            return fail(ErrorCode::Truncated,
                        "xboxupd buffer too small to contain full CG (CG size 0x{:X}, buffer "
                        "size 0x{:X})",
                        cg_size, xboxupd_bytes.size());
        }

        const auto cg_magic_field =
            wire::read<wire::be16>(xboxupd_bytes, cg_offset + kMagicOffset, "xboxupd CG magic");
        if (!cg_magic_field) {
            return std::unexpected(std::move(cg_magic_field.error()));
        }
        const uint16_t cg_magic = cg_magic_field->get();
        if ((cg_magic & 0x0FFF) != 0x347) {
            return fail(ErrorCode::Malformed,
                        "CG header not found in xboxupd (magic=0x{:04X}). invalid xboxupd.bin?",
                        cg_magic);
        }

        XboxupdParts parts;
        parts.cf_raw.assign(xboxupd_bytes.begin(),
                            xboxupd_bytes.begin() + static_cast<std::ptrdiff_t>(cf_size));
        parts.cg_raw.assign(xboxupd_bytes.begin() + static_cast<std::ptrdiff_t>(cg_offset),
                            xboxupd_bytes.begin() +
                                static_cast<std::ptrdiff_t>(cg_offset + cg_size));
        Log::Debug("Split xboxupd.bin into CF (0x{:X} bytes) and CG (0x{:X} bytes)", cf_size,
                   cg_size);
        return parts;
    }

    Result<XboxupdParts> split_xboxupd_raw(std::span<const std::byte> xboxupd_bytes) {
        return split_xboxupd_raw(wire::as_u8(xboxupd_bytes));
    }

} // namespace gxbuild3::nand
