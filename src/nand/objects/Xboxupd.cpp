#include "nand/objects/Xboxupd.hpp"

#include "Endian.hpp"
#include "utils/Log.hpp"
#include "utils/Utils.hpp"

namespace gxbuild3::nand {
    namespace {

        constexpr std::size_t kBootloaderHeaderSize = 0x20;

        std::vector<uint8_t> bytes_to_u8(std::span<const std::byte> data) {
            std::vector<uint8_t> out;
            out.reserve(data.size());
            for (const auto byte : data) {
                out.push_back(std::to_integer<uint8_t>(byte));
            }
            return out;
        }

    } // namespace

    Result<XboxupdParts> split_xboxupd_raw(std::span<const uint8_t> xboxupd_bytes) {
        if (xboxupd_bytes.size() < kBootloaderHeaderSize) {
            return fail(ErrorCode::Truncated, "xboxupd buffer too small to split ({} bytes)",
                        xboxupd_bytes.size());
        }

        const std::byte* raw = std::as_bytes(xboxupd_bytes).data();
        const uint16_t cf_magic = read_be16(raw);
        if ((cf_magic & 0x0FFF) != 0x346) {
            return fail(ErrorCode::Malformed,
                        "CF header not found in xboxupd (magic=0x{:04X}). invalid xboxupd.bin?",
                        cf_magic);
        }

        const uint32_t cf_size = read_be32(raw + 0x0C);
        if (cf_size < kBootloaderHeaderSize) {
            return fail(ErrorCode::Malformed, "invalid CF size 0x{:X} in xboxupd", cf_size);
        }
        if (xboxupd_bytes.size() < cf_size) {
            return fail(ErrorCode::Truncated,
                        "xboxupd buffer too small to contain full CF (CF size 0x{:X}, buffer "
                        "size 0x{:X})",
                        cf_size, xboxupd_bytes.size());
        }

        const uint32_t cg_size = read_be32(raw + 0x1C);
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

        const uint16_t cg_magic = read_be16(raw + cg_offset);
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
        return split_xboxupd_raw(std::span<const uint8_t>(bytes_to_u8(xboxupd_bytes)));
    }

} // namespace gxbuild3::nand
