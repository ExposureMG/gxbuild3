#include "stfs/HeaderParser.hpp"

#include "Wire.hpp"
#include "stfs/Commons.hpp"
#include "stfs/Layout.hpp"

#include <array>
#include <bit>
#include <cstddef>
#include <fstream>
#include <string_view>
#include <utility>
#include <vector>

namespace gxbuild3::stfs {

    namespace {

        [[nodiscard]] Result<Magic> parse_magic(std::span<const std::byte> data) {
            const std::string_view magic(reinterpret_cast<const char*>(data.data()), 4);

            if (magic == "CON ") {
                return Magic::CON;
            } else if (magic == "PIRS") {
                return Magic::PIRS;
            } else if (magic == "LIVE") {
                return Magic::LIVE;
            }

            return fail(ErrorCode::Malformed, "invalid STFS magic bytes");
        }

        // Copies an on-disk byte or char field into the model's array of the same size.
        template <class To, class From, std::size_t N>
        [[nodiscard]] std::array<To, N> to_array(const From (&field)[N]) {
            return std::bit_cast<std::array<To, N>>(field);
        }

        [[nodiscard]] Result<ConSignature> parse_con_signature(std::span<const std::byte> data) {
            auto disk = wire::read<con_signature_disk>(wire::as_u8(data), kSignatureOffset,
                                                       "STFS CON signature");
            if (!disk) {
                return std::unexpected(std::move(disk.error()));
            }

            ConSignature sig;
            sig.public_key_certificate_size = disk->public_key_certificate_size.get();
            sig.certificate_owner_console_id = to_array<std::byte>(disk->console_id);
            sig.certificate_owner_console_part_number = to_array<char>(disk->part_number);
            sig.certificate_owner_console_type = disk->console_type;
            sig.certificate_date_of_generation = to_array<char>(disk->date);
            sig.public_exponent = to_array<std::byte>(disk->exponent);
            sig.public_modulus = to_array<std::byte>(disk->modulus);
            sig.certificate_signature = to_array<std::byte>(disk->certificate_signature);
            sig.signature = to_array<std::byte>(disk->signature);
            return sig;
        }

        [[nodiscard]] Result<LiveSignature> parse_live_signature(std::span<const std::byte> data) {
            auto disk = wire::read<live_signature_disk>(wire::as_u8(data), kSignatureOffset,
                                                        "STFS LIVE signature");
            if (!disk) {
                return std::unexpected(std::move(disk.error()));
            }

            LiveSignature sig;
            sig.package_signature = to_array<std::byte>(disk->package_signature);
            sig.padding = to_array<std::byte>(disk->padding);
            return sig;
        }

    } // namespace

    Result<Header> parse_header(std::span<const std::byte> data) {
        if (data.size() < kHeaderRegionSize) {
            return fail(ErrorCode::Truncated, "STFS header needs 0x{:X} bytes, got 0x{:X}",
                        kHeaderRegionSize, data.size());
        }

        auto magic = parse_magic(data);
        if (!magic) {
            return std::unexpected(std::move(magic.error()));
        }

        Header header;
        header.magic = *magic;

        switch (header.magic) {
            case Magic::CON: {
                auto signature = parse_con_signature(data);
                if (!signature) {
                    return std::unexpected(std::move(signature.error()));
                }
                header.signature = *signature;
                break;
            }
            case Magic::PIRS:
            case Magic::LIVE: {
                auto signature = parse_live_signature(data);
                if (!signature) {
                    return std::unexpected(std::move(signature.error()));
                }
                header.signature = *signature;
                break;
            }
        }

        return header;
    }

    Result<Header> read_header_from_file(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return fail(ErrorCode::IoError, "cannot open {}", path.string());
        }

        std::vector<std::byte> buffer(kHeaderRegionSize);
        file.read(reinterpret_cast<char*>(buffer.data()),
                  static_cast<std::streamsize>(buffer.size()));
        if (file.gcount() != static_cast<std::streamsize>(buffer.size())) {
            return fail(ErrorCode::Truncated, "{} is too small for an STFS header", path.string());
        }

        return parse_header(buffer);
    }

} // namespace gxbuild3::stfs