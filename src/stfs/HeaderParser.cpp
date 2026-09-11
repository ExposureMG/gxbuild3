#include <Commons.hpp>
#include <Endian.hpp>
#include <array>
#include <cstring>
#include <fstream>
#include <stdexcept>

namespace stfs {

    namespace {

        Magic parseMagic(std::span<const std::byte> data) {
            std::array<char, 4> magic_bytes;
            std::memcpy(magic_bytes.data(), data.data(), 4);

            if (magic_bytes[0] == 'C' && magic_bytes[1] == 'O' && magic_bytes[2] == 'N' &&
                magic_bytes[3] == ' ') {
                return Magic::CON;
            } else if (magic_bytes[0] == 'P' && magic_bytes[1] == 'I' && magic_bytes[2] == 'R' &&
                       magic_bytes[3] == 'S') {
                return Magic::PIRS;
            } else if (magic_bytes[0] == 'L' && magic_bytes[1] == 'I' && magic_bytes[2] == 'V' &&
                       magic_bytes[3] == 'E') {
                return Magic::LIVE;
            }

            throw std::runtime_error("Invalid magic bytes");
        }

        ConSignature parseConSignature(std::span<const std::byte> data) {
            ConSignature sig;
            const auto* ptr = data.data();

            sig.public_key_certificate_size = readBE16(ptr + 0x004);

            std::memcpy(sig.certificate_owner_console_id.data(), ptr + 0x006, 5);
            std::memcpy(sig.certificate_owner_console_part_number.data(), ptr + 0x00B, 0x14);

            sig.certificate_owner_console_type =
                *reinterpret_cast<const std::uint8_t*>(ptr + 0x01F);

            std::memcpy(sig.certificate_date_of_generation.data(), ptr + 0x020, 8);
            std::memcpy(sig.public_exponent.data(), ptr + 0x028, 4);
            std::memcpy(sig.public_modulus.data(), ptr + 0x02C, 0x80);
            std::memcpy(sig.certificate_signature.data(), ptr + 0x0AC, 0x100);
            std::memcpy(sig.signature.data(), ptr + 0x1AC, 0x80);

            return sig;
        }

        LiveSignature parseLiveSignature(std::span<const std::byte> data) {
            LiveSignature sig;
            const auto* ptr = data.data();

            std::memcpy(sig.package_signature.data(), ptr + 0x004, 0x100);
            std::memcpy(sig.padding.data(), ptr + 0x104, 0x128);

            return sig;
        }

    } // namespace

    Header parseHeader(std::span<const std::byte> data) {
        if (data.size() < 0x1AC) {
            throw std::runtime_error("Insufficient data for header parsing");
        }

        Header header;
        header.magic = parseMagic(data);

        switch (header.magic) {
            case Magic::CON:
                header.signature = parseConSignature(data);
                break;
            case Magic::PIRS:
            case Magic::LIVE:
                header.signature = parseLiveSignature(data);
                break;
        }

        return header;
    }

    Header readHeaderFromFile(const std::filesystem::path& path) {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file: " + path.string());
        }

        file.seekg(0, std::ios::end);
        std::size_t file_size = file.tellg();
        file.seekg(0, std::ios::beg);

        if (file_size < 0x1AC) {
            throw std::runtime_error("File too small for header");
        }

        std::vector<std::byte> buffer(0x1AC);
        file.read(reinterpret_cast<char*>(buffer.data()), 0x1AC);

        return parseHeader(buffer);
    }

} // namespace stfs