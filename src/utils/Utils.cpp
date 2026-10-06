#include "utils/Utils.hpp"

#include <cerrno>
#include <string_view>
#include <system_error>

namespace gxbuild3::utils {

    std::string bytes_to_hex(std::span<const uint8_t> bytes) {
        static constexpr char hex_chars[] = "0123456789ABCDEF";
        std::string hex;
        hex.reserve(bytes.size() * 2);
        for (uint8_t b : bytes) {
            hex.push_back(hex_chars[(b >> 4) & 0x0F]);
            hex.push_back(hex_chars[b & 0x0F]);
        }
        return hex;
    }

    namespace {

        // Builds the Error for a stream that failed to open, from the errno the open left
        // behind. std::fstream does not promise to set errno, so a zero errno falls back to a
        // generic message.
        std::unexpected<Error> open_failure(const fs::path& path, int saved_errno,
                                            std::string_view action) {
            if (saved_errno != 0) {
                return from_error_code(std::error_code(saved_errno, std::generic_category()), path);
            }
            return fail(ErrorCode::IoError, "{}: could not open the file for {}", path.string(),
                        action);
        }

    } // namespace

    Result<std::vector<uint8_t>> read_file(const fs::path& path) {
        errno = 0;
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            const int saved_errno = errno;
            std::error_code status_error;
            if (!fs::exists(path, status_error) && !status_error) {
                return from_error_code(std::make_error_code(std::errc::no_such_file_or_directory),
                                       path);
            }
            return open_failure(path, saved_errno, "reading");
        }

        const std::streamsize size = file.tellg();
        if (size < 0) {
            return fail(ErrorCode::IoError, "{}: could not determine the file size", path.string());
        }
        file.seekg(0, std::ios::beg);

        std::vector<uint8_t> buffer(static_cast<size_t>(size));
        if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
            return fail(ErrorCode::IoError, "{}: could not read {} bytes", path.string(), size);
        }

        return buffer;
    }

    Result<std::vector<uint8_t>> read_file(const fs::path& path, size_t max_length) {
        auto result = read_file(path);
        if (result && result->size() > max_length) {
            result->resize(max_length);
        }
        return result;
    }

    Result<void> write_file(const fs::path& path, const std::vector<uint8_t>& data) {
        if (path.has_parent_path() && !directory_exists(path.parent_path())) {
            if (auto created = utils::create_directory(path.parent_path()); !created) {
                return with_context(std::move(created),
                                    "creating the parent directory of " + path.string());
            }
        }

        errno = 0;
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file.is_open()) {
            return open_failure(path, errno, "writing");
        }

        file.write(reinterpret_cast<const char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
        file.flush();
        file.close();
        // failbit and badbit are sticky, so this covers the write, the flush and the close.
        if (file.fail()) {
            return fail(ErrorCode::IoError, "{}: could not write {} bytes", path.string(),
                        data.size());
        }

        return {};
    }

    bool directory_exists(const fs::path& path) {
        std::error_code ec;
        return fs::is_directory(path, ec);
    }

    Result<void> create_directory(const fs::path& path) {
        std::error_code ec;
        if (fs::is_directory(path, ec)) {
            return {};
        }
        fs::create_directories(path, ec);
        if (ec) {
            return from_error_code(ec, path);
        }
        if (!fs::is_directory(path, ec)) {
            return fail(ErrorCode::IoError, "{}: exists and is not a directory", path.string());
        }
        return {};
    }

} // namespace gxbuild3::utils
