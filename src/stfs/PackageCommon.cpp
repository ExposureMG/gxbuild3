#include "PackageCommon.hpp"

#include <cstdint>
#include <stdexcept>

namespace stfs::detail {

    std::vector<std::filesystem::path> buildEntryPaths(const std::vector<FileEntry>& entries) {
        constexpr std::uint16_t kRootIndicator = 0xFFFF;

        std::vector<std::filesystem::path> paths;
        paths.reserve(entries.size());

        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& entry = entries[i];
            std::filesystem::path path{entry.name};

            const auto parent = static_cast<std::uint16_t>(entry.path_indicator);
            if (parent != kRootIndicator) {
                if (parent >= i) {
                    throw std::runtime_error("STFS file table references an invalid parent index");
                }
                path = paths[parent] / path;
            }

            paths.push_back(std::move(path));
        }

        return paths;
    }

    std::filesystem::path safeJoin(const std::filesystem::path& parent,
                                   const std::filesystem::path& relative) {
        if (relative.is_absolute() || relative.has_root_path() || relative.has_root_name()) {
            throw std::runtime_error("STFS entry uses an absolute path");
        }

        const auto normalized = relative.lexically_normal();
        for (const auto& part : normalized) {
            if (part == "..") {
                throw std::runtime_error("STFS entry escapes the target directory");
            }
        }
        if (normalized.empty() || normalized == ".") {
            throw std::runtime_error("STFS entry has an empty path");
        }

        return parent / normalized;
    }

} // namespace stfs::detail
