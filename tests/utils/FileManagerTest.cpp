#include "FileManagerTest.hpp"

#include "support/Bytes.hpp"

#include <algorithm>
#include <gtest/gtest.h>

namespace gxbuild3::utils {

    test::Bytes make_simple_package(const StfsFiles& files, std::string_view corrupt_file) {
        if (files.size() >= 64) {
            ADD_FAILURE() << "fixture fits in one file table";
            return {};
        }
        test::Bytes package(0xC000 + files.size() * 0x1000, 0);
        std::copy_n("PIRS", 4, package.begin());
        test::put_be32(package, 0x340, 0xA000);
        package[0x379] = 0x24;
        package[0x37B] = 1; // block_separation: read-only layout
        package[0x37C] = 1; // file table block count (little endian)
        for (size_t block = 0; block <= files.size(); ++block) {
            const size_t hash = 0xA000 + block * 0x18;
            package[hash + 0x14] = 0x80;
            package[hash + 0x15] = package[hash + 0x16] = package[hash + 0x17] = 0xFF;
        }
        for (size_t i = 0; i < files.size(); ++i) {
            const auto& [name, data] = files[i];
            if (name.size() > 40 || data.size() > 0x1000) {
                ADD_FAILURE() << "fixture entry fits: " << name;
                return {};
            }
            const size_t entry = 0xB000 + i * 0x40;
            std::copy(name.begin(), name.end(), package.begin() + entry);
            package[entry + 0x28] = static_cast<uint8_t>(name.size());
            package[entry + 0x29] = package[entry + 0x2C] = 1;
            package[entry + 0x2F] = static_cast<uint8_t>(i + 1);
            package[entry + 0x32] = package[entry + 0x33] = 0xFF;
            test::put_be32(package, entry + 0x34, static_cast<uint32_t>(data.size()));
            std::copy(data.begin(), data.end(), package.begin() + 0xC000 + i * 0x1000);
            if (name == corrupt_file) {
                package[0xA000 + (i + 1) * 0x18 + 0x14] = 0; // invalid block chain
            }
        }
        return package;
    }

    test::Bytes make_xboxupd(uint16_t version) {
        test::Bytes xboxupd(0x40, 0);
        xboxupd[0] = xboxupd[0x20] = 0x43;
        xboxupd[1] = 0x46;
        xboxupd[0x21] = 0x47;
        xboxupd[2] = xboxupd[0x22] = static_cast<uint8_t>(version >> 8);
        xboxupd[3] = xboxupd[0x23] = static_cast<uint8_t>(version);
        test::put_be32(xboxupd, 0x0C, 0x20);
        test::put_be32(xboxupd, 0x1C, 0x20);
        return xboxupd;
    }

    test::Bytes xboxupd_cf(const test::Bytes& xboxupd) {
        return {xboxupd.begin(), xboxupd.begin() + 0x20};
    }

    test::Bytes xboxupd_cg(const test::Bytes& xboxupd) {
        return {xboxupd.begin() + 0x20, xboxupd.end()};
    }

    std::optional<test::Bytes> payload(const IniFilesResult& result, std::string_view name) {
        const auto it = std::ranges::find_if(
            result.flashfs_sec, [&](const auto& entry) { return entry.first == name; });
        if (it == result.flashfs_sec.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    void FileManagerTest::SetUp() {
        ScratchTest::SetUp();
        working_directory_.emplace(root());
        write("version/_test.ini", "[testbl]\nnone\n[flashfs]\ndash.xex\n");
        clear_stfs_cache();
    }

    void FileManagerTest::TearDown() {
        clear_stfs_cache();
        working_directory_.reset();
        ScratchTest::TearDown();
    }

    void FileManagerTest::write_stfs(const std::filesystem::path& relative, const StfsFiles& files,
                                     std::string_view corrupt_file) const {
        write(relative, make_simple_package(files, corrupt_file));
    }

} // namespace gxbuild3::utils
