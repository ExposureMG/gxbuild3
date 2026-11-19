#include "Scratch.hpp"

#include "Env.hpp"

#include <atomic>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace gxbuild3::test {

    namespace {
        long process_id() {
#ifdef _WIN32
            return static_cast<long>(_getpid());
#else
            return static_cast<long>(::getpid());
#endif
        }

        // "<Suite>.<Test>" of the running test with '/' (parameterized names) made safe for a
        // path; "NoTest" outside a test body.
        std::string current_test_label() {
            const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
            if (info == nullptr) {
                return "NoTest";
            }
            std::string label = std::format("{}.{}", info->test_suite_name(), info->name());
            for (char& c : label) {
                if (c == '/' || c == '\\' || c == ':') {
                    c = '_';
                }
            }
            return label;
        }

        bool keep_failed_scratch() {
            const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
            return info != nullptr && info->result()->Failed() &&
                   env_value("GXBUILD3_KEEP_SCRATCH").has_value();
        }
    } // namespace

    std::filesystem::path scratch_root() {
        return GXBUILD3_TEST_SCRATCH_ROOT;
    }

    ScratchDir::ScratchDir() {
        static std::atomic<unsigned> counter{0};
        path_ =
            scratch_root() / std::format("{}.{}.{}", current_test_label(), process_id(), counter++);
        std::error_code error;
        std::filesystem::remove_all(path_, error);
        std::filesystem::create_directories(path_, error);
        if (error || !std::filesystem::is_directory(path_)) {
            ADD_FAILURE() << "cannot create scratch directory " << path_.string() << ": "
                          << error.message();
        }
    }

    ScratchDir::~ScratchDir() {
        if (!keep_failed_scratch()) {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }
    }

    ScopedCurrentPath::ScopedCurrentPath(const std::filesystem::path& directory) {
        std::error_code error;
        previous_ = std::filesystem::current_path(error);
        if (!error) {
            std::filesystem::current_path(directory, error);
        }
        if (error) {
            ADD_FAILURE() << "cannot change the working directory to " << directory.string() << ": "
                          << error.message();
        }
    }

    ScopedCurrentPath::~ScopedCurrentPath() {
        std::error_code error;
        std::filesystem::current_path(previous_, error);
        if (error) {
            ADD_FAILURE() << "cannot restore the working directory " << previous_.string() << ": "
                          << error.message();
        }
    }

    void ScratchTest::SetUp() {
        scratch_.emplace();
    }

    void ScratchTest::TearDown() {
        scratch_.reset();
    }

    const std::filesystem::path& ScratchTest::root() const {
        return scratch_->path();
    }

    std::filesystem::path ScratchTest::write(const std::filesystem::path& relative,
                                             std::span<const uint8_t> bytes) const {
        const auto path = root() / relative;
        EXPECT_OK(write_file(path, bytes));
        return path;
    }

    std::filesystem::path ScratchTest::write(const std::filesystem::path& relative,
                                             std::string_view text) const {
        return write(relative,
                     std::span{reinterpret_cast<const uint8_t*>(text.data()), text.size()});
    }

    Result<> write_file(const std::filesystem::path& path, std::span<const uint8_t> bytes) {
        std::error_code error;
        if (path.has_parent_path()) {
            std::filesystem::create_directories(path.parent_path(), error);
            if (error) {
                return from_error_code(error, path.parent_path());
            }
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        out.close();
        if (!out) {
            return fail(ErrorCode::IoError, "{}: cannot write", path.string());
        }
        return {};
    }

    Result<Bytes> read_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return fail(ErrorCode::NotFound, "{}: cannot open", path.string());
        }
        Bytes bytes{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
        if (in.bad()) {
            return fail(ErrorCode::IoError, "{}: cannot read", path.string());
        }
        return bytes;
    }

    std::filesystem::path support_dir(const char* env_override) {
        if (env_override != nullptr) {
            if (auto value = env_value(env_override); value && !value->empty()) {
                return *value;
            }
        }
        return GXBUILD3_SUPPORT_DIR;
    }

    Result<Bytes> read_support_file(const std::filesystem::path& relative,
                                    const char* env_override) {
        return read_file(support_dir(env_override) / relative);
    }

} // namespace gxbuild3::test
