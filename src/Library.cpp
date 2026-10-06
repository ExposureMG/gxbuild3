#include "Library.hpp"

#include "BuildRunner.hpp"
#include "utils/Log.hpp"

#include <exception>
#include <string_view>
#include <type_traits>
#include <utility>

namespace GxBuild {

    namespace {

        // The public extraction boundary, and the only place an extraction Error is logged: the
        // core's reason is logged once and the caller sees std::nullopt. Only std (allocation)
        // exceptions can still come out of a core; they are logged the same way.
        template <class Extract>
        auto extract_or_log(std::string_view what, Extract&& extract)
            -> std::optional<typename std::invoke_result_t<Extract>::value_type> try {
            auto result = std::forward<Extract>(extract)();
            if (!result) {
                gxbuild3::Log::Error("{}: {}", what, result.error().describe());
                return std::nullopt;
            }
            return std::move(*result);
        } catch (const std::exception& exception) {
            gxbuild3::Log::Error("{}: {}", what, exception.what());
            return std::nullopt;
        }

        constexpr std::string_view kSomeInfo = "Failed to extract public NAND info";
        constexpr std::string_view kMetadata = "Failed to extract metadata";
        constexpr std::string_view kAllInfo = "Failed to extract NAND info";
        constexpr std::string_view kAll = "Failed to extract NAND";

    } // namespace

    BuildResult RunBuild(const Input& input) {
        return gxbuild3::run_build(input);
    }

    std::optional<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image) {
        return extract_or_log(kSomeInfo, [&] { return gxbuild3::extract_some_info(nand_image); });
    }

    std::optional<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image) {
        return extract_or_log(kSomeInfo, [&] { return gxbuild3::extract_some_info(nand_image); });
    }

    std::optional<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                                 std::span<const uint8_t> cpu_key) {
        return extract_or_log(kMetadata,
                              [&] { return gxbuild3::extract_metadata(nand_image, cpu_key); });
    }

    std::optional<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                                 const std::vector<uint8_t>& cpu_key) {
        return extract_or_log(kMetadata,
                              [&] { return gxbuild3::extract_metadata(nand_image, cpu_key); });
    }

    std::optional<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                              std::span<const uint8_t> cpu_key) {
        return extract_or_log(kAllInfo,
                              [&] { return gxbuild3::extract_all_info(nand_image, cpu_key); });
    }

    std::optional<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                              const std::vector<uint8_t>& cpu_key) {
        return extract_or_log(kAllInfo,
                              [&] { return gxbuild3::extract_all_info(nand_image, cpu_key); });
    }

    std::optional<Input> ExtractAll(std::span<const uint8_t> nand_image,
                                    std::span<const uint8_t> cpu_key) {
        return extract_or_log(kAll, [&] { return gxbuild3::extract_all(nand_image, cpu_key); });
    }

    std::optional<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                                    const std::vector<uint8_t>& cpu_key) {
        return extract_or_log(kAll, [&] { return gxbuild3::extract_all(nand_image, cpu_key); });
    }

} // namespace GxBuild
