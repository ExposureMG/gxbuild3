#include "gxbuild/Library.hpp"

#include "core/BuildRunner.hpp"

#include <exception>
#include <string_view>
#include <type_traits>
#include <utility>

namespace gxbuild {

    namespace {

        template <class Call>
        auto guard_public(std::string_view what, Call&& call)
            -> std::invoke_result_t<Call> try {
            return std::forward<Call>(call)();
        } catch (const std::exception& exception) {
            return fail(ErrorCode::Internal, "{}: {}", what, exception.what());
        }

    } // namespace

    Result<std::vector<uint8_t>> RunBuild(const Input& input) {
        return guard_public("Build failed", [&] { return run_build(input); });
    }

    Result<AllNandInfo> ExtractSomeInfo(std::span<const uint8_t> nand_image) {
        return guard_public("Failed to extract public NAND info",
                            [&] { return extract_some_info(nand_image); });
    }

    Result<AllNandInfo> ExtractSomeInfo(const std::vector<uint8_t>& nand_image) {
        return guard_public("Failed to extract public NAND info",
                            [&] { return extract_some_info(nand_image); });
    }

    Result<InputMetadata> ExtractMetadata(std::span<const uint8_t> nand_image,
                                          std::span<const uint8_t> cpu_key) {
        return guard_public("Failed to extract metadata",
                            [&] { return extract_metadata(nand_image, cpu_key); });
    }

    Result<InputMetadata> ExtractMetadata(const std::vector<uint8_t>& nand_image,
                                          const std::vector<uint8_t>& cpu_key) {
        return guard_public("Failed to extract metadata",
                            [&] { return extract_metadata(nand_image, cpu_key); });
    }

    Result<AllNandInfo> ExtractAllInfo(std::span<const uint8_t> nand_image,
                                       std::span<const uint8_t> cpu_key) {
        return guard_public("Failed to extract NAND info",
                            [&] { return extract_all_info(nand_image, cpu_key); });
    }

    Result<AllNandInfo> ExtractAllInfo(const std::vector<uint8_t>& nand_image,
                                       const std::vector<uint8_t>& cpu_key) {
        return guard_public("Failed to extract NAND info",
                            [&] { return extract_all_info(nand_image, cpu_key); });
    }

    Result<Input> ExtractAll(std::span<const uint8_t> nand_image,
                             std::span<const uint8_t> cpu_key) {
        return guard_public("Failed to extract NAND",
                            [&] { return extract_all(nand_image, cpu_key); });
    }

    Result<Input> ExtractAll(const std::vector<uint8_t>& nand_image,
                             const std::vector<uint8_t>& cpu_key) {
        return guard_public("Failed to extract NAND",
                            [&] { return extract_all(nand_image, cpu_key); });
    }

} // namespace gxbuild
