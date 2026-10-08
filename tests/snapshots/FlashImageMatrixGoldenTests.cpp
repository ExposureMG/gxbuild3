// tests/golden/flashimage_matrix.txt: the synthetic fresh-layout matrix, Small/Big/Emmc x the
// eight build types plain and sealed, plus the header encoded for a zeroed nand_header
// (FlashImageMatrixRender.cpp), compared per section. The old FlashImageGoldenTests.cpp main()
// rendered the whole file once and compared it; a cell that did not build or kept a zero nonce
// was a failed check. Its sections, which partition the file in this order:
//
//   HeaderEncode   the "# F0c" comment and the header_encode.<Mode>. lines of the three shapes;
//   24 cells       matrix.<Mode>.<Type>., shape-major as the file lists them;
//   trailer        matrix.cells=<count>.
//
// FlashImageMatrixCell renders one cell (two full-size images written, one sealed and parsed
// back) and compares the lines its key owns; each of its build checks is one failure. It is
// instantiated per build type over the three shapes (Retail/FlashImageMatrixCell.MatchesSlice/
// Small ...), each instantiation one bundled ctest entry of about 1-4 s. Its plain companion
// FlashImageMatrixGolden (gtest forbids TEST and TEST_P in one suite) holds the header slice,
// the trailer, whose count is the size of the cell tables, and IsPartitioned, which takes the
// sections in file order. A cell that depended on an earlier one would fail its compare here; it
// is never rewritten. The whole-file renderer registered for --update composes the same pieces.

#include "FlashImageGoldenRender.hpp"
#include "nand/FlashDriver.hpp"
#include "support/Expect.hpp"
#include "support/golden/Golden.hpp"

#include <array>
#include <cstddef>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace gxbuild3::snapshots {
    namespace {

        using flashimage_matrix::kGolden;
        using flashimage_matrix::render_file;
        using nand::Driver;

        GX_GOLDEN(kGolden, render_file);

        struct MatrixCell {
            const char* name;
            Driver::DriverMode mode;
            BuildType type;
            std::string_view key;
        };
        GX_PRINT_ROW_AS_NAME(MatrixCell)

        constexpr MatrixCell kRetailCells[] = {
            {"Small", Driver::Small, BuildType::Retail, "matrix.Small.Retail."},
            {"Big", Driver::Big, BuildType::Retail, "matrix.Big.Retail."},
            {"Emmc", Driver::Emmc, BuildType::Retail, "matrix.Emmc.Retail."},
        };
        constexpr MatrixCell kJtagCells[] = {
            {"Small", Driver::Small, BuildType::Jtag, "matrix.Small.Jtag."},
            {"Big", Driver::Big, BuildType::Jtag, "matrix.Big.Jtag."},
            {"Emmc", Driver::Emmc, BuildType::Jtag, "matrix.Emmc.Jtag."},
        };
        constexpr MatrixCell kGlitchCells[] = {
            {"Small", Driver::Small, BuildType::Glitch, "matrix.Small.Glitch."},
            {"Big", Driver::Big, BuildType::Glitch, "matrix.Big.Glitch."},
            {"Emmc", Driver::Emmc, BuildType::Glitch, "matrix.Emmc.Glitch."},
        };
        constexpr MatrixCell kGlitch2Cells[] = {
            {"Small", Driver::Small, BuildType::Glitch2, "matrix.Small.Glitch2."},
            {"Big", Driver::Big, BuildType::Glitch2, "matrix.Big.Glitch2."},
            {"Emmc", Driver::Emmc, BuildType::Glitch2, "matrix.Emmc.Glitch2."},
        };
        constexpr MatrixCell kGlitch2mCells[] = {
            {"Small", Driver::Small, BuildType::Glitch2m, "matrix.Small.Glitch2m."},
            {"Big", Driver::Big, BuildType::Glitch2m, "matrix.Big.Glitch2m."},
            {"Emmc", Driver::Emmc, BuildType::Glitch2m, "matrix.Emmc.Glitch2m."},
        };
        constexpr MatrixCell kGlitch3Cells[] = {
            {"Small", Driver::Small, BuildType::Glitch3, "matrix.Small.Glitch3."},
            {"Big", Driver::Big, BuildType::Glitch3, "matrix.Big.Glitch3."},
            {"Emmc", Driver::Emmc, BuildType::Glitch3, "matrix.Emmc.Glitch3."},
        };
        constexpr MatrixCell kDevglCells[] = {
            {"Small", Driver::Small, BuildType::Devgl, "matrix.Small.Devgl."},
            {"Big", Driver::Big, BuildType::Devgl, "matrix.Big.Devgl."},
            {"Emmc", Driver::Emmc, BuildType::Devgl, "matrix.Emmc.Devgl."},
        };
        constexpr MatrixCell kDevkitCells[] = {
            {"Small", Driver::Small, BuildType::Devkit, "matrix.Small.Devkit."},
            {"Big", Driver::Big, BuildType::Devkit, "matrix.Big.Devkit."},
            {"Emmc", Driver::Emmc, BuildType::Devkit, "matrix.Emmc.Devkit."},
        };

        // The cell tables in the renderer's build-type order; row i of each is shape kModes[i].
        constexpr std::array<std::span<const MatrixCell>, 8> kCellTables{
            kRetailCells,   kJtagCells,    kGlitchCells, kGlitch2Cells,
            kGlitch2mCells, kGlitch3Cells, kDevglCells,  kDevkitCells};

        constexpr std::array<std::string_view, 2> kHeaderEncodeKeys{"# F0c ", "header_encode."};
        constexpr std::array<std::string_view, 1> kTrailerKeys{"matrix.cells="};
        constexpr test::Section kHeaderEncodeSection{"header_encode", kHeaderEncodeKeys};
        constexpr test::Section kTrailerSection{"trailer", kTrailerKeys};

        test::Section cell_section(const MatrixCell& cell) {
            return {cell.key, std::span{&cell.key, 1}};
        }

        std::size_t cell_count() {
            std::size_t cells = 0;
            for (const auto table : kCellTables) {
                cells += table.size();
            }
            return cells;
        }

        class FlashImageMatrixCell : public ::testing::TestWithParam<MatrixCell> {};

        TEST_P(FlashImageMatrixCell, MatchesSlice) {
            const MatrixCell& cell = GetParam();
            std::vector<std::string> problems;
            const auto text = flashimage_matrix::render_cell(flashimage_cells_support(), cell.mode,
                                                             cell.type, problems);
            for (const auto& problem : problems) {
                ADD_FAILURE() << problem;
            }
            EXPECT_TRUE(test::matches_golden_slice(kGolden, cell_section(cell), text));
        }

        INSTANTIATE_TEST_SUITE_P(Retail, FlashImageMatrixCell, ::testing::ValuesIn(kRetailCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Jtag, FlashImageMatrixCell, ::testing::ValuesIn(kJtagCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch, FlashImageMatrixCell, ::testing::ValuesIn(kGlitchCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch2, FlashImageMatrixCell, ::testing::ValuesIn(kGlitch2Cells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch2m, FlashImageMatrixCell,
                                 ::testing::ValuesIn(kGlitch2mCells), test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Glitch3, FlashImageMatrixCell, ::testing::ValuesIn(kGlitch3Cells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Devgl, FlashImageMatrixCell, ::testing::ValuesIn(kDevglCells),
                                 test::RowName{});
        INSTANTIATE_TEST_SUITE_P(Devkit, FlashImageMatrixCell, ::testing::ValuesIn(kDevkitCells),
                                 test::RowName{});

        TEST(FlashImageMatrixGolden, HeaderEncodeMatchesSlice) {
            EXPECT_TRUE(test::matches_golden_slice(kGolden, kHeaderEncodeSection,
                                                   flashimage_matrix::render_header_encode()));
        }

        TEST(FlashImageMatrixGolden, CellCountTrailerMatchesTheCellTables) {
            EXPECT_EQ(cell_count(),
                      flashimage_matrix::kModes.size() * flashimage_matrix::kTypes.size());
            EXPECT_TRUE(test::matches_golden_slice(
                kGolden, kTrailerSection, flashimage_matrix::render_trailer(cell_count())));
        }

        TEST(FlashImageMatrixGolden, IsPartitioned) {
            // File order: the header, then the cells shape-major, then the trailer.
            std::vector<test::Section> sections{kHeaderEncodeSection};
            for (std::size_t m = 0; m < flashimage_matrix::kModes.size(); ++m) {
                for (const auto table : kCellTables) {
                    sections.push_back(cell_section(table[m]));
                }
            }
            sections.push_back(kTrailerSection);
            EXPECT_TRUE(test::golden_is_partitioned(kGolden, sections));
        }

    } // namespace
} // namespace gxbuild3::snapshots
