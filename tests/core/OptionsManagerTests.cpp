// OptionsManager (src/Args.cpp): the nopatch stage list and resolve_no_patch, and the button
// options that take xeBuild's names only, checked again by validate_input.

#include "Args.hpp"
#include "InputSample.hpp"
#include "InputValidator.hpp"
#include "support/Expect.hpp"

#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace gxbuild3::core {
    namespace {

        TEST(OptionsManager, NopatchAccumulatesStageByStage) {
            OptionsManager options;
            EXPECT_TRUE(options.parse("nopatch=cb")) << "nopatch takes one stage";
            EXPECT_EQ(options.get_string("nopatch"), std::optional<std::string>{"cb"})
                << "nopatch takes one stage";
            EXPECT_TRUE(options.parse("nopatch=khv,nopatch=cd"))
                << "repeated nopatch settings accumulate in stage order";
            EXPECT_EQ(options.get_string("nopatch"), std::optional<std::string>{"cb+cd+khv"})
                << "repeated nopatch settings accumulate in stage order";
            EXPECT_FALSE(options.set("nopatch", "ce"))
                << "an unknown stage or a joined list is refused and the earlier value kept";
            EXPECT_FALSE(options.set("nopatch", "cb+cd"))
                << "an unknown stage or a joined list is refused and the earlier value kept";
            EXPECT_EQ(options.get_string("nopatch"), std::optional<std::string>{"cb+cd+khv"})
                << "an unknown stage or a joined list is refused and the earlier value kept";

            const auto all = resolve_no_patch(options.data());
            OptionsArgs legacy;
            legacy.noblpatch = true;
            const auto old = resolve_no_patch(legacy);
            EXPECT_TRUE(all.cb) << "every named stage is skipped";
            EXPECT_TRUE(all.cd) << "every named stage is skipped";
            EXPECT_TRUE(all.khv) << "every named stage is skipped";
            EXPECT_TRUE(old.cb) << "noblpatch still means nopatch=cb and nopatch=cd";
            EXPECT_TRUE(old.cd) << "noblpatch still means nopatch=cb and nopatch=cd";
            EXPECT_FALSE(old.khv) << "noblpatch still means nopatch=cb and nopatch=cd";
            EXPECT_TRUE(options.set("nopatch", "")) << "a blank nopatch clears the list";
            EXPECT_FALSE(options.has("nopatch")) << "a blank nopatch clears the list";
        }

        TEST(OptionsManager, ButtonOptionsTakeXebuildNamesOnly) {
            EXPECT_EQ(OptionsManager::power_on_reason("power"), std::optional<uint8_t>{0x11})
                << "button names map to xeBuild's header bytes in any case";
            EXPECT_EQ(OptionsManager::power_on_reason(" Eject "), std::optional<uint8_t>{0x12})
                << "button names map to xeBuild's header bytes in any case";
            EXPECT_EQ(OptionsManager::power_on_reason("wiredx"), std::optional<uint8_t>{0x5A})
                << "button names map to xeBuild's header bytes in any case";
            EXPECT_EQ(OptionsManager::power_on_reason("wiredxb3"), std::optional<uint8_t>{0x5A})
                << "button names map to xeBuild's header bytes in any case";
            EXPECT_EQ(OptionsManager::power_on_reason("0x11"), std::nullopt)
                << "a number or an unknown name is no button";
            EXPECT_EQ(OptionsManager::power_on_reason(""), std::nullopt)
                << "a number or an unknown name is no button";
            EXPECT_EQ(OptionsManager::power_on_reason("powerbutton"), std::nullopt)
                << "a number or an unknown name is no button";

            OptionsManager options;
            EXPECT_TRUE(options.set("xellbutton", "Power"))
                << "xellbutton, xellbutton2 and dualboot take button names";
            EXPECT_TRUE(options.set("xellbutton2", "remox"))
                << "xellbutton, xellbutton2 and dualboot take button names";
            EXPECT_TRUE(options.set("dualboot", "kiosk"))
                << "xellbutton, xellbutton2 and dualboot take button names";
            EXPECT_FALSE(options.set("xellbutton", "bogus"))
                << "an unknown button is refused and the earlier value kept";
            EXPECT_EQ(options.get_string("xellbutton"), std::optional<std::string>{"Power"})
                << "an unknown button is refused and the earlier value kept";

            OptionsManager blank;
            EXPECT_TRUE(blank.set("xellbutton2", "")) << "a blank button names none";
            EXPECT_FALSE(blank.has("xellbutton2")) << "a blank button names none";
            EXPECT_TRUE(blank.set("xellbutton2", "remox")) << "a blank button names none";
            EXPECT_TRUE(blank.set("xellbutton2", " ")) << "a blank button names none";
            EXPECT_FALSE(blank.has("xellbutton2")) << "a blank button names none";

            auto input = valid_input();
            input.options = options.data();
            ASSERT_OK(validate_input(input)) << "named buttons validate";
            input.options.dualboot = "sideways";
            EXPECT_ERROR(validate_input(input), InputErrorCode::InvalidOption)
                << "an unknown button supplied directly is rejected";
        }

    } // namespace
} // namespace gxbuild3::core
