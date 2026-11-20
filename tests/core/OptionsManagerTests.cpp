// OptionsManager (src/Args.cpp): the nopatch stage list and resolve_no_patch, and the button
// options that take xeBuild's names only, checked again by validate_input.

#include "Args.hpp"
#include "InputSample.hpp"
#include "InputValidator.hpp"
#include "support/Expect.hpp"

#include <array>
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

        TEST(OptionsManager, SettingsAndKeyvaultOptionsValidateAndClearOnBlank) {
            EXPECT_EQ(OptionsManager::parse_u32(" 65 "), std::optional<uint32_t>{65u});
            EXPECT_EQ(OptionsManager::parse_u32("0x300"), std::optional<uint32_t>{0x300u});
            EXPECT_EQ(OptionsManager::parse_u32("0XFFFFFFFF"),
                      std::optional<uint32_t>{0xFFFFFFFFu});
            EXPECT_EQ(OptionsManager::parse_u32(""), std::nullopt);
            EXPECT_EQ(OptionsManager::parse_u32("-5"), std::nullopt);
            EXPECT_EQ(OptionsManager::parse_u32("65c"), std::nullopt);
            EXPECT_EQ(OptionsManager::parse_u32("0x100000000"), std::nullopt);

            EXPECT_EQ(OptionsManager::parse_u16("0x00FF"), std::optional<uint16_t>{0x00FFu});
            EXPECT_EQ(OptionsManager::parse_u16("0xFFFF"), std::optional<uint16_t>{0xFFFFu});
            EXPECT_EQ(OptionsManager::parse_u16("0x10000"), std::nullopt);

            const std::array<uint8_t, 6> expected_mac{0x00, 0x22, 0x48, 0xF1, 0x01, 0x02};
            EXPECT_EQ(OptionsManager::parse_mac_id(" 00:22:48:F1:01:02 "), expected_mac);
            EXPECT_EQ(OptionsManager::parse_mac_id("002248f10102"), expected_mac);
            EXPECT_EQ(OptionsManager::parse_mac_id("00:22:48:F1:01"), std::nullopt);
            EXPECT_EQ(OptionsManager::parse_mac_id("00:22:48:ZZ:01:02"), std::nullopt);

            const std::array<uint8_t, 16> expected_dvd{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB,
                                                       0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
                                                       0x89, 0xAB, 0xCD, 0xEF};
            EXPECT_EQ(OptionsManager::parse_dvd_key(" 0123456789ABCDEF0123456789abcdef "),
                      expected_dvd);
            EXPECT_EQ(OptionsManager::parse_dvd_key("0123456789ABCDEF"), std::nullopt);
            EXPECT_EQ(OptionsManager::parse_dvd_key("01:23:45:67:89:AB:CD:EF:01:23:45:67:89:AB:CD"),
                      std::nullopt);
            EXPECT_EQ(OptionsManager::parse_dvd_key("0123456789ABCDEF0123456789ABCDEG"),
                      std::nullopt);

            OptionsManager options;
            EXPECT_TRUE(options.set("cputemp", "65"));
            EXPECT_FALSE(options.set("cputemp", "bad"))
                << "a malformed setting is refused and the earlier value kept";
            EXPECT_EQ(options.get_string("cputemp"), std::optional<std::string>{"65"});
            EXPECT_TRUE(options.set("cputemp", "")) << "a blank value clears the setting";
            EXPECT_FALSE(options.has("cputemp"));

            EXPECT_TRUE(options.set("gameregion", "0x02FE"));
            EXPECT_FALSE(options.set("gameregion", "0x10000"));
            EXPECT_EQ(options.get_string("gameregion"), std::optional<std::string>{"0x02FE"});
            EXPECT_TRUE(options.set("gameregion", " "));
            EXPECT_FALSE(options.has("gameregion"));

            EXPECT_TRUE(options.set("macid", "00:22:48:F1:01:02"));
            EXPECT_FALSE(options.set("macid", "notamac"));
            EXPECT_EQ(options.get_string("macid"),
                      std::optional<std::string>{"00:22:48:F1:01:02"});
            EXPECT_TRUE(options.set("macid", ""));
            EXPECT_FALSE(options.has("macid"));

            EXPECT_TRUE(options.set("dvdkey", "0123456789ABCDEF0123456789ABCDEF"));
            EXPECT_FALSE(options.set("dvdkey", "short"));
            EXPECT_EQ(options.get_string("dvdkey"),
                      std::optional<std::string>{"0123456789ABCDEF0123456789ABCDEF"});
            EXPECT_TRUE(options.set("dvdkey", ""));
            EXPECT_FALSE(options.has("dvdkey"));

            auto input = valid_input();
            input.options.cputemp = "65";
            input.options.gputemp = " ";
            input.options.gameregion = "0x00FF";
            input.options.macid = "00:22:48:F1:01:02";
            input.options.dvdkey = "";
            ASSERT_OK(validate_input(input)) << "valid and blank values pass validate_input";

            {
                auto bad = input;
                bad.options.cputemp = "abc";
                EXPECT_ERROR(validate_input(bad), InputErrorCode::InvalidOption);
            }
            {
                auto bad = input;
                bad.options.gameregion = "0x10000";
                EXPECT_ERROR(validate_input(bad), InputErrorCode::InvalidOption);
            }
            {
                auto bad = input;
                bad.options.macid = "1234";
                EXPECT_ERROR(validate_input(bad), InputErrorCode::InvalidOption);
            }
            {
                auto bad = input;
                bad.options.dvdkey = "ZZZZ";
                EXPECT_ERROR(validate_input(bad), InputErrorCode::InvalidOption);
            }
        }

    } // namespace
} // namespace gxbuild3::core
