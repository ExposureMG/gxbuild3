#include "Options.hpp"

std::optional<OptionsArgs> Options::s_Options;

void Options::Init(OptionsArgs options) {
    s_Options = std::move(options);
}
