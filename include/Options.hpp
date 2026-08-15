#pragma once

#include "Args.hpp"

#include <cassert>

class Options {
  public:
    static void Init(OptionsArgs options);

    [[nodiscard]] static const OptionsArgs& Get() {
        assert(s_Options.has_value() && "Options::Init() not called");
        return *s_Options;
    }

  private:
    static std::optional<OptionsArgs> s_Options;
};
