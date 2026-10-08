#include "ResolverTest.hpp"

#include "support/Expect.hpp"

#include <gtest/gtest.h>

namespace gxbuild3::cli {

    void ResolverTest::SetUp() {
        ScratchTest::SetUp();
        ASSERT_OK_AND_ASSIGN(tree_, test::ResolverTree::make(root()));
    }

} // namespace gxbuild3::cli
