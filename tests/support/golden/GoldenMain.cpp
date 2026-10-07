// main() of gxbuild3_golden_tests: golden_main (support/golden/Golden.hpp) runs the tests, lists
// the registered goldens or re-renders the named ones.

#include "support/golden/Golden.hpp"

int main(int argc, char** argv) {
    return gxbuild3::test::golden_main(argc, argv);
}
