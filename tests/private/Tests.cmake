# gxbuild3_private_tests: KeyvaultCrypto, keyvault_decrypt and Keyvault::decrypt against a
# console's private fixtures, which are never committed. The cache variables below name them
# (git-ignored _temp/ by default) and reach the binary as compile definitions on this target
# only. All three absent: every KeyvaultCrypto case skips (GTEST_SKIP), and ctest reports the
# bundle Skipped through SKIP_BUNDLE; some absent: every case fails, naming the missing roles.
# The fixture set is all or nothing, so one skip regex over the bundle cannot hide a failure.
# State/PrivateFixtureState checks that classification on dummy files on every clone.
set(GXBUILD3_KEYVAULT_CPU_KEY_FILE "${PROJECT_SOURCE_DIR}/_temp/cpukey.txt"
    CACHE FILEPATH "Private CPU key fixture (32 hex characters)")
set(GXBUILD3_KEYVAULT_ENCRYPTED_FILE "${PROJECT_SOURCE_DIR}/_temp/KV_en.bin"
    CACHE FILEPATH "Private encrypted keyvault fixture")
set(GXBUILD3_KEYVAULT_DECRYPTED_FILE "${PROJECT_SOURCE_DIR}/_temp/KV_dec.bin"
    CACHE FILEPATH "Private independently decrypted keyvault fixture")

gxbuild3_add_gtest(gxbuild3_private_tests
    PREFIX private
    LABELS unit private
    SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/PrivateFixtures.cpp
        ${CMAKE_CURRENT_LIST_DIR}/KeyvaultCryptoTests.cpp
        ${CMAKE_CURRENT_LIST_DIR}/PrivateFixtureStateTests.cpp
    BUNDLE
        KeyvaultCrypto
        State/PrivateFixtureState
    SKIP_BUNDLE
        KeyvaultCrypto)
target_compile_definitions(gxbuild3_private_tests PRIVATE
    GXBUILD3_KEYVAULT_CPU_KEY_FILE="${GXBUILD3_KEYVAULT_CPU_KEY_FILE}"
    GXBUILD3_KEYVAULT_ENCRYPTED_FILE="${GXBUILD3_KEYVAULT_ENCRYPTED_FILE}"
    GXBUILD3_KEYVAULT_DECRYPTED_FILE="${GXBUILD3_KEYVAULT_DECRYPTED_FILE}")
