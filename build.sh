#!/bin/bash
set -euo pipefail
cmake -B build -S . -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build build -j"$(nproc)"
