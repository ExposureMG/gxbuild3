#!/bin/bash
cmake -B build -S . -G Ninja
cmake --build build -j${nproc}
