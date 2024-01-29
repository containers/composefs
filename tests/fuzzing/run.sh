#!/bin/sh

set -xeuo pipefail

./configure HFUZZ_CC_UBSAN=1 HFUZZ_CC_ASAN=1 CC=hfuzz-clang CPPFLAGS="-D FUZZER" CFLAGS="-ggdb3 -g3 -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-div,indirect-calls" --enable-static --disable-shared

make -j $(nproc)

bwrap --bind / / --dev-bind /dev/null /dev/null --dev-bind /dev/urandom /dev/urandom --bind ${PWD} ${PWD} --remount-ro / honggfuzz --verifier --linux_perf_instr --threads 4 -s --exit_upon_crash -i tests/fuzzing -- tools/mkcomposefs
