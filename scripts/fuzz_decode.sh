#!/usr/bin/env bash
set -euo pipefail

# Reproducible local fuzzing of bytes that enter from peers. This uses a
# separate Clang/ASan/UBSan build and only writes inside this checkout.
repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
duration="${1:-300}"
if [[ ! "$duration" =~ ^[0-9]+$ ]] || (( duration == 0 )); then
    printf 'Usage: %s [positive-seconds]\n' "$0" >&2
    exit 2
fi

cmake -S "$repo_dir" -B "$repo_dir/build" -DBUILD_TESTING=ON
cmake --build "$repo_dir/build" --target eclipse-node node_tx_fixture -j2
cmake -S "$repo_dir" -B "$repo_dir/build-fuzz" \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS='-O1 -g -fsanitize=fuzzer-no-link,address,undefined -fno-omit-frame-pointer' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address,undefined' \
    -DECLIPSE_BUILD_FUZZ=ON -DBUILD_TESTING=OFF
cmake --build "$repo_dir/build-fuzz" --target eclipse-fuzz-decode -j2
python3 "$repo_dir/tests/fuzz_seed.py" "$repo_dir/build/eclipse-node" \
    "$repo_dir/build/node_tx_fixture" "$repo_dir/fuzz-corpus"
mkdir -p "$repo_dir/fuzz-artifacts"

export ASAN_OPTIONS="detect_leaks=0:quarantine_size_mb=64:malloc_context_size=10"
exec "$repo_dir/build-fuzz/eclipse-fuzz-decode" "$repo_dir/fuzz-corpus" \
    "-artifact_prefix=$repo_dir/fuzz-artifacts/" \
    -max_len=70000 -rss_limit_mb=1024 -timeout=20 \
    "-max_total_time=$duration"
