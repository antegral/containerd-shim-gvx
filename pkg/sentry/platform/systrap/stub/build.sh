#!/bin/sh
# Rebuilds the embedded macOS systrap stubs. Run it from this directory.
# It needs Apple clang and the macOS SDK, and it ad-hoc signs the result.
set -eu

out="${1:-.}"
sdk="$(xcrun --show-sdk-path 2>/dev/null || echo /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

clang -arch arm64 -isysroot "$sdk" -mmacosx-version-min=11.0 -c stub_arm64.S -o "$tmp/stub_arm64.o"
clang -arch arm64 -isysroot "$sdk" -mmacosx-version-min=11.0 -O2 -fno-stack-protector \
  -c stub_darwin.c -o "$tmp/stub_darwin.o" \
  -D_DARWIN_C_SOURCE
clang -arch arm64 -isysroot "$sdk" -mmacosx-version-min=11.0 \
  -o "$out/gvx-stub-darwin-arm64" "$tmp/stub_arm64.o" "$tmp/stub_darwin.o"
codesign --force --sign - "$out/gvx-stub-darwin-arm64"
