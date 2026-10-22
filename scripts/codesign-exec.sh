#!/bin/sh
# Signs a Go test binary with the hypervisor entitlement on macOS, then runs it.
# Use it as `go test -exec "$PWD/scripts/codesign-exec.sh" ./...`.
# An unsigned binary would re-exec a signed copy, and that copy cannot verify TLS
# certificates, so network image tests would skip silently.
set -eu

if [ "$#" -lt 1 ]; then
	echo "usage: codesign-exec.sh <test-binary> [args...]" >&2
	exit 2
fi

bin=$1
shift

if [ "$(uname -s)" = "Darwin" ]; then
	root=$(cd "$(dirname "$0")/.." && pwd)
	codesign --force --sign - --entitlements "$root/entitlements.plist" "$bin" >/dev/null
fi

exec "$bin" "$@"
