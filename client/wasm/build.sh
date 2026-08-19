#!/bin/sh
# SPDX-FileCopyrightText: 2026 OpenWaymark contributors
# SPDX-License-Identifier: Apache-2.0
#
# Builds the WASM verifier and drops it, together with the matching
# wasm_exec.js, straight into client/web/ — open client/web/index.html
# afterwards, no server, no bundler, no npm install.
#
# client/wasm has its own go.mod (a local replace pointing at the module
# root) specifically so this package — GOOS=js/GOARCH=wasm only, since it
# imports syscall/js — never breaks a plain `go build ./...` from the repo
# root. That is also why this script cds into client/wasm rather than using
# `go build ./client/wasm` from outside it.

set -eu

cd "$(dirname "$0")"
out="../web"

echo "building client/wasm ..."
GOOS=js GOARCH=wasm go build -o "$out/verifier.wasm" .

wasm_exec="$(go env GOROOT)/lib/wasm/wasm_exec.js"
if [ ! -f "$wasm_exec" ]; then
	echo "wasm_exec.js not found at $wasm_exec — Go version too old? (need Go 1.24+)" >&2
	exit 1
fi
# -f, and a fresh copy rather than an in-place overwrite: the Go module
# cache ships wasm_exec.js read-only, and a plain cp over an existing
# destination inherits that instead of using the umask-derived mode a
# normal file creation would get.
rm -f "$out/wasm_exec.js"
cp "$wasm_exec" "$out/wasm_exec.js"
chmod u+w "$out/wasm_exec.js"

ls -la "$out/verifier.wasm" "$out/wasm_exec.js"
echo "done — open $out/index.html in a browser"
