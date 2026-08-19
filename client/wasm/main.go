// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Command wasm is client/verify compiled to WebAssembly and exposed to
// JavaScript as one function, owmVerifySubject(nodeURL, subjectHex) — the
// browser's own fetch() stands in for the Fetcher client/verify already
// takes as a parameter, so this file adds no logic of its own beyond
// bridging fetch's promises to the blocking calls client/verify expects.
// Every actual decision — what counts as verified, what counts as a
// finding — is made in client/verify, testable without a browser at all.
//
// Build with GOOS=js GOARCH=wasm (see build.sh); requires Go's own
// wasm_exec.js, copied at build time rather than vendored by hand so it
// never drifts from the toolchain that produced the .wasm file next to it.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"

	"openwaymark.org/owm/client/verify"
	"openwaymark.org/owm/core"
	"openwaymark.org/owm/trust"
)

func main() {
	js.Global().Set("owmVerifySubject", js.FuncOf(verifySubject))
	// A WASM program under GOOS=js exits the moment main returns, tearing
	// down every registered callback with it — block forever instead.
	select {}
}

// verifySubject is the JS-facing entry point: owmVerifySubject(nodeURL,
// subjectHex). Returns a Promise resolving to the JSON encoding of
// verify.Result, or rejecting with a plain error string.
func verifySubject(_ js.Value, args []js.Value) any {
	if len(args) < 2 {
		return rejectedPromise("owmVerifySubject requires (nodeURL, subjectHex)")
	}
	nodeURL := args[0].String()
	subjectHex := args[1].String()

	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resolve, reject := args[0], args[1]
		go func() {
			result, err := runVerify(nodeURL, subjectHex)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()
		return nil
	})
	// The executor runs synchronously inside this constructor call, so it
	// is safe to release right after — the resolve/reject js.Values it
	// captured stay valid independently of it.
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}

func rejectedPromise(msg string) js.Value {
	executor := js.FuncOf(func(_ js.Value, args []js.Value) any {
		args[1].Invoke(msg)
		return nil
	})
	defer executor.Release()
	return js.Global().Get("Promise").New(executor)
}

// runVerify does the actual work: parse the subject, fetch and check its
// history against nodeURL through jsFetcher, marshal the result to JSON.
//
// Roots is empty here — this build has no way yet for a visitor to supply
// their own accreditation root set, so every entity trust level recomputes
// to LevelNone, an ordinary and honestly reported result (verify.Result's
// own contract), not silently hidden or faked as something more.
func runVerify(nodeURL, subjectHex string) (string, error) {
	digest, err := core.ParseDigest(subjectHex)
	if err != nil {
		return "", fmt.Errorf("invalid subject: %w", err)
	}
	subject := core.SubjectID(digest)

	res, err := verify.VerifySubject(context.Background(), jsFetcher{}, nodeURL, subject,
		verify.Options{Roots: trust.RootSet{}})
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(res)
	if err != nil {
		return "", fmt.Errorf("encode result: %w", err)
	}
	return string(out), nil
}
