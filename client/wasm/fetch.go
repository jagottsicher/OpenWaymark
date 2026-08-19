// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"syscall/js"

	"openwaymark.org/owm/client/verify"
)

// jsFetcher implements verify.Fetcher over the browser's own fetch() —
// deliberately the browser's network stack and TLS validation, not a
// reimplementation of either. Blocking on a channel inside a goroutine is
// the standard Go/WASM bridge from a JS Promise back into ordinary Go
// control flow: the scheduler yields to the JS event loop while the
// goroutine waits, which is what lets the promise's own callback run at
// all.
type jsFetcher struct{}

// fetchResult carries only the response body across the channel — status
// and ok are read directly from the closed-over variables below, since only
// the body (and whether reading it succeeded) ever differs between the two
// callbacks that can send on the channel.
type fetchResult struct {
	body []byte
	err  error
}

func (jsFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	ch := make(chan fetchResult, 1)

	bodyThen := js.FuncOf(func(_ js.Value, args []js.Value) any {
		buf := args[0]
		data := make([]byte, buf.Get("byteLength").Int())
		js.CopyBytesToGo(data, js.Global().Get("Uint8Array").New(buf))
		ch <- fetchResult{body: data}
		return nil
	})
	defer bodyThen.Release()
	bodyCatch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		ch <- fetchResult{err: fmt.Errorf("read response body: %s", jsErrString(args))}
		return nil
	})
	defer bodyCatch.Release()

	status, ok := 0, false
	respThen := js.FuncOf(func(_ js.Value, args []js.Value) any {
		resp := args[0]
		status, ok = resp.Get("status").Int(), resp.Get("ok").Bool()
		resp.Call("arrayBuffer").Call("then", bodyThen).Call("catch", bodyCatch)
		return nil
	})
	defer respThen.Release()
	respCatch := js.FuncOf(func(_ js.Value, args []js.Value) any {
		ch <- fetchResult{err: fmt.Errorf("fetch %s: %s", url, jsErrString(args))}
		return nil
	})
	defer respCatch.Release()

	js.Global().Call("fetch", url).Call("then", respThen).Call("catch", respCatch)

	select {
	case r := <-ch:
		if r.err != nil {
			return nil, r.err
		}
		if !ok {
			ae := &verify.APIError{StatusCode: status}
			var eb struct {
				Error  string `json:"error"`
				Detail string `json:"detail"`
			}
			if json.Unmarshal(r.body, &eb) == nil {
				ae.Code, ae.Detail = eb.Error, eb.Detail
			}
			return nil, ae
		}
		return r.body, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// jsErrString reads a JS error/rejection value defensively — fetch rejects
// with an Error object (.message), but not every rejection in the wild is
// guaranteed to be one.
func jsErrString(args []js.Value) string {
	if len(args) == 0 {
		return "unknown error"
	}
	v := args[0]
	if msg := v.Get("message"); msg.Type() == js.TypeString {
		return msg.String()
	}
	return v.String()
}
