// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package testnode wraps node.Open and httptest.NewServer into one call, for
// tests elsewhere in the module that need a real *node.Node reachable over
// real HTTP — genuine wire-format round trips, not calls against the Go API
// directly. Shared between monitor/'s and node/'s own end-to-end tests so
// neither has to duplicate node/node_test.go's own testConfig/newTestNode
// pair.
//
// node.Open and node.DefaultConfig are already exported and sufficient for
// this; this package exists only to avoid repeating the wiring, not to
// expose anything new from node itself.
package testnode

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"openwaymark.org/owm/node"
)

// Node is a real node, opened in a throwaway directory, serving its public
// API over a real httptest.Server. Server and database are cleaned up
// automatically at the end of the test.
type Node struct {
	*node.Node
	Server *httptest.Server
}

// New opens a node and starts serving it. STHInterval is left at zero — the
// caller issues STHs explicitly via IssueSTH, on its own schedule, rather
// than racing a background ticker.
func New(t *testing.T) *Node {
	t.Helper()
	dir := t.TempDir()
	cfg := node.DefaultConfig()
	cfg.Database = filepath.Join(dir, "owm.sqlite")
	cfg.Identity = filepath.Join(dir, "identity.json")
	cfg.Listen = "127.0.0.1:0"
	cfg.AdminListen = "127.0.0.1:0"
	cfg.STHInterval = 0
	cfg.Operator = node.Operator{Name: "Test operator", Contact: "mailto:test@example.org"}

	n, err := node.Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("testnode: open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })

	srv := httptest.NewServer(n.PublicHandler())
	t.Cleanup(srv.Close)

	return &Node{Node: n, Server: srv}
}
