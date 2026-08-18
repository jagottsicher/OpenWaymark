// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

// Package monitor is the independent log monitor (OWM-5 §4, stage E4).
//
// It collects STHs from configured targets, checks them for self-
// contradiction using package gossip, and persists any finding as evidence.
// Deliberately small and self-contained, so that someone other than the
// observed node can run it — that is the whole point (see the package
// README). The split-view test is the most important test in this project;
// see monitor_test.go's TestSplitViewEndToEnd.
package monitor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"openwaymark.org/owm/discovery"
	"openwaymark.org/owm/gossip"
)

// resolveDomain is discovery.Resolve behind a package variable so tests can
// substitute a fake resolution (a real node's httptest URL, no real DNS)
// without touching the discovery package itself.
var resolveDomain = discovery.Resolve

// Monitor watches a set of targets' logs and raises an alarm on a split view
// or similar contradiction.
type Monitor struct {
	cfg Config

	// Out and Err receive the monitor's plain-text alarm and warning lines.
	// nil defaults to os.Stdout / os.Stderr.
	Out, Err io.Writer
	// HTTP is used for all outgoing requests, discovery and gossip alike.
	// nil uses http.DefaultClient.
	HTTP *http.Client
}

// New checks cfg and returns a Monitor. The findings directory is created
// immediately so a misconfigured path is caught at startup, not on the first
// finding.
func New(cfg Config) (*Monitor, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.FindingsDir, 0o700); err != nil {
		return nil, fmt.Errorf("owm/monitor: findings directory: %w", err)
	}
	return &Monitor{cfg: cfg}, nil
}

func (m *Monitor) out() io.Writer {
	if m.Out != nil {
		return m.Out
	}
	return os.Stdout
}

func (m *Monitor) errOut() io.Writer {
	if m.Err != nil {
		return m.Err
	}
	return os.Stderr
}

// Run starts one watch loop per target and blocks until ctx ends.
func (m *Monitor) Run(ctx context.Context) error {
	if len(m.cfg.Targets) == 0 {
		<-ctx.Done()
		return ctx.Err()
	}
	var wg sync.WaitGroup
	for _, target := range m.cfg.Targets {
		wg.Add(1)
		go func(target Target) {
			defer wg.Done()
			m.runTarget(ctx, target)
		}(target)
	}
	wg.Wait()
	return ctx.Err()
}

// runTarget watches one target for as long as ctx runs. A BaseURL target is
// watched directly. A Domain target is resolved, watched for at most
// RediscoverInterval, then re-resolved — so a partner's base URL can change
// without an operator editing the config (OWM-5 §2.3).
func (m *Monitor) runTarget(ctx context.Context, target Target) {
	if target.BaseURL != "" {
		m.watch(ctx, target, target.BaseURL)
		return
	}
	for ctx.Err() == nil {
		info, err := resolveDomain(ctx, target.Domain, m.HTTP)
		if err != nil {
			fmt.Fprintf(m.errOut(), "owm/monitor: %s: resolve %s: %v\n", target.Name, target.Domain, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(m.cfg.RediscoverInterval.Duration()):
				continue
			}
		}
		roundCtx, cancel := context.WithTimeout(ctx, m.cfg.RediscoverInterval.Duration())
		m.watch(roundCtx, target, info.BaseURL)
		cancel()
	}
}

// watch polls one resolved base URL until ctx ends.
func (m *Monitor) watch(ctx context.Context, target Target, baseURL string) {
	c := gossip.NewClient(baseURL)
	c.HTTP = m.HTTP
	err := gossip.Watch(ctx, c, m.cfg.PollInterval.Duration(), func(ev gossip.Event, err error) {
		if err != nil {
			fmt.Fprintf(m.errOut(), "owm/monitor: %s: %v\n", target.Name, err)
			return
		}
		if ev.Finding == nil {
			return
		}
		path, werr := WriteFinding(m.cfg.FindingsDir, target.Name, *ev.Finding)
		if werr != nil {
			// The finding itself is still reported below — losing the
			// alarm because the disk write failed would be worse than a
			// noisy log line about it.
			fmt.Fprintf(m.errOut(), "owm/monitor: %s: write finding: %v\n", target.Name, werr)
		}
		fmt.Fprintf(m.out(), "owm/monitor: ALARM target=%s log=%s kind=%s size=%d at=%s evidence=%s\n",
			target.Name, ev.Finding.Log, ev.Finding.Kind, ev.STH.Size, time.Now().UTC().Format(time.RFC3339), path)
	})
	// A context ending — shutdown, or the end of one discovery round for a
	// Domain target — is not itself something to report as a failure.
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		fmt.Fprintf(m.errOut(), "owm/monitor: %s: %v\n", target.Name, err)
	}
}
