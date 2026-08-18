// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"errors"
	"log"
	"time"

	"openwaymark.org/owm/discovery"
	"openwaymark.org/owm/gossip"
)

// RunGossip polls each configured partner's STH at GossipInterval until ctx
// ends — the node's own half of targeted partner gossip (OWM-5 §3.2).
//
// A partner's self-contradiction is logged, not persisted as evidence: unlike
// an independent monitor (monitor/), this node is a self-interested party
// noticing its own partner double-crossing it, which is already useful even
// if the only reaction is to pick up the phone (OWM-9 A1). A single
// partner's poll failures never bring gossip with the others down, and never
// make RunGossip itself return early — see watchPartner.
//
// Zero interval or no configured partners: RunGossip still just blocks on
// ctx.Done(), the same convention RunSTH uses for a disabled STH interval.
func (n *Node) RunGossip(ctx context.Context) error {
	if interval := n.cfg.GossipInterval.Duration(); interval > 0 {
		for _, p := range n.cfg.Partners {
			go n.watchPartner(ctx, p, interval)
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

// watchPartner resolves (once) and watches one partner until ctx ends.
func (n *Node) watchPartner(ctx context.Context, p Partner, interval time.Duration) {
	baseURL := p.BaseURL
	if baseURL == "" {
		info, err := discovery.Resolve(ctx, p.Domain, nil)
		if err != nil {
			log.Printf("owm/node: partner %s: resolve %s: %v", p.Name, p.Domain, err)
			return
		}
		baseURL = info.BaseURL
	}

	c := gossip.NewClient(baseURL)
	err := gossip.Watch(ctx, c, interval, func(ev gossip.Event, err error) {
		if err != nil {
			log.Printf("owm/node: partner %s: %v", p.Name, err)
			return
		}
		if ev.Finding == nil {
			return
		}
		log.Printf("owm/node: ALARM partner=%s log=%s kind=%s size=%d",
			p.Name, ev.Finding.Log, ev.Finding.Kind, ev.STH.Size)
	})
	if err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("owm/node: partner %s: %v", p.Name, err)
	}
}
