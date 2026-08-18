// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
)

// ErrNoRecord reports a domain with no OpenWaymark TXT record.
var ErrNoRecord = errors.New("owm/discovery: no OpenWaymark TXT record found")

// ErrAmbiguousRecord reports more than one OpenWaymark TXT record at the same
// name — a misconfiguration (OWM-5 §2.1). Silently picking one would let
// whoever can add a second TXT record at that name redirect discovery
// without the legitimate operator noticing.
var ErrAmbiguousRecord = errors.New("owm/discovery: more than one OpenWaymark TXT record found")

// lookupTXT resolves TXT records for a DNS name. A package variable, not a
// direct call, so tests can substitute a fake resolver without touching real
// DNS.
var lookupTXT = net.DefaultResolver.LookupTXT

// Lookup resolves the "_openwaymark.<domain>" TXT record (OWM-5 §2.1).
//
// A TXT string at the name that does not parse as an OpenWaymark record is
// ignored, not treated as an error — the label may carry an unrelated
// project's record too, and ParseRecord's version tag is exactly what tells
// the two apart.
func Lookup(ctx context.Context, domain string) (*Record, error) {
	name := "_openwaymark." + domain
	txts, err := lookupTXT(ctx, name)
	if err != nil {
		// A name that does not exist at all (NXDOMAIN, or the equivalent the
		// resolver in use reports) means the same thing as zero TXT records
		// found at a name that does exist: this domain runs no OpenWaymark
		// node. Any other failure (timeout, SERVFAIL, ...) is a real
		// operational error and stays one.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, fmt.Errorf("%w: %s", ErrNoRecord, name)
		}
		return nil, fmt.Errorf("owm/discovery: lookup %s: %w", name, err)
	}

	var found *Record
	for _, txt := range txts {
		rec, err := ParseRecord(txt)
		if err != nil {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: %s", ErrAmbiguousRecord, name)
		}
		found = rec
	}
	if found == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoRecord, name)
	}
	return found, nil
}
