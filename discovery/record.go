// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0

// Package discovery resolves an OpenWaymark node from a domain name: the
// "_openwaymark" DNS TXT record (OWM-5 §2.1) gives a base URL, and
// .well-known/openwaymark (OWM-7 §4.1) at that URL gives the node's current
// description. Neither step is itself cryptographically authenticated — trust
// rides on TLS to the resolved base URL, the same boundary a certificate
// transparency log's own HTTPS endpoint relies on (OWM-5 §2.2).
package discovery

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// RecordPrefix is the mandatory tag at the start of every OpenWaymark TXT
// record. It is what makes the record self-identifying: a resolver can tell
// an OpenWaymark record apart from an unrelated TXT record some other project
// happens to publish at the same name (OWM-5 §2.1).
const RecordPrefix = "v=owm1"

// ErrBadRecord reports a TXT string that is not a valid OpenWaymark record —
// missing or wrong version tag, missing node=, or a node= value that is not
// an absolute https:// URL. A foreign record sharing the name is ignored, not
// repaired: this error is exactly the signal for "not one of ours."
var ErrBadRecord = errors.New("owm/discovery: not a valid OpenWaymark TXT record")

// Record is one parsed "_openwaymark" TXT record.
type Record struct {
	// NodeURL is the node's base URL, taken from the record's node= field.
	NodeURL string
}

// ParseRecord parses one TXT record string.
//
// Fields after node= that this parser does not recognise are tolerated and
// ignored — the same forward-compatibility rule as unknown fields elsewhere
// in the protocol (OWM-5 §2.1).
func ParseRecord(txt string) (*Record, error) {
	fields := strings.Split(txt, ";")
	if strings.TrimSpace(fields[0]) != RecordPrefix {
		return nil, fmt.Errorf("%w: missing %q tag", ErrBadRecord, RecordPrefix)
	}

	var nodeURL string
	for _, f := range fields[1:] {
		v, ok := strings.CutPrefix(strings.TrimSpace(f), "node=")
		if !ok {
			continue
		}
		nodeURL = v
		break
	}
	if nodeURL == "" {
		return nil, fmt.Errorf("%w: no node= field", ErrBadRecord)
	}
	u, err := url.Parse(nodeURL)
	if err != nil || !u.IsAbs() || u.Scheme != "https" {
		return nil, fmt.Errorf("%w: node= is not an absolute https URL: %q", ErrBadRecord, nodeURL)
	}
	return &Record{NodeURL: nodeURL}, nil
}
