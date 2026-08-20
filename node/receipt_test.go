// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"testing"

	"openwaymark.org/owm/core"
	owmlog "openwaymark.org/owm/log"
)

// TestSubmitIncludesReceipt confirms a receipt is issued by default (OWM-9
// A3): its own signature verifies against the node's own key, and it names
// exactly the entry that was just submitted.
func TestSubmitIncludesReceipt(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)
	farmer := newParticipant(t, n, core.SigAlgMLDSA65, "farmer")
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt, payload := farmer.sign(t, core.EntryTypeAssertion, subject, evProduction)

	res := a.submit(se, salt, payload)
	if len(res.Receipt) == 0 {
		t.Fatal("no receipt in the response, despite MaxMergeDelay defaulting on")
	}
	signed, err := owmlog.ParseSignedReceipt(res.Receipt)
	if err != nil {
		t.Fatalf("parse receipt: %v", err)
	}
	if err := signed.Verify(n.Identity().Key.Public()); err != nil {
		t.Fatalf("verify: %v", err)
	}
	r, err := signed.Receipt()
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	if r.EntryID != res.EntryID {
		t.Errorf("receipt names entry %s, submission response names %s", r.EntryID, res.EntryID)
	}
	if r.Seq != res.Seq {
		t.Errorf("receipt seq = %d, want %d", r.Seq, res.Seq)
	}
	if r.Deadline <= r.IssuedAt {
		t.Errorf("deadline %d is not after issuance %d", r.Deadline, r.IssuedAt)
	}
}

// TestSubmitOmitsReceiptWhenDisabled confirms MaxMergeDelay = 0 is a real
// opt-out, not merely an unusually short deadline.
func TestSubmitOmitsReceiptWhenDisabled(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxMergeDelay = 0
	n, err := Open(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open node: %v", err)
	}
	t.Cleanup(func() { n.Close() })
	a := newAPI(t, n)
	farmer := newParticipant(t, n, core.SigAlgMLDSA65, "farmer")
	subject, err := core.NewSubjectID()
	if err != nil {
		t.Fatalf("subject: %v", err)
	}
	se, salt, payload := farmer.sign(t, core.EntryTypeAssertion, subject, evProduction)

	res := a.submit(se, salt, payload)
	if len(res.Receipt) != 0 {
		t.Error("receipt present despite MaxMergeDelay = 0")
	}
}

func TestConfigRejectsNegativeMaxMergeDelay(t *testing.T) {
	cfg := testConfig(t)
	cfg.MaxMergeDelay = -1
	if err := cfg.Check(); err == nil {
		t.Fatal("negative max_merge_delay was accepted")
	}
}
