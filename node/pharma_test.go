// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: AGPL-3.0-only

package node

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"openwaymark.org/owm/core"
	"openwaymark.org/owm/profiles/pharma"
)

// signPharma builds a signed pharma.v1 entry, mirroring participant.sign
// (node_test.go) but against pharma.ID instead of food.ID.
func (p *participant) signPharma(t *testing.T, typ core.EntryType, subject core.SubjectID, payload string, parents ...core.EntryRef) (*core.SignedEntry, core.Salt, []byte) {
	t.Helper()
	salt, err := core.NewSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	body := []byte(payload)
	e := &core.Entry{
		Version:    1,
		Type:       typ,
		Profile:    pharma.ID,
		Subject:    subject,
		Issuer:     p.key.Public().ID(),
		Commitment: core.Commit(salt, body),
		Parents:    parents,
	}
	e.SetIssuedAt(time.Now())
	se, err := core.SignEntry(p.key, e)
	if err != nil {
		t.Fatalf("sign entry: %v", err)
	}
	return se, salt, body
}

// TestPharmaSupplyChainEndToEnd runs a full nine-event chain through the
// public HTTP API — API synthesis through dispensing — exercising every
// event pharma.v1 defines, including the two subject-granularity tiers
// (§6: lot-level API, instance-level finished product) and the
// entry-type binding that measurement alone requires sensor_reading.
func TestPharmaSupplyChainEndToEnd(t *testing.T) {
	n := newTestNode(t)
	a := newAPI(t, n)

	manufacturer := newParticipant(t, n, core.SigAlgMLDSA65, "Alpha Pharma Chemicals")
	qp := newParticipant(t, n, core.SigAlgMLDSA65, "Qualified Person")
	sensor := newParticipant(t, n, core.SigAlgMLDSA44, "cool-91")
	wholesaler := newParticipant(t, n, core.SigAlgMLDSA65, "PharmaWholesale Nord")
	pharmacy := newParticipant(t, n, core.SigAlgMLDSA65, "Apotheke am Markt")

	apiLot := newSubject(t)      // lot-level: the API batch.
	finishedLot := newSubject(t) // lot-level: the tableted batch, pre-serialization.
	pack := newSubject(t)        // instance-level: one serialized saleable unit.

	ref := func(r submitResponse) core.EntryRef {
		return core.EntryRef{Entry: r.EntryID, Log: r.Log}
	}

	// 1. Production: the API batch comes into being.
	se, salt, payload := manufacturer.signPharma(t, core.EntryTypeAssertion, apiLot, `{
		"event": "production",
		"time": "2026-06-01T08:00:00+02:00",
		"product": {"name": "Ibuprofen API", "lot": "API-2026-0601", "stage": "api"},
		"quantity": {"value": 500, "unit": "KGM"}
	}`)
	production := a.submit(se, salt, payload)

	// 2. Processing: API becomes finished dosage form, still lot-level.
	evProcessing := `{
		"event": "processing",
		"time": "2026-07-01T09:00:00+02:00",
		"process": "tableting",
		"inputs": [{"subject": "` + apiLot.String() + `", "product": {"stage": "api"}}],
		"outputs": [{"subject": "` + finishedLot.String() + `", "product": {"stage": "finished_product", "lot": "FIN-2026-0710"}}]
	}`
	se, salt, payload = manufacturer.signPharma(t, core.EntryTypeAssertion, finishedLot, evProcessing, ref(production))
	processing := a.submit(se, salt, payload)

	// 3. Release: the QP certifies the finished-product lot.
	se, salt, payload = qp.signPharma(t, core.EntryTypeAssertion, finishedLot, `{
		"event": "release",
		"time": "2026-07-09T16:00:00+02:00",
		"lot": "FIN-2026-0710",
		"certified": true,
		"standard": "eu-gmp-annex16"
	}`, ref(processing))
	release := a.submit(se, salt, payload)

	// 4. Aggregation: the tier change (§6) — one serialized pack drawn from the
	// lot, subject moves from lot-level to instance-level.
	evAggregation := `{
		"event": "aggregation",
		"time": "2026-07-10T09:00:00+02:00",
		"action": "add",
		"container": {"lot": "FIN-2026-0710"},
		"children": [{"subject": "` + pack.String() + `", "product": {"stage": "finished_product", "serial": "SN-0001"}}]
	}`
	se, salt, payload = manufacturer.signPharma(t, core.EntryTypeAssertion, finishedLot, evAggregation, ref(release))
	aggregation := a.submit(se, salt, payload)

	// 5. Transport departure, with a cold-chain promise.
	se, salt, payload = wholesaler.signPharma(t, core.EntryTypeAssertion, pack, `{
		"event": "transport",
		"time": "2026-07-11T07:00:00+02:00",
		"step": "departure",
		"conditions": {"temperature_c": {"min": 2, "max": 8}, "max_transit_hours": 24}
	}`, ref(aggregation))
	transport := a.submit(se, salt, payload)

	// 6. Measurement: the cold-chain evidence, signed by the device key and
	// submitted as sensor_reading — the one event the entry-type rule binds.
	se, salt, payload = sensor.signPharma(t, core.EntryTypeSensorReading, pack, `{
		"event": "measurement",
		"time": "2026-07-11T07:00:00+02:00",
		"sensor": {"id": "cool-91"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [{"t": "2026-07-11T07:00:00+02:00", "v": 4.1}]
	}`, ref(transport))
	measurement := a.submit(se, salt, payload)

	// 7. Storage: a stay at the distribution center, distinct from transport.
	se, salt, payload = wholesaler.signPharma(t, core.EntryTypeAssertion, pack, `{
		"event": "storage",
		"time": "2026-07-12T10:00:00+02:00",
		"action": "enter",
		"conditions": {"temperature_c": {"min": 2, "max": 8}}
	}`, ref(measurement))
	storage := a.submit(se, salt, payload)

	// 8. Handover: wholesaler to pharmacy.
	se, salt, payload = wholesaler.signPharma(t, core.EntryTypeAssertion, pack, `{
		"event": "handover",
		"time": "2026-07-15T14:00:00+02:00",
		"to": {"name": "Apotheke am Markt"},
		"transaction": {"type": "desadv", "id": "DE-2026-77410"}
	}`, ref(storage))
	handover := a.submit(se, salt, payload)

	// 9. Decommission: administered — no patient named anywhere.
	se, salt, payload = pharmacy.signPharma(t, core.EntryTypeAssertion, pack, `{
		"event": "decommission",
		"time": "2026-07-20T11:00:00+02:00",
		"reason": "administered"
	}`, ref(handover))
	decommission := a.submit(se, salt, payload)
	if decommission.Seq != 8 {
		t.Fatalf("after nine entries decommission sits at seq %d", decommission.Seq)
	}

	// The pack's history: aggregation onward, five entries at instance level.
	var history historyResponse
	a.mustGet("/owm/v1/subjects/"+pack.String(), &history)
	wantEvents := []string{"transport", "measurement", "storage", "handover", "decommission"}
	if history.Total != len(wantEvents) {
		t.Fatalf("pack history has %d entries, want %d", history.Total, len(wantEvents))
	}
	for i, wantEvent := range wantEvents {
		var pr payloadResponse
		a.mustGet("/owm/v1/entries/"+history.Entries[i].EntryID.String()+"/payload", &pr)
		var got struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal(pr.Payload, &got); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if got.Event != wantEvent {
			t.Fatalf("pack history[%d] = %q, want %q", i, got.Event, wantEvent)
		}
	}

	// The finished-product lot's own history: processing, release, aggregation —
	// the lot-level side of the tier change, kept apart from the pack's.
	var lotHistory historyResponse
	a.mustGet("/owm/v1/subjects/"+finishedLot.String(), &lotHistory)
	if lotHistory.Total != 3 {
		t.Fatalf("lot history has %d entries, want 3 (processing, release, aggregation)", lotHistory.Total)
	}
}

// TestPharmaMeasurementRequiresSensorReading confirms the one entry-type
// binding this profile enforces (pharma.v1 §4) is actually wired into
// Submit, not only into profiles.Profile.Check in isolation.
func TestPharmaMeasurementRequiresSensorReading(t *testing.T) {
	ctx := context.Background()
	n := newTestNode(t)
	manufacturer := newParticipant(t, n, core.SigAlgMLDSA65, "Alpha Pharma Chemicals")
	subject := newSubject(t)

	se, salt, payload := manufacturer.signPharma(t, core.EntryTypeAssertion, subject, `{
		"event": "measurement",
		"time": "2026-07-11T07:00:00+02:00",
		"sensor": {"id": "cool-91"},
		"quantity_kind": "temperature",
		"unit": "CEL",
		"readings": [{"t": "2026-07-11T07:00:00+02:00", "v": 4.1}]
	}`)
	if _, err := n.Submit(ctx, se, salt, payload); err == nil {
		t.Fatal("a hand-written measurement, submitted as assertion, was accepted")
	}
}
