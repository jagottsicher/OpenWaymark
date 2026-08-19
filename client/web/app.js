// SPDX-FileCopyrightText: 2026 OpenWaymark contributors
// SPDX-License-Identifier: Apache-2.0
//
// No framework, no build step, no bundler — the same "go run ./demo and
// nothing else" ethos the rest of this project holds itself to. Every
// verification decision was already made in Go (client/verify, compiled to
// verifier.wasm); this file only drives the form and renders what
// owmVerifySubject() returns. It does not re-check anything itself — the
// page rendering something as "ok" without the WASM call actually having
// run it would be exactly the kind of "trust the presentation" failure
// OWM-9 A11 is about.

const ENTRY_TYPE_NAMES = {
  1: "assertion",
  2: "attestation",
  3: "revocation",
  4: "key_rotation",
  5: "sensor_reading",
  6: "erasure",
};

const $ = (id) => document.getElementById(id);
const form = $("form");
const nodeInput = $("node");
const subjectInput = $("subject");
const verifyBtn = $("verify-btn");
const statusLine = $("status");
const results = $("results");
const sthSummary = $("sth-summary");
const findingsBox = $("findings");
const entriesBox = $("entries");
const trustCard = $("trust-card");
const trustTable = $("trust-table");

function abbrev(hex) {
  if (!hex || hex.length <= 16) return hex || "";
  return hex.slice(0, 8) + "…" + hex.slice(-6);
}

function prefillFromFragment() {
  const params = new URLSearchParams(location.hash.replace(/^#/, ""));
  const node = params.get("node");
  const subject = params.get("subject");
  if (node) nodeInput.value = node;
  if (subject) subjectInput.value = subject;
  return Boolean(node && subject);
}

function badgeClass(status) {
  if (status === "ok") return "badge-ok";
  if (status === "erased") return "badge-erased";
  return "badge-failed";
}

function renderResult(res) {
  results.classList.remove("hidden");

  // STH summary
  sthSummary.innerHTML = "";
  if (res.sth) {
    const rows = [
      ["log", abbrev(res.log)],
      ["tree size", String(res.sth.size)],
      ["root", abbrev(res.sth.root)],
      ["issued", new Date(res.sth.ts).toISOString()],
    ];
    for (const [k, v] of rows) {
      const d = document.createElement("div");
      d.innerHTML = `<dt>${k}</dt><dd>${v}</dd>`;
      sthSummary.appendChild(d);
    }
  } else {
    sthSummary.textContent = "The node's signed tree head did not verify — see findings below.";
  }

  // Findings
  findingsBox.innerHTML = "";
  if (res.findings && res.findings.length > 0) {
    findingsBox.classList.remove("hidden");
    const h = document.createElement("h2");
    h.textContent = `${res.findings.length} finding${res.findings.length === 1 ? "" : "s"} — read before trusting anything below`;
    const ul = document.createElement("ul");
    for (const f of res.findings) {
      const li = document.createElement("li");
      li.textContent = f;
      ul.appendChild(li);
    }
    findingsBox.appendChild(h);
    findingsBox.appendChild(ul);
  } else {
    findingsBox.classList.add("hidden");
  }

  // Entries
  entriesBox.innerHTML = "";
  const entries = res.entries || [];
  if (entries.length === 0) {
    const p = document.createElement("p");
    p.className = "status-line";
    p.textContent = "This subject has no history on this node.";
    entriesBox.appendChild(p);
  }
  for (const e of entries) {
    const card = document.createElement("div");
    card.className = "entry";
    const typeName = ENTRY_TYPE_NAMES[e.type] || `type ${e.type}`;
    const profile = e.profile ? ` · ${e.profile}` : "";
    card.innerHTML = `
      <div class="entry-head">
        <span class="entry-title">${typeName}${profile}</span>
        <span class="badge ${badgeClass(e.status)}">${e.status}</span>
      </div>
      <div class="entry-meta">
        seq ${e.seq} · entry ${abbrev(e.entry_id)} · issuer ${abbrev(e.issuer)} ·
        ${new Date(e.issued_at).toISOString()}
      </div>`;
    if (e.status === "failed" && e.reason) {
      const r = document.createElement("div");
      r.className = "entry-reason";
      r.textContent = e.reason;
      card.appendChild(r);
    }
    if (e.payload) {
      const pre = document.createElement("div");
      pre.className = "entry-payload";
      pre.textContent = decodePayload(e.payload);
      card.appendChild(pre);
    }
    entriesBox.appendChild(card);
  }

  // Trust levels
  trustTable.innerHTML = "";
  const levels = res.trust_level || {};
  const serverLevels = res.server_trust_level || {};
  const issuers = Object.keys(levels);
  if (issuers.length > 0) {
    trustCard.classList.remove("hidden");
    const head = document.createElement("tr");
    head.innerHTML = "<th>issuer</th><th>recomputed</th><th>node claims</th>";
    trustTable.appendChild(head);
    for (const id of issuers) {
      const mine = levels[id];
      const theirs = serverLevels[id];
      const mismatch = theirs !== undefined && theirs !== mine;
      const row = document.createElement("tr");
      row.innerHTML = `
        <td>${abbrev(id)}</td>
        <td>${mine}</td>
        <td class="${mismatch ? "mismatch" : ""}">${theirs === undefined ? "—" : theirs}${mismatch ? " ⚠" : ""}</td>`;
      trustTable.appendChild(row);
    }
  } else {
    trustCard.classList.add("hidden");
  }
}

// decodePayload renders a payload for display: JSON pretty-printed where
// possible, otherwise the raw bytes are shown as base64 rather than
// silently dropped — an unrecognised payload shape is not a reason to hide
// it.
function decodePayload(base64) {
  try {
    const bytes = Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch (e) {
    return `(${base64.length} bytes, base64) ${base64.slice(0, 120)}${base64.length > 120 ? "…" : ""}`;
  }
}

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const node = nodeInput.value.trim().replace(/\/$/, "");
  const subject = subjectInput.value.trim().toLowerCase();
  if (!node || !/^[0-9a-f]{64}$/.test(subject)) {
    statusLine.textContent = "Enter a node base URL and a 64-character hex subject ID.";
    return;
  }
  verifyBtn.disabled = true;
  statusLine.textContent = "Fetching and verifying…";
  results.classList.add("hidden");
  try {
    const json = await window.owmVerifySubject(node, subject);
    const res = JSON.parse(json);
    renderResult(res);
    statusLine.textContent = `Done — ${res.entries ? res.entries.length : 0} entr${(res.entries || []).length === 1 ? "y" : "ies"} checked.`;
  } catch (err) {
    statusLine.textContent = `Failed: ${err}`;
  } finally {
    verifyBtn.disabled = false;
  }
});

// Boot: load the WASM module, then enable the form. A page opened straight
// from disk (file://) cannot fetch cross-origin — that is a browser
// restriction on this page's own assets, unrelated to what it then verifies
// once running, which happens entirely over ordinary fetch() to the node.
const go = new Go();
WebAssembly.instantiateStreaming(fetch("verifier.wasm"), go.importObject)
  .then((result) => {
    go.run(result.instance);
    verifyBtn.disabled = false;
    verifyBtn.textContent = "Verify";
    const prefilled = prefillFromFragment();
    statusLine.textContent = prefilled
      ? "Ready — values filled in from the link. Press Verify."
      : "Ready.";
  })
  .catch((err) => {
    statusLine.textContent = `Could not load verifier.wasm: ${err}. Run client/wasm/build.sh first.`;
  });
