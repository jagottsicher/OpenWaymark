<!--
SPDX-FileCopyrightText: 2026 OpenWaymark contributors
SPDX-License-Identifier: Apache-2.0
-->

# `client/` — Web app and WASM verifier · Apache-2.0

**Planned (stage E6). No code yet.**

The verifier is compiled to WASM from the same Go code that also runs in the node — one code path,
two targets.

That is not a convenience feature but the condition for the whole chain of proofs being worth
anything: the client checks signatures and inclusion proofs **itself** instead of believing the
server. A client that believes the server makes the log pointless — in which case one could have
saved the trouble. See [OWM-9 A11](../spec/owm-9-threat-model.md).

On top of that: QR scanning via `BarcodeDetector` with a JS fallback, and a chain view that marks
the weakest link explicitly instead of hiding it.
