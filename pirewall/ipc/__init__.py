"""pirewall-core <-> pirewall-api RPC protocol (ADDENDUM.md A4).

**This package deliberately re-exports nothing.** The two halves of the RPC
protocol belong to two different OS processes, and a re-export here would
load both into whichever process imports either: importing any submodule
first executes this `__init__`, so a single
`from pirewall.ipc.dispatcher import CoreRpcDispatcher` line here is enough
to pull `pirewall.firewall.manager` into the *pirewall-api* process, which
A4 exists to prevent. An audit caught exactly that — the AST-based
import-isolation test passed while `FirewallManager` was in fact resident
in the API process's memory.

Import from the specific submodule instead:

* `pirewall.ipc.protocol` — the shared wire types (both processes).
* `pirewall.ipc.client` — `BaseRpcClient`/`UnixSocketRpcClient`
  (pirewall-api side).
* `pirewall.ipc.dispatcher` — `CoreRpcDispatcher` (pirewall-core side).
* `pirewall.ipc.server` — `UnixSocketRpcServer` (pirewall-core side).
* `pirewall.ipc.state` — `CoreStateStore` (pirewall-core side).
* `pirewall.ipc.loopback` — `LoopbackRpcClient`, **test-only**; the real
  two-process deployment must never use it. See `docs/ARCHITECTURE.md`
  "Process split".

`tests/security/test_api_process_isolation.py` enforces the resulting
separation at runtime, not just by static analysis.
"""
