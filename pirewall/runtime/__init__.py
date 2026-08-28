"""pirewall-core's process runtime: the wiring that turns the subsystems into a daemon.

Everything in this package is **pirewall-core side only** (ADDENDUM.md A4).
It imports `pirewall.capture` and `pirewall.firewall.manager`, so nothing
under `pirewall/api/` or `pirewall/web/` may import it — that would put
packet capture and the firewall backend inside the pirewall-api process,
which is exactly what the process split exists to prevent.

Like `pirewall.ipc`, this `__init__` deliberately re-exports nothing, so a
stray `from pirewall.runtime import X` in the API process cannot silently
pull the whole daemon in. Import the specific submodule:

* `pirewall.runtime.core` — `CoreDaemon`, the process's lifecycle owner.
* `pirewall.runtime.pipeline` — `FlowPipeline`, one completed flow's journey
  from features to an enforced rule.
* `pirewall.runtime.forwarder` — `EventForwarder`, the single sink every
  `SecurityEvent` in the process passes through.
* `pirewall.runtime.metrics` — `MetricsCollector`, builds a
  `NetdataMetricsSnapshot` from live state.
* `pirewall.runtime.watchdog` — `SystemdNotifier`, `sd_notify` support.
"""
