#!/usr/bin/env python3
"""Set-element add+delete latency: libnftables (python3-nftables) vs `nft -j -f -` subprocess.
Run inside the router netns with the adaptive table loaded."""
import json, statistics, subprocess, time
import nftables

N = 300
def elem_cmd(op, mac):
    return {"nftables": [{op: {"element": {"family": "inet", "table": "pirewall_adaptive", "name": "block_mac",
            "elem": ([{"elem": {"val": mac, "timeout": 300}}] if op == "add" else [mac])}}}]}

macs = [f"02:bb:00:00:{i // 256:02x}:{i % 256:02x}" for i in range(N)]
nft = nftables.Nftables(); nft.set_json_output(True)
lib = []
for m in macs:
    for op in ("add", "delete"):
        t = time.perf_counter(); rc, out, err = nft.json_cmd(elem_cmd(op, m)); lib.append(time.perf_counter() - t)
        assert rc == 0, err
sub = []
for m in macs:
    for op in ("add", "delete"):
        t = time.perf_counter()
        subprocess.run(["nft", "-j", "-f", "-"], input=json.dumps(elem_cmd(op, m)), text=True, check=True, capture_output=True)
        sub.append(time.perf_counter() - t)
# one batch of N adds in a single transaction
t = time.perf_counter(); nft.json_cmd({"nftables": [c for m in macs for c in elem_cmd("add", m)["nftables"]]}); batch = time.perf_counter() - t
nft.cmd("flush set inet pirewall_adaptive block_mac")
f = lambda xs: {"median_ms": round(statistics.median(xs) * 1e3, 3), "p95_ms": round(sorted(xs)[int(len(xs) * .95)] * 1e3, 3)}
print(json.dumps({"ops": 2 * N, "libnftables": f(lib), "subprocess_nft_j": f(sub), f"batch_{N}_adds_ms": round(batch * 1e3, 2)}))
