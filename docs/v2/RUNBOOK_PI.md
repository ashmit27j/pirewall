# RUNBOOK_PI — the human's steps on the Raspberry Pi (v2)

Written 2026-10-29, after phase 17. Phases 13–17 have **never run on the Pi**:
every step below is the first real-hardware check of something that so far
has only run in a sandbox (`env=sandbox`) or on mock data (`env=mock`).

**How to use this file.** Stages are in order. Each says what it needs
(**now**, or **after phase 18/19**). Run the commands as written, paste the
output somewhere you keep (or into a Claude session started with
`docs/v2/prompts/pi-session.md`), and record results in `docs/PROGRESS.md`
with their `pi-*` env tag. If a step fails, stop: don't improvise a fix to
the network on the Pi. `--panic` and the restore line it prints are your undo.

The H-numbers come from PLAN_FINAL §7 (hours from the start of the
evaluation window). Phase prompts refer to them: H1–H3 and H10 (phase 16),
H20 (phase 17), H24–H41 (phases 18–20).

**Assumed layout** (from PLAN_v3): the Pi is the AP on `wlan0` (LAN), uplink
on `wlan1` (TL-WN725N), Admin PC wired on `eth0`, repo at `/opt/pirewall`.
Set these once per shell and adjust if yours differ:

```sh
cd /opt/pirewall
LAN=wlan0
PI_LAN_IP=$(uv run python -c "from pirewall.config.loader import load_config; print(load_config('config/local_config.toml').network.pirewall_lan_ip)")
echo "$LAN $PI_LAN_IP"
```

**Before anything: keep a second SSH session open from the Admin PC** for
the whole of H10 and H22. If a guard locks the first one out, the second is
already established and conntrack keeps it alive.

---

## H0 — update the code, start the benign capture, remove demo accounts (now)

1. Update the checkout (v2 is merged into `main`):

   ```sh
   cd /opt/pirewall
   git status                         # must be clean; local_config.toml is gitignored
   git fetch origin && git checkout main && git pull --ff-only
   git log --oneline -1               # record this SHA
   ```

2. Install the Python deps and the native engine. The native engine needs a
   Rust toolchain; install it only if `cargo` is missing:

   ```sh
   command -v cargo || { curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal; . "$HOME/.cargo/env"; }
   uv sync --no-dev --extra native
   uv run python -c "import pirewall_native as n; print('native ok, ring:', n.HAS_PACKET_RING)"
   ```

3. Version checks (paste the output into PROGRESS, tagged `pi-live`):

   ```sh
   nft --version; uname -r; head -3 /etc/os-release
   uv run python --version; uv --version; tcpdump --version 2>&1 | head -1
   chronyc tracking | grep -E 'System time|Leap status'
   ```

4. **Remove the demo portal accounts** (KNOWN_ISSUES #4; high severity while they exist):

   ```sh
   sudo -u pirewall-core uv run python -m scripts.deployment.portal_users remove-demo
   sudo -u pirewall-core uv run python -m scripts.deployment.portal_users list
   ```

5. **Start the benign capture** (pi-live data for D1 thresholds, the G5
   check and phase 19 training). Tell the household first: this records
   packet headers (first 128 bytes) of every device on the LAN. pcaps never
   leave the Pi except to your own dev machine, and are never committed.

   ```sh
   sudo apt install -y tcpdump
   df -h /var/lib                                    # note free space
   sudo bash lab/capture/benign_capture.sh start     # consent banner: type yes
   sudo bash lab/capture/benign_capture.sh status
   ```

   It writes hourly `benign-%Y%m%d%H.pcap` files (`-s 128`) on
   `network.lan_interface` into a new session directory
   `/var/lib/pirewall-lab/benign/<UTC stamp>/`, and its disk watchdog stops
   it at 85% full and logs why. `sudo bash lab/capture/benign_capture.sh stop`
   ends it and seals the session (`manifest.json`, env tag `pi-live`, with the
   lab-MAC list of step 6). To keep it running unattended, as a transient unit
   (it stops on reboot; rerun it after one, then seal the old session with
   `sudo bash lab/capture/benign_capture.sh seal <session dir>`):

   ```sh
   sudo systemd-run --unit=pirewall-benign-capture \
     bash "$PWD/lab/capture/benign_capture.sh" start --foreground --i-have-consent
   ```

6. **Write down every lab device's MAC** (Kali, test laptops) with the time
   it joined, in `/var/lib/pirewall-lab/lab_macs.txt`. Their traffic is
   excluded from benign data later:

   ```sh
   ip neigh show dev "$LAN"
   echo "<mac> kali joined $(date -Is)" | sudo tee -a /var/lib/pirewall-lab/lab_macs.txt
   ```

## H1–H3 — hardware facts v2 depends on (now)

7. **Do the templates parse on this Pi's nft?** (tested on nft 1.0.2 and
   1.0.9 in the sandbox only; Raspberry Pi OS Bookworm ships 1.0.6):

   ```sh
   uv run python -m scripts.deployment.migrate_config --check   # if it says "needs migration": --write
   uv run python -m scripts.deployment.render_templates --config config/local_config.toml
   for f in deploy/rendered/*.nft; do echo "== $f"; sudo nft -c -f "$f" && echo OK; done
   ```

   Any failure here blocks H10. Keep the exact error.

8. **Does nft see the station's MAC as `ether saddr` on `wlan0`?** (brcmfmac;
   the whole MAC identity layer depends on it). Uses a throwaway table that
   only counts, never drops:

   ```sh
   PHONE_MAC=<a LAN client's MAC from ip neigh>
   sudo nft add table inet pwtest
   sudo nft add chain inet pwtest pre '{ type filter hook prerouting priority -500; policy accept; }'
   sudo nft add rule inet pwtest pre iifname "$LAN" ether saddr "$PHONE_MAC" counter
   # browse on that phone for ~10 s, then:
   sudo nft list chain inet pwtest pre        # counter packets must be > 0
   sudo nft delete table inet pwtest
   ```

9. **Client↔client visibility** (expected: none; it confirms the scope
   limit). With two LAN clients A and B pinging each other:

   ```sh
   sudo timeout 20 tcpdump -ni "$LAN" -c 20 "host <A-ip> and host <B-ip>"   # expect 0 packets
   ```

10. **Native capture benchmark** (phase 15; Table VII and Fig. 1 input):

    ```sh
    sudo apt install -y tcpreplay
    sudo ENV_TAG=pi-scripted ./benchmarks/v2-native-pi/run.sh
    ls benchmarks/v2-native-pi/results-*-pi-scripted.jsonl
    ```

11. **PMF timebox (30 min max).** Clients briefly drop off Wi-Fi; the Admin
    PC on `eth0` is unaffected:

    ```sh
    nmcli -t -f NAME,TYPE,DEVICE connection show --active      # find the AP connection on $LAN
    AP=<that name>
    sudo nmcli connection modify "$AP" 802-11-wireless-security.pmf required && sudo nmcli connection up "$AP"
    # if any household device can't reconnect within the timebox:
    sudo nmcli connection modify "$AP" 802-11-wireless-security.pmf optional && sudo nmcli connection up "$AP"
    ```

## H10 — deploy v2.0 (now; the v1 pipeline drives the v2 data plane)

12. One-time prerequisites (SETUP.md "v2 bring-up"):

    ```sh
    sudo apt install -y python3-nftables
    sudo scripts/deployment/install_nftables_pth.sh
    scripts/deployment/install_nftables_pth.sh --check
    uv run python -m scripts.deployment.configure --set-admin-pc   # confirm the MAC on the Admin PC itself (ip link / ipconfig /all)
    grep -q 'flush ruleset' /etc/nftables.conf && sudo systemctl disable --now nftables.service
    echo "net.ipv6.conf.$LAN.disable_ipv6 = 1" | sudo tee /etc/sysctl.d/60-pirewall-ipv6.conf && sudo sysctl --system
    sudo cp deploy/systemd/pirewall-core.service deploy/systemd/pirewall-api.service \
            deploy/systemd/pirewall-portal.service deploy/systemd/pirewall-crashloop-alert.service /etc/systemd/system/
    sudo cp deploy/systemd/pirewall-tmpfiles.conf /etc/tmpfiles.d/pirewall.conf
    sudo systemd-tmpfiles --create && sudo systemctl daemon-reload
    ```

13. Preflight, then bring-up:

    ```sh
    sudo scripts/deployment/pirewall-start --check --data-mode live        # exit 2 = a refusal, each prints its fix
    sudo scripts/deployment/pirewall-start --data-mode live --manifest ~/manifest-v2.0.json
    ```

14. Verify (each line is a PROGRESS entry, `pi-live`):

    ```sh
    sudo nft list tables                                    # pirewall_base, pirewall_static, pirewall_static_arp, pirewall_adaptive (+ pirewall_portal)
    sudo nft list set inet pirewall_static macbind | head   # bindings seeded from the lease file
    sudo nft list chain inet pirewall_static guard_verdict_raw    # contains drop => raw enforces
    cat /var/lib/pirewall/manifest.json | head -40
    systemctl status pirewall-core pirewall-api --no-pager | grep -E 'Active|Main PID'
    ```

    From the Admin PC: SSH still works (new session), and
    `https://<PI_LAN_IP>:8443` shows the Guards, Offenders and Bindings panels.
    A LAN phone still browses.

15. **Panic and restore**, once, on purpose:

    ```sh
    sudo scripts/deployment/pirewall-start --panic          # prints the restore command
    sudo nft list tables                                    # the v2 tables are gone; base remains
    <run the printed restore command>
    ```

16. **Lab victim** (forward-path target). Install the services without
    letting Debian start host-wide copies:

    ```sh
    sudo apt install -y nginx iperf3 dnsmasq-base openssh-server   # answer "No" to iperf3's daemon question
    sudo systemctl disable --now nginx                             # the host nginx would take :80 from the portal
    sudo scripts/deployment/pirewall-start --lab-victim up
    sudo ip netns exec labvictim ss -ltn                            # 22, 80, 5201, 53
    ```

    From a LAN client: `curl http://<victim-ip>/` answers "pirewall lab
    victim". The victim address is printed on the `Lab victim up` line
    (inside `[lab] victim_network`, `10.250.0.0/30` by default).
    `sudo scripts/deployment/pirewall-start --lab-victim down` removes it.

17. **Crash safety (G6) and the crash-loop alert:**

    ```sh
    sudo systemctl kill -s SIGKILL pirewall-core
    sudo nft list table inet pirewall_static | head -3       # still there
    # a LAN client still browses; then, to trip the alert:
    for i in 1 2 3; do sudo systemctl kill -s SIGKILL pirewall-core; sleep 30; done
    journalctl -u pirewall-crashloop-alert -n 20 --no-pager  # expect a CRITICAL
    sudo systemctl reset-failed pirewall-core && sudo systemctl start pirewall-core
    ```

18. **Flood and spoof smoke checks** (G1/G4 sanity, not paper numbers; the
    harness arrives in phase 18). From Kali on the LAN, against the Pi only:

    ```sh
    # Kali
    sudo timeout 10 hping3 -S -p 80 --flood <PI_LAN_IP>
    sudo hping3 -a <a bound neighbour's IP> -S -p 80 -c 200 <PI_LAN_IP>
    # Pi, during and after
    sudo nft list set inet pirewall_static offenders
    sudo nft list counters table inet pirewall_static
    sudo nft list set inet pirewall_adaptive block_mac; sudo nft list set inet pirewall_adaptive ratelimit_mac
    ```

    Expected: Kali's MAC in `offenders`; the neighbour's MAC in **no** set;
    the spoofed packets counted as dropped by the raw guard.

## H20 — fit the D1 thresholds from real benign data (now; needs ≥ 12 h of capture)

19. Turn the benign pcaps into rows with the runtime engine, then fit.
    Exclude every MAC in `lab_macs.txt`:

    ```sh
    sudo cp -r /var/lib/pirewall-lab/benign/<session> ~/benign && sudo chown -R "$USER" ~/benign
    uv run python -m scripts.dataset.pcap_to_flows ~/benign --out ~/flows-benign \
      --config config/local_config.toml --continuous --env-tag pi-live
    uv run python -m scripts.train.fit_d1_thresholds ~/flows-benign --config config/local_config.toml \
      --assume-benign --exclude-mac <kali-mac> --out config/d1_thresholds.toml
    head -30 config/d1_thresholds.toml        # frozen = false, provenance names the manifests
    ```

    Do **not** pass `--freeze` yet: that happens before campaign #2 (H35).

## H22–H24 — deploy v2.1: `--engine v2` in SHADOW (now)

20. ```sh
    grep -n 'mode' config/local_config.toml | head       # enforcement mode: keep "shadow" for this step
    sudo scripts/deployment/pirewall-start --check --engine v2 --data-mode live
    sudo scripts/deployment/pirewall-start --engine v2 --data-mode live --manifest ~/manifest-v2.1.json
    ```

    Leave it in SHADOW for a few hours of normal household use. On the
    control panel, check that the only POLICY_DECISION events are for lab
    MACs. Any decision against a household device is a G5 failure: record
    it, don't tune it by hand.

## H24–H30 — campaign #1, dev runs (after phase 18)

21. `lab/README.md` has every flag. Copy `lab/` to Kali first
    (`scp -r lab kali@<kali-ip>:lab`; it needs hping3, nmap, masscan, hydra,
    slowhttptest, dsniff, isc-dhcp-client). Then, on the Pi:

    ```sh
    sudo scripts/deployment/pirewall-start --lab-victim up
    sudo uv run python lab/preflight.py --host kali@<kali-ip>
    CAMPAIGN=(--attacker kali@<kali-ip> --attacker-ip <kali LAN ip> --attacker-mac <kali LAN mac>
              --param neighbour_ip=<a bound household IP> --param attacker_iface=<kali LAN iface>
              --param wordlist=<wordlist path on kali>)
    sudo uv run python lab/run_campaign.py lab/campaigns/dev.toml "${CAMPAIGN[@]}" --dry-run   # read it
    sudo uv run python lab/run_campaign.py lab/campaigns/dev.toml "${CAMPAIGN[@]}"
    uv run python lab/score_run.py lab/runs/<stamp>-dev/*/
    uv run python lab/aggregate.py lab/runs/<stamp>-dev --out lab/runs/<stamp>-dev-aggregate
    ```

    Also start scripted benign traffic on your own client devices (copy
    `lab/` there too):
    `python3 lab/benign/background.py --profile mixed --env-tag pi-scripted`.

## H28–H30 — ML training on own data (after phase 19)

22. Copy the pcap-derived rows (not the pcaps, if you can avoid it) to the dev
    machine and run phase 19's dataset builder, trainers, audit and evaluator
    there. The data stays out of git (`.gitignore` covers `*.pcap`, `*.csv`,
    `data/`, `reports/`).

    ```sh
    # dev machine
    rsync -a pi:~/flows-benign ./data/flows-benign-pi-live/
    rsync -a pi:~/flows-attack ./data/flows-attack-pi-scripted/

    # one dataset: pi-live benign + pi-scripted attacks, schema 3.0.0
    uv run python -m scripts.dataset.build_dataset \
      data/flows-benign-pi-live data/flows-attack-pi-scripted \
      --out data/phase19/dataset-pi --max-rows-per-run 5000

    uv run python -m scripts.train.train_phase19 \
      --dataset data/phase19/dataset-pi --output-dir data/phase19/models-pi

    # must exit 0 and name no feature; a failure blocks the report
    uv run python -m scripts.train.shortcut_audit \
      --dataset data/phase19/dataset-pi \
      --model data/phase19/models-pi/lightgbm_model.txt \
      --output reports/phase19/pi/audit.json

    # ONE read of the test blocks; a second needs --allow-repeat-test-read
    uv run python -m scripts.train.evaluate_phase19 \
      --dataset data/phase19/dataset-pi \
      --d2 data/phase19/models-pi/isolation_forest_model.joblib \
      --d3 data/phase19/models-pi/lightgbm_model.txt \
      --audit reports/phase19/pi/audit.json \
      --output-dir reports/phase19/pi
    ```

    Every file must say `pi-live`/`pi-scripted`. If the audit fails, stop:
    fix the dataset or the feature, not the threshold. Only then copy the
    `models-pi` artifacts and sidecars to the Pi and review the numbers.

## H35–H41 — freeze, campaign #2 (eval), held-out benign window (after phase 18)

23. Freeze the thresholds **before** campaign #2, and never change them after:

    ```sh
    uv run python -m scripts.train.fit_d1_thresholds ~/flows-benign --config config/local_config.toml \
      --assume-benign --exclude-mac <kali-mac> --freeze --out config/d1_thresholds.toml
    sha256sum config/d1_thresholds.toml pirewall/policy/table.toml   # record both
    sudo uv run python lab/run_campaign.py lab/campaigns/eval.toml "${CAMPAIGN[@]}"   # refuses unfrozen thresholds
    uv run python lab/score_run.py lab/runs/<stamp>-eval/*/
    uv run python lab/aggregate.py lab/runs/<stamp>-eval --out lab/runs/<stamp>-eval-aggregate
    ```

24. Offline G5 over every clean `pi-live` hour, including the held-out
    window. Per sealed capture session (step 5):

    ```sh
    uv run python -m scripts.dataset.pcap_to_flows ~/benign --out ~/flows-g5 \
      --config config/local_config.toml --continuous --env-tag pi-live
    uv run python lab/benign_fp.py ~/flows-g5 --out lab/runs/g5-$(date +%Y%m%d) --pcaps ~/benign \
      --config config/local_config.toml --capture-manifest ~/benign \
      --ground-truth lab/runs/<stamp>-dev/*/ground_truth.jsonl --ground-truth lab/runs/<stamp>-eval/*/ground_truth.jsonl
    ```

    It prints "forward guard may enforce: yes/no — <reason>". Only on "yes"
    may you run `sudo scripts/deployment/pirewall-start --guard-forward enforce`.

## H41–H42 — review

25. Start a Claude session with `docs/v2/prompts/phase-20-eval-docs-paper.md`.
    Hand it the run directories; it builds the tables from `lab/aggregate.py`
    only.

---

## Undo / recovery

| Situation | Command |
|---|---|
| Locked out, or anything looks wrong | `sudo scripts/deployment/pirewall-start --panic` (deletes the v2 tables; base policy stays) |
| Back to v1 behaviour on the v2 data plane | `sudo scripts/deployment/pirewall-start --engine v1 --data-mode live` |
| Stop the benign capture | `sudo bash lab/capture/benign_capture.sh stop` (or `sudo systemctl stop pirewall-benign-capture` for the systemd-run form; both seal the session) |
| Undo PMF | `sudo nmcli connection modify "$AP" 802-11-wireless-security.pmf optional && sudo nmcli connection up "$AP"` |
| Remove the `.pth` link | `sudo scripts/deployment/install_nftables_pth.sh --uninstall` |
| Remove the lab victim | `sudo scripts/deployment/pirewall-start --lab-victim down` |

More rows in `docs/SETUP.md` → Troubleshooting.
