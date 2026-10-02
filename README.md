# NetSieve

Passive network capture, payload decoding, and attacker tracing.

One command. No config. No cloud. No daemon.

---

## Install

**Requirements:**
- Linux (real kernel required for `capture` and `detect` — WSL2 will NOT work for those)
- Python 3.10+
- `sudo` (needed for `capture`, `detect`, `block`, `unblock`, `restore`, `service`)
- `traceroute` + `iptables` (installed automatically by `netsieve setup`)

    git clone https://github.com/cyberSeRvEr0/netsieve.git
    cd netsieve
    sudo pip install --break-system-packages --root-user-action=ignore .
    sudo netsieve setup

| Command | What it does |
|---------|-------------|
| `git clone ...` | Downloads the netsieve source code from GitHub |
| `cd netsieve` | Enters the downloaded folder |
| `sudo pip install --break-system-packages --root-user-action=ignore .` | Installs netsieve and its Python dependencies (scapy, rich, requests, click, ja3, python-whois) system-wide |
| `sudo netsieve setup` | Installs `iptables` and `traceroute` if missing, and creates a symlink so `sudo netsieve` works |

---

## Configuration File (optional)

Create `~/.config/netsieve/config.json` to set defaults once and never type flags again:

    {
      "output_dir": "~/captures",
      "min_payload_size": 20,
      "interface": null,
      "auto_block": false,
      "auto_block_threshold": 3,
      "webhook": "https://ntfy.sh/your-topic",
      "shodan_key": null,
      "save_pcap": true
    }

| Key | What it controls |
|-----|-----------------|
| `output_dir` | Where capture files are saved |
| `min_payload_size` | Minimum packet size (bytes) to record |
| `interface` | Lock to one interface (e.g. `"eth0"`) or `null` for auto |
| `auto_block` | If `true`, `detect` auto-blocks IPs that exceed threshold |
| `auto_block_threshold` | Number of alerts before auto-block triggers (default 3) |
| `webhook` | Webhook URL for phone alerts (ntfy.sh, Slack, Discord) |
| `shodan_key` | Shodan API key for `identify` deep lookup |
| `save_pcap` | If `true`, `capture` also saves raw `.pcap` files |

If the file doesn't exist, defaults are used. CLI flags always override the config file.

---

## The 7-Step Workflow

This is the main use case: detect an attack → identify the attacker → block them → save evidence.

| Step | Command | What it does |
|------|---------|-------------|
| 1 | `sudo netsieve detect -d 30` | Watches network traffic for 30 seconds. If it sees a SQL injection, XSS, path traversal, command injection, SSRF, port scan, or beaconing pattern, it prints an alert with the attacker's IP |
| 2 | `netsieve trace 203.0.113.44` | Looks up that IP: reverse DNS, GeoIP (country, city, ISP), AbuseIPDB score, and enriched traceroute |
| 3 | `netsieve identify 203.0.113.44` | Deep identification: ASN, VPN/Tor detection, Shodan ports/services, passive DNS history, WHOIS |
| 4 | `sudo netsieve block 203.0.113.44` | Adds an iptables rule that drops ALL traffic from that IP. Saves to `~/.netsieve_blocked.json` |
| 5 | `netsieve report 203.0.113.44 -o evidence.txt` | Generates a forensic report with SHA-256 hash, host info, and recommendations |
| 6 | `netsieve list` | Shows all IPs currently in the blocklist |
| 7 | `sudo netsieve unblock 203.0.113.44` | Removes the iptables rule and the IP from the blocklist |

**Example session:**

    $ sudo netsieve detect -d 30
      [ALERT] 14:32:07
        From: 203.0.113.44:80 → 192.168.1.50
        Threat: SQL injection
        Data: GET /products?id=1 UNION SELECT username FROM users

    $ netsieve identify 203.0.113.44
      ASN:          AS15169 (Google LLC, US)
      Type:         Direct / Datacenter
      Tor Exit:     No
      Shodan:       80/tcp open, 443/tcp open | OS: Linux
      Passive DNS:  12 domains resolved here in last 90 days
      WHOIS:        Created 2015-03-12, Org: Google LLC

      VERDICT: IP appears to be a direct or datacenter address. Full trace available.

    $ sudo netsieve block 203.0.113.44
      ✓ 203.0.113.44 is now blocked. All traffic from this IP will be dropped.

    $ netsieve report 203.0.113.44 -o evidence.txt
      ✓ Report saved: evidence.txt

    $ netsieve list
      Blocked IPs (1):
        203.0.113.44

    $ sudo netsieve unblock 203.0.113.44
      ✓ 203.0.113.44 has been unblocked.

---

## `detect` — Watch for attacks in real-time

Scans every incoming packet for known attack patterns AND statistical anomalies. When one is found, it prints the attacker's IP, threat type, and a snippet of the malicious payload to the terminal.

| Command | What it does |
|---------|-------------|
| `sudo netsieve detect` | Watches forever until you press Ctrl+C |
| `sudo netsieve detect -d 30` | Watches for 30 seconds then stops |
| `sudo netsieve detect -i eth0` | Only watches traffic on the `eth0` interface |
| `sudo netsieve detect -w "https://ntfy.sh/your-topic"` | Also sends push notifications to your phone |
| `sudo netsieve detect --auto-block` | Auto-blocks IPs that exceed the threshold (default 3 alerts) |
| `sudo netsieve detect --auto-block --threshold 5` | Auto-blocks after 5 alerts instead of 3 |

**Threat patterns detected (regex):**

| Pattern | Example payload |
|---------|----------------|
| SQL injection | `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `;--` |
| XSS | `<script>`, `javascript:`, `onerror=`, `alert(` |
| Path traversal | `../../`, `%2e%2e%2f` |
| Command injection | `; cat /etc/passwd`, `\| whoami` |
| SSRF | `http://169.254.169.254`, `http://127.0.0.1` |

**Anomaly patterns detected (statistical):**

| Pattern | What triggers it |
|---------|-----------------|
| Port scan | One IP touches 10+ different ports in a short window |
| Beaconing | One IP connects at a regular interval (e.g., every 60s ± 15s) — indicates C2 malware |

**Auto-block:**

When `--auto-block` is active, the same IP that triggers N alerts (default 3, configurable with `--threshold`) is automatically blocked via iptables and added to the blocklist. No human intervention needed. This is the key feature for running `detect` as a 24/7 background service.

---

## `capture` — Record all traffic as readable files + PCAP

Records ALL network traffic, decodes every payload into readable text, extracts JA3 TLS fingerprints, and saves each conversation (flow) between two IPs as a separate `.txt` file AND a raw `.pcap` file.

Files are organized by date: `~/captures/2026-10-02/`

| Command | What it does |
|---------|-------------|
| `sudo netsieve capture -d 30` | Records all traffic for 30 seconds, saves `.txt` + `.pcap` to `~/captures/` |
| `sudo netsieve capture -i eth0 -d 60` | Same but only on `eth0`, for 60 seconds |
| `sudo netsieve capture -d 30 -o ~/evidence/` | Same but saves to a custom folder |

**What's in each capture file:**

| File | Content |
|------|---------|
| `10_0_0_1_to_93_184_216_34_TCP_443.txt` | Readable decoded payloads, HTTP text, threat flags, JA3 hashes, verdict |
| `10_0_0_1_to_93_184_216_34_TCP_443.pcap` | Raw packet data — open in Wireshark for full forensic analysis |

**JA3 fingerprinting:**

Every TLS (HTTPS) connection has a unique "ClientHello" fingerprint. NetSieve extracts the JA3 hash from each flow and logs it. This lets you:
- Identify the tool the attacker used (Python, curl, browser, specific malware)
- Link multiple IPs to the same attacker (same JA3 = same tool)
- Match against known malware C2 fingerprints

**After it finishes:**

    ls ~/captures/2026-10-02/
    cat ~/captures/2026-10-02/10_0_0_1_to_93_184_216_34_TCP_443.txt
    wireshark ~/captures/2026-10-02/10_0_0_1_to_93_184_216_34_TCP_443.pcap

---

## `trace` — Identify an IP (basic)

Prints full intelligence about an IP to the terminal:

| Command | What it does |
|---------|-------------|
| `netsieve trace 203.0.113.44` | Reverse DNS, GeoIP (country, city, ISP, org), AbuseIPDB score, and enriched traceroute (each hop's location and ISP) |

No `sudo` needed — it only makes HTTP requests and runs traceroute.

---

## `identify` — Deep IP identification (VPN/Tor/Shodan)

Goes beyond `trace` to determine **what infrastructure** the attacker is hiding behind.

| Command | What it does |
|---------|-------------|
| `netsieve identify 203.0.113.44` | ASN lookup, VPN/Proxy detection, Tor exit check, passive DNS history, WHOIS |
| `netsieve identify 203.0.113.44 --shodan-key YOUR_KEY` | Same + Shodan port/service/OS lookup |

**What it checks:**

| Layer | Source | What it reveals |
|-------|--------|----------------|
| ASN / BGP | ipinfo.io | Which network owns the IP (e.g., "Mullvad VPN AB", "AT&T") |
| VPN/Proxy DB | VPNBlocklist (free JSON) | Whether the IP is in a known VPN/proxy range |
| Tor exit | check.torproject.org | Whether the IP is a Tor exit node |
| Shodan | Shodan API (free tier: 500 credits/day) | Open ports, services, OS, hostnames on that server |
| Passive DNS | Mnemonic pDNS (free) | What domains have historically resolved to that IP |
| WHOIS | python-whois | Registration date, org, registrar |

**Example output (VPN attacker):**

    $ netsieve identify 185.220.101.1

      ASN:          AS200502 (Mullvad VPN AB, SE)
      Type:         VPN / Proxy
      Tor Exit:     No
      WHOIS:        Created 2019-03-15, Org: Mullvad VPN AB

      VERDICT: Attacker is behind a VPN (Mullvad VPN AB).
               Real IP requires ISP cooperation.

**Example output (Tor attacker):**

    $ netsieve identify 77.247.181.165

      ASN:          AS13238 (Tor Project, US)
      Type:         TOR EXIT NODE
      Tor Exit:     Yes

      VERDICT: Attacker is behind Tor. Real IP unobtainable without legal action.

No `sudo` needed.

---

## `report` — Generate a forensic report file

Same info as `trace` + `identify`, but writes it to a plain-text file with **chain of custody** (SHA-256 hash, hostname, OS, Python version) making it forensically admissible.

| Command | What it does |
|---------|-------------|
| `netsieve report 203.0.113.44` | Saves to `netsieve_report_203.0.113.44.txt` in current directory |
| `netsieve report 203.0.113.44 -o evidence_2026.txt` | Saves to a custom filename |

**Report contents:**

| Section | Data |
|---------|------|
| Identification | Reverse DNS, GeoIP, ISP, Organization |
| Threat Intelligence | AbuseIPDB score, total reports |
| Network Path | Full traceroute with per-hop GeoIP |
| Recommendations | Block, check other systems, preserve evidence, file CERT report |
| Evidence Integrity | SHA-256 hash of the file, hostname, OS, Python version, tool version |

The SHA-256 hash means anyone can verify the file hasn't been tampered with. Essential for sharing with a CISO, SOC team, or law enforcement.

---

## Block management

| Command | What it does |
|---------|-------------|
| `sudo netsieve block 203.0.113.44` | Drops all traffic from that IP via iptables. Saves to `~/.netsieve_blocked.json` |
| `sudo netsieve unblock 203.0.113.44` | Allows traffic from that IP again. Removes from blocklist file |
| `netsieve list` | Prints all currently blocked IPs. No sudo needed |
| `sudo netsieve restore` | Re-applies all iptables rules from the blocklist file. Needed after reboot |

---

## Service — Run detect 24/7 in the background

Installs netsieve as a systemd service. `detect` runs forever without you keeping a terminal open. Auto-starts on boot. Auto-restarts if it crashes.

With `--auto-block` in the config file, the service will **actively block attackers** without any human intervention.

| Command | What it does |
|---------|-------------|
| `sudo netsieve service` | Creates the service file, enables it, starts it |
| `sudo netsieve service -w "https://ntfy.sh/my-topic"` | Same, but the background service also sends phone alerts |
| `sudo netsieve service -i eth0 -w "https://ntfy.sh/my-topic"` | Same, but only watches `eth0` |
| `sudo systemctl start netsieve` | Starts the service (if stopped) |
| `sudo systemctl stop netsieve` | Stops the service |
| `sudo systemctl status netsieve` | Shows if running, uptime, and recent log lines |
| `sudo systemctl restart netsieve` | Stops and starts (use after changing config) |
| `journalctl -u netsieve -f` | Live log output in your terminal |
| `journalctl -u netsieve --since today` | All logs from today |
| `sudo netsieve service-remove` | Stops, disables, and deletes the service completely |

> Your blocklist (`~/.netsieve_blocked.json`), captures (`~/captures/`), and config (`~/.config/netsieve/`) are NOT deleted when you remove the service.

---

## Webhook alerts (phone notifications)

Send real-time alerts to your phone or team when an attack is detected.

**Supported:**
- **ntfy.sh** (free, no signup): `https://ntfy.sh/your-topic-name`
- **Slack**: `https://hooks.slack.com/services/XXX/YYY/ZZZ`
- **Discord**: `https://discord.com/api/webhooks/XXX/YYY`

    # One-time test (30 seconds):
    sudo netsieve detect -d 30 -w "https://ntfy.sh/abc"

    # Or set it once in config and never type -w again:
    # Edit ~/.config/netsieve/config.json → set "webhook" field

    # As a permanent background service:
    sudo netsieve service -w "https://ntfy.sh/abc"

To receive ntfy.sh alerts on your phone: install the **ntfy** app (Android/iOS) and subscribe to your topic name.

---

## Misc

| Command | What it does |
|---------|-------------|
| `sudo netsieve setup` | Installs `iptables` + `traceroute` if missing, creates the symlink. Run once after install |
| `netsieve --version` | Prints the version number |
| `netsieve --help` | Shows all available commands with descriptions |
| `netsieve detect --help` | Shows all options/flags for `detect` specifically |
| `netsieve capture --help` | Same for `capture` |
| `netsieve identify --help` | Same for `identify` |
| `netsieve service --help` | Same for `service` |

---

## Notes

- `detect` and `capture` require `sudo` because they use raw packet capture (scapy).
- `trace`, `identify`, `report`, `list` do NOT require `sudo` — they only make HTTP requests.
- `block`, `unblock`, `restore` require `sudo` because they modify iptables rules.
- Traceroute hop enrichment (GeoIP per hop) requires a direct network path. In a NAT VM, only the gateway hop will be visible. On a real server or bridged VM, all hops are shown.
- `identify --shodan-key` requires a free Shodan API key (500 credits/day on free tier). Without it, Shodan lookup is skipped.
- PCAP files are only generated if `save_pcap` is `true` in config (default: `true`).
- JA3 fingerprinting only works on TLS traffic (ports 443, 8443, 8080 by default).
- VPN/Tor detection in `identify` uses free public lists. For higher accuracy, consider a commercial threat intel feed.   