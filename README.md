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

```bash
git clone https://github.com/cyberSeRvEr0/netsieve.git
cd netsieve
sudo pip install --break-system-packages --root-user-action=ignore .
sudo netsieve setup
```

| Command | What it does |
|---------|-------------|
| `git clone ...` | Downloads the netsieve source code from GitHub |
| `cd netsieve` | Enters the downloaded folder |
| `sudo pip install --break-system-packages --root-user-action=ignore .` | Installs netsieve and its Python dependencies (scapy, rich, requests, click) system-wide |
| `sudo netsieve setup` | Installs `iptables` and `traceroute` if missing, and creates a symlink so `sudo netsieve` works |

---

## The 6-Step Workflow

This is the main use case: detect an attack → identify the attacker → block them → save evidence.

| Step | Command | What it does |
|------|---------|-------------|
| 1 | `sudo netsieve detect -d 30` | Watches network traffic for 30 seconds. If it sees a SQL injection, XSS, path traversal, command injection, or SSRF pattern in any packet, it prints an alert with the attacker's IP |
| 2 | `netsieve trace 203.0.113.44` | Looks up that IP: reverse DNS (hostname), GeoIP (country, city, ISP), AbuseIPDB score (0–100), and runs traceroute to show the network path with each hop's location |
| 3 | `sudo netsieve block 203.0.113.44` | Adds an iptables rule that drops ALL traffic from that IP. Also saves it to `~/.netsieve_blocked.json` so it survives reboots |
| 4 | `netsieve report 203.0.113.44 -o evidence.txt` | Generates a plain-text forensic report file (DNS, GeoIP, threat score, traceroute, recommendations) ready to share with a security team or law enforcement |
| 5 | `netsieve list` | Shows all IPs currently in the blocklist |
| 6 | `sudo netsieve unblock 203.0.113.44` | Removes the iptables rule and removes the IP from the blocklist — traffic is allowed again |

**Example session:**

```
$ sudo netsieve detect -d 30
  [ALERT] 14:32:07
    From: 203.0.113.44:80 → 192.168.1.50
    Threat: SQL injection
    Data: GET /products?id=1 UNION SELECT username FROM users

$ netsieve trace 203.0.113.44
  Reverse DNS:  host-203-0-113-44.static.asianet.com
  Country:      Russia
  City:         Moscow
  ISP:          SomeHost LLC
  AbuseIPDB:    Score 87/100 | Reports: 342

$ sudo netsieve block 203.0.113.44
  ✓ 203.0.113.44 is now blocked. All traffic from this IP will be dropped.

$ netsieve report 203.0.113.44 -o evidence.txt
  ✓ Report saved: evidence.txt

$ netsieve list
  Blocked IPs (1):
    203.0.113.44

$ sudo netsieve unblock 203.0.113.44
  ✓ 203.0.113.44 has been unblocked.
```

---

## `detect` — Watch for attacks in real-time

Scans every incoming packet for known attack patterns. When one is found, it prints the attacker's IP, threat type, and a snippet of the malicious payload to the terminal.

| Command | What it does |
|---------|-------------|
| `sudo netsieve detect` | Watches forever until you press Ctrl+C |
| `sudo netsieve detect -d 30` | Watches for 30 seconds then stops automatically |
| `sudo netsieve detect -i eth0` | Only watches traffic on the `eth0` interface (not all interfaces) |
| `sudo netsieve detect -w "https://ntfy.sh/your-topic"` | Same as above, but also sends a push notification to your phone (via ntfy.sh, Slack, or Discord) every time an alert fires |

**Threat patterns detected:**

| Pattern | Example payload |
|---------|----------------|
| SQL injection | `UNION SELECT`, `DROP TABLE`, `OR 1=1`, `;--` |
| XSS | `<script>`, `javascript:`, `onerror=`, `alert(` |
| Path traversal | `../../`, `%2e%2e%2f` |
| Command injection | `; cat /etc/passwd`, `\| whoami` |
| SSRF | `http://169.254.169.254`, `http://127.0.0.1` |

---

## `capture` — Record all traffic as readable files

Records ALL network traffic, decodes every payload into readable text, and saves each conversation (flow) between two IPs as a separate `.txt` file.

Files are organized by date: `~/captures/2026-09-25/`

| Command | What it does |
|---------|-------------|
| `sudo netsieve capture -d 30` | Records all traffic for 30 seconds, saves decoded flows to `~/captures/` |
| `sudo netsieve capture -i eth0 -d 60` | Same but only on `eth0`, for 60 seconds |
| `sudo netsieve capture -d 30 -o ~/evidence/` | Same but saves to a custom folder |

**After it finishes:**
```bash
ls ~/captures/2026-09-25/
cat ~/captures/2026-09-25/10_0_0_1_to_93_184_216_34_TCP_443.txt
```

---

## `trace` — Identify an IP

Prints full intelligence about an IP to the terminal:

| Command | What it does |
|---------|-------------|
| `netsieve trace 203.0.113.44` | Reverse DNS, GeoIP (country, city, ISP, org), AbuseIPDB score, and enriched traceroute (each hop's location and ISP) |

No `sudo` needed — it only makes HTTP requests and runs traceroute.

---

## `report` — Generate a forensic report file

Same info as `trace`, but writes it to a plain-text file with recommendations for your security team or law enforcement.

| Command | What it does |
|---------|-------------|
| `netsieve report 203.0.113.44` | Saves to `netsieve_report_203.0.113.44.txt` in the current directory |
| `netsieve report 203.0.113.44 -o evidence_2026.txt` | Saves to a custom filename |

---

## Block management

| Command | What it does |
|---------|-------------|
| `sudo netsieve block 203.0.113.44` | Drops all traffic from that IP via iptables. Saves to `~/.netsieve_blocked.json` |
| `sudo netsieve unblock 203.0.113.44` | Allows traffic from that IP again. Removes from blocklist file |
| `netsieve list` | Prints all currently blocked IPs. No sudo needed |
| `sudo netsieve restore` | Re-applies all iptables rules from the blocklist file. Needed after reboot because iptables rules are lost |

---

## Service — Run detect 24/7 in the background

Installs netsieve as a systemd service. `detect` runs forever without you keeping a terminal open. Auto-starts on boot. Auto-restarts if it crashes.

| Command | What it does |
|---------|-------------|
| `sudo netsieve service` | Creates the service file, enables it, starts it |
| `sudo netsieve service -w "https://ntfy.sh/my-topic"` | Same, but the background service also sends phone alerts |
| `sudo netsieve service -i eth0 -w "https://ntfy.sh/my-topic"` | Same, but only watches `eth0` |
| `sudo systemctl start netsieve` | Starts the service (if stopped) |
| `sudo systemctl stop netsieve` | Stops the service |
| `sudo systemctl status netsieve` | Shows if running, uptime, and recent log lines |
| `sudo systemctl restart netsieve` | Stops and starts (use after changing config) |
| `journalctl -u netsieve -f` | Live log output in your terminal (like watching it run in real-time) |
| `journalctl -u netsieve --since today` | All logs from today |
| `sudo netsieve service-remove` | Stops, disables, and deletes the service completely |

> Your blocklist (`~/.netsieve_blocked.json`) and captures (`~/captures/`) are NOT deleted when you remove the service.

---

## Misc

| Command | What it does |
|---------|-------------|
| `sudo netsieve setup` | Installs `iptables` + `traceroute` if missing, creates the symlink. Run once after install |
| `netsieve --version` | Prints the version number |
| `netsieve --help` | Shows all available commands with descriptions |
| `netsieve detect --help` | Shows all options/flags for `detect` specifically |
| `netsieve capture --help` | Same for `capture` |
| `netsieve service --help` | Same for `service` |

---

## Webhook alerts (phone notifications)

Send real-time alerts to your phone or team when an attack is detected.

**Supported:**
- **ntfy.sh** (free, no signup): `https://ntfy.sh/your-topic-name`
- **Slack**: `https://hooks.slack.com/services/XXX/YYY/ZZZ`
- **Discord**: `https://discord.com/api/webhooks/XXX/YYY`

```bash
# One-time test (30 seconds):
sudo netsieve detect -d 30 -w "https://ntfy.sh/abc"

# As a permanent background service:
sudo netsieve service -w "https://ntfy.sh/abc"
```

To receive ntfy.sh alerts on your phone: install the **ntfy** app (Android/iOS) and subscribe to your topic name.

---

## Notes

- `detect` and `capture` require `sudo` because they use raw packet capture (scapy).
- `trace`, `report`, `list` do NOT require `sudo` — they only make HTTP requests.
- `block`, `unblock`, `restore` require `sudo` because they modify iptables rules.
- Traceroute hop enrichment (GeoIP per hop) requires a direct network path. In a NAT VM, only the gateway hop will be visible. On a real server or bridged VM, all hops are shown.   