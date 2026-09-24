# NetSieve

Passive network capture, payload decoding, and attacker tracing.

One command. No config. No cloud. No daemon.

## Install

```bash
# Requirements:
#   - Linux (real kernel required for capture and detect, WSL2 will NOT work for those)
#   - Python 3.10+
#   - sudo (needed for capture, detect, block, unblock, restore, service)
#   - traceroute + iptables (installed automatically by 'netsieve setup')

git clone https://github.com/cyberSeRvEr0/netsieve.git
cd netsieve
pip install --break-system-packages .
sudo netsieve setup   

# 1. Watch for attacks (find the attacker)
sudo netsieve detect -d 30
#    → [ALERT] From: 203.0.113.44  Threat: SQL injection

# 2. Identify the attacker (who are they?)
netsieve trace 203.0.113.44
#    → Country: Russia, City: Moscow, ISP: SomeHost LLC, Abuse Score: 87/100

# 3. Block them (cut them off)
sudo netsieve block 203.0.113.44
#    → ✓ 203.0.113.44 is now blocked

# 4. Save evidence (for your team or law enforcement)
netsieve report 203.0.113.44 -o evidence.txt
#    → ✓ Report saved: evidence.txt

# 5. Verify the block
netsieve list
#    → Blocked IPs (1): 203.0.113.44

# 6. When you're done, unblock
sudo netsieve unblock 203.0.113.44   

# Watch for attacks in real-time (prints alert to terminal)
sudo netsieve detect

# Watch for 30 seconds then stop
sudo netsieve detect -d 30

# Watch on a specific interface
sudo netsieve detect -i eth0

# Watch AND send phone alerts (Slack, Discord, or ntfy.sh)
sudo netsieve detect -w "https://ntfy.sh/your-topic-name"

# Capture all traffic, decode payloads, save as .txt files
sudo netsieve capture -d 30

# Capture on a specific interface for 60 seconds
sudo netsieve capture -i eth0 -d 60

# Save captures to a custom folder
sudo netsieve capture -d 30 -o ~/evidence/   

# Identify an IP (reverse DNS, GeoIP, threat intel, route)
netsieve trace 203.0.113.44

# Generate a forensic report file (for security team or law enforcement)
netsieve report 203.0.113.44

# Save report to a specific filename
netsieve report 203.0.113.44 -o evidence_2026.txt   

# Block an IP (all traffic from it is dropped)
sudo netsieve block 203.0.113.44

# Unblock an IP (allow traffic again)
sudo netsieve unblock 203.0.113.44

# Show all currently blocked IPs
netsieve list

# Re-apply all blocks after a reboot
sudo netsieve restore   

# Install and start the service (detect runs forever in background)
sudo netsieve service

# With phone alerts
sudo netsieve service -w "https://ntfy.sh/your-topic-name"

# Start the service
sudo systemctl start netsieve

# Stop the service
sudo systemctl stop netsieve

# Check if it's running
sudo systemctl status netsieve

# Restart (after changing config)
sudo systemctl restart netsieve

# Watch live logs (same as sitting in the terminal)
journalctl -u netsieve -f

# See today's logs
journalctl -u netsieve --since today

# Remove the service completely (stops, disables, deletes)
sudo netsieve service-remove   

# Install system dependencies (iptables, traceroute) — run once
sudo netsieve setup

# Show version
netsieve --version

# Show help for any command
netsieve --help
netsieve detect --help
netsieve capture --help
netsieve service --help   

sudo netsieve detect -w "https://ntfy.sh/abc"
# or as a service:
sudo netsieve service -w "https://ntfy.sh/abc"   