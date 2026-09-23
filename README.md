# NetSieve

Passive network capture, payload decoding, and attacker tracing.

One command. No config. No cloud. No daemon.

## Install & Usage

```bash
# Requirements: Linux/WSL, Python 3.10+, sudo
# capture and detect require a real Linux kernel (not WSL2)

git clone https://github.com/cyberSeRvEr0/netsieve.git
cd netsieve
sudo pip install --break-system-packages .
sudo netsieve setup


# --- Watch for incoming attacks in real-time ---
sudo netsieve detect -d 30

# --- Watch indefinitely (Ctrl+C to stop) ---
sudo netsieve detect

# --- Capture traffic for 30 seconds (saves .txt files to ~/captures/) ---
sudo netsieve capture -d 30

# --- Capture on a specific interface ---
sudo netsieve capture -i eth0 -d 60

# --- Trace an IP ---
netsieve trace 203.0.113.44

# --- Generate a forensic report ---
netsieve report 203.0.113.44

# --- Save report to a specific file ---
netsieve report 203.0.113.44 -o evidence.txt

# --- Block an attacker IP ---
sudo netsieve block 203.0.113.44

# --- Unblock an IP ---
sudo netsieve unblock 203.0.113.44

# --- List blocked IPs ---
netsieve list

# --- Restore blocks after reboot ---
sudo netsieve restore

# --- Show version ---
netsieve --version

# --- Show help ---
netsieve --help   