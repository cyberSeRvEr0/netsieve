# NetSieve

Passive network capture, payload decoding, and attacker tracing.

One command. No config. No cloud. No daemon.

## Install & Usage

```bash
# Requirements: Linux/WSL, Python 3.10+, sudo
# traceroute is installed below for the trace command
# NOTE: capture and detect require a real Linux kernel (not WSL2)

git clone https://github.com/cyberSeRvEr0/netsieve.git
cd netsieve
sudo pip install --break-system-packages .
sudo apt install traceroute -y
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc


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

# --- Show version ---
netsieve --version

# --- Show help ---
netsieve --help   