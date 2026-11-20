import os
import hashlib
from scapy.utils import wrpcap   
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from rich.console import Console
from rich.text import Text
from netsieve.decode import decode_payload, extract_http
from netsieve.flags import check_payload

console = Console()

class Flow:
    def __init__(self, src, dst, proto):
        self.src = src
        self.dst = dst
        self.proto = proto
        self.packets = []
        self.first_seen = datetime.now()
        self.last_seen = datetime.now()
        self.flags = []
        self._seen = set()
        self.packet_count = 0

    def add(self, ts, decoded, http_text):
        content_key = (decoded[:100], http_text[:100] if http_text else "")
        if content_key in self._seen:
            return
        self._seen.add(content_key)
        self.packets.append({"time": ts, "decoded": decoded, "http": http_text})   
        
class NetSieve:
    def __init__(
        self,
        interface=None,
        output_dir="~/captures",
        min_payload_size=20,
        save_pcap=True,
        save_protocols=("TCP", "UDP"),
    ):
        self.interface = interface
        # Resolve ~ to the real user's home, not root's
        if output_dir.startswith("~"):
            sudo_user = os.environ.get("SUDO_USER")
            if sudo_user:
                import pwd
                home = pwd.getpwnam(sudo_user).pw_dir
            else:
                home = os.path.expanduser("~")
            self.output_dir = Path(home) / output_dir[2:]
        else:
            self.output_dir = Path(output_dir).expanduser()
        self.min_payload_size = min_payload_size
        self.save_pcap = save_pcap
        self.save_protocols = {protocol.upper() for protocol in save_protocols}
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.flows = defaultdict(Flow)
        self.total_packets = 0 
        self.raw_packets = defaultdict(list)  # store raw packets for pcap export   

    def _compute_ja3(self, ch):
        if ch.version is None:
            return None   
        grease = lambda value: (value & 0x0F0F) == 0x0A0A

        def values(items):
            return [int(value) for value in (items or []) if not grease(int(value))]

        try:
            version = int(ch.version)
            ciphers = values(ch.ciphers)
            extensions = []
            groups = []
            point_formats = []
            for extension in ch.ext or []:
                extension_type = int(extension.type)
                if grease(extension_type):
                    continue
                extensions.append(extension_type)
                if extension_type == 10:
                    groups = values(getattr(extension, "groups", []))
                elif extension_type == 11:
                    point_formats = values(getattr(extension, "ecpl", []))
            fingerprint = ",".join((
                str(version),
                "-".join(map(str, ciphers)),
                "-".join(map(str, extensions)),
                "-".join(map(str, groups)),
                "-".join(map(str, point_formats)),
            ))
        except (TypeError, ValueError, AttributeError):
            return None
        return hashlib.md5(fingerprint.encode("ascii"), usedforsecurity=False).hexdigest()
    
    def run(self, duration=None):
        if duration is not None and duration < 1:
            raise ValueError("duration must be a positive number of seconds")
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw
        except ImportError:
            console.print("[red]scapy not installed. Run: pip install scapy[/]")
            return

        console.print(Text(f"  Capturing on {self.interface or 'auto'} for {duration or '∞'}s...", style="bold cyan"))
        console.print(Text("  Ctrl+C to stop and save.\n", style="dim"))

        try:
            if duration is not None:
                sniff(iface=self.interface, timeout=duration, prn=self._handle, store=0)
            else:
                sniff(iface=self.interface, prn=self._handle, store=0)
        except PermissionError:
            console.print("[red]Permission denied. Run with sudo or grant CAP_NET_RAW.[/]")
            return
        except KeyboardInterrupt:
            pass

        self.save_all()

    def _handle(self, pkt):
        from scapy.all import IP, TCP, UDP, Raw

        if IP not in pkt:
            return

        self.total_packets += 1
        src = pkt[IP].src
        dst = pkt[IP].dst

        if TCP in pkt:
            if "TCP" not in self.save_protocols:
                return
            proto = f"TCP:{pkt[TCP].dport}"
        elif UDP in pkt:
            if "UDP" not in self.save_protocols:
                return
            proto = f"UDP:{pkt[UDP].dport}"
        else:
            return

        sport = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport
        dport = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport
        flow_key = f"{src}:{sport}→{dst}:{dport}:{proto.split(':', 1)[0]}"
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(src, dst, proto)
        flow = self.flows[flow_key]
        flow.packet_count += 1
        flow.last_seen = datetime.now()
        if self.save_pcap:
            self.raw_packets[flow_key].append(pkt)

        if TCP in pkt and pkt[TCP].dport in (443, 8443, 8080):
            from scapy.layers.tls.handshake import TLSClientHello
            if TLSClientHello in pkt:
                ja3_hash = self._compute_ja3(pkt[TLSClientHello])
                if ja3_hash and ja3_hash not in flow.flags:
                    flow.flags.append(f"JA3:{ja3_hash}")

        if Raw not in pkt:
            return

        raw = pkt[Raw].load
        if len(raw) < self.min_payload_size:
            return

        decoded = decode_payload(raw)
        http = extract_http(raw)

        flow.add(datetime.now().strftime("%H:%M:%S"), decoded, http)

        if http:
            threats = check_payload(http)
            for t in threats:
                if t not in self.flows[flow_key].flags:
                    self.flows[flow_key].flags.append(t)

    def save_all(self):
        day_dir = self.output_dir / datetime.now().strftime("%Y-%m-%d")
        day_dir.mkdir(parents=True, exist_ok=True)

        saved = 0
        for key, flow in self.flows.items():
            safe_key = key.replace(":", "_").replace("/", "-").replace("→", "_to_")
            filepath = day_dir / f"{safe_key}.txt"

            lines = []
            lines.append("NETSIEVE CAPTURE")
            lines.append(f"Date: {flow.first_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"Last: {flow.last_seen.strftime('%Y-%m-%d %H:%M:%S')}")
            lines.append(f"Source: {flow.src}")
            lines.append(f"Dest:   {flow.dst}")
            lines.append(f"Protocol: {flow.proto}")
            lines.append(f"Packets: {flow.packet_count}")
            lines.append("")
            lines.append("--- DECODED PAYLOADS ---")
            for p in flow.packets:
                lines.append(f"[{p['time']}]")
                if p["http"]:
                    lines.append(p["http"][:2000])
                else:
                    lines.append(p["decoded"][:500])
                lines.append("")

            if flow.flags:
                lines.append("--- FLAGS ---")
                for f in flow.flags:
                    lines.append(f"  [HIGH] {f}")
                lines.append("")
                lines.append(f"VERDICT: {len(flow.flags)} threat(s) detected — review recommended")
            else:
                lines.append("VERDICT: No known threat patterns detected")

            if self.raw_packets.get(key):
                lines.append(f"PCAP: {safe_key}.pcap (open in Wireshark)")   

            filepath.write_text("\n".join(lines))

            # PCAP export
            if self.raw_packets.get(key):
                pcap_path = filepath.with_suffix(".pcap")
                wrpcap(str(pcap_path), self.raw_packets[key]) 

            saved += 1

        console.print()
        console.print(Text(f"  Total packets seen: {self.total_packets}", style="bold"))
        console.print(Text(f"  Flows saved: {saved}", style="bold"))
        console.print(Text(f"  Output: {day_dir}", style="green"))

        flagged = [f for f in self.flows.values() if f.flags]
        if flagged:
            console.print(Text(f"  Flagged flows: {len(flagged)}", style="bold red"))
            for f in flagged:
                console.print(Text(f"    {f.src} → {f.dst} [{', '.join(f.flags)}]", style="red"))   