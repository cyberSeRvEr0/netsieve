import time
import os
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

    def add(self, ts, decoded, http_text):
        content_key = (decoded[:100], http_text[:100] if http_text else "")
        if content_key in self._seen:
            return
        self._seen.add(content_key)
        self.last_seen = datetime.now()
        self.packets.append({"time": ts, "decoded": decoded, "http": http_text})   
        
class NetSieve:
    def __init__(self, interface=None, output_dir="~/captures", min_payload_size=20):
        self.interface = interface
        self.output_dir = Path(output_dir).expanduser()
        self.min_payload_size = min_payload_size
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.flows = defaultdict(Flow)
        self.total_packets = 0

    def run(self, duration=None):
        try:
            from scapy.all import sniff, IP, TCP, UDP, Raw
        except ImportError:
            console.print("[red]scapy not installed. Run: pip install scapy[/]")
            return

        console.print(Text(f"  Capturing on {self.interface or 'auto'} for {duration or '∞'}s...", style="bold cyan"))
        console.print(Text("  Ctrl+C to stop and save.\n", style="dim"))

        try:
            if duration:
                sniff(iface=self.interface, timeout=duration, prn=self._handle, store=0)
            else:
                sniff(iface=self.interface, prn=self._handle, store=0)
        except PermissionError:
            console.print("[red]Permission denied. Run with sudo.[/]")
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
            proto = f"TCP:{pkt[TCP].dport}"
        elif UDP in pkt:
            proto = f"UDP:{pkt[UDP].dport}"
        else:
            return

        if Raw not in pkt:
            return

        raw = pkt[Raw].load
        if len(raw) < self.min_payload_size:
            return

        flow_key = f"{src}→{dst}"
        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(src, dst, proto)

        decoded = decode_payload(raw)
        http = extract_http(raw)

        self.flows[flow_key].add(datetime.now().strftime("%H:%M:%S"), decoded, http)

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
            lines.append(f"Packets: {len(flow.packets)}")
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

            filepath.write_text("\n".join(lines))
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