import time
from pathlib import Path
from rich.console import Console

console = Console()

class NetSieve:
    def __init__(self, interface=None, output_dir="~/captures", min_payload_size=20):
        self.interface = interface
        self.output_dir = Path(output_dir).expanduser()
        self.min_payload_size = min_payload_size
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def run(self, duration=None):
        console.print(f"\n[dim]Starting capture... (Ctrl+C to stop)[/]\n")
        try:
            from scapy.all import sniff
            if duration:
                sniff(iface=self.interface, timeout=duration, pr=self._handle_packet)
            else:
                sniff(iface=self.interface, pr=self._handle_packet)
        except ImportError:
            console.print("[red]scapy not installed. Run: pip install scapy[/]")
        except PermissionError:
            console.print("[red]Permission denied. Run with sudo.[/]")

    def _handle_packet(self, pkt):
        pass   