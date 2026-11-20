from collections import defaultdict
from datetime import datetime, timedelta


class AnomalyDetector:
    def __init__(
        self,
        port_scan_threshold=10,
        port_scan_window=60,
        beacon_interval=60,
        beacon_tolerance=15,
        beacon_window=10,
    ):
        self.port_scan_threshold = port_scan_threshold
        self.port_scan_window = port_scan_window
        self.beacon_interval = beacon_interval
        self.beacon_tolerance = beacon_tolerance
        self.beacon_window = beacon_window
        self.ports_seen = defaultdict(dict)
        self.connections = defaultdict(list)
        self._last_activity = {}
        self._last_cleanup = None

    def record(self, src_ip, port, ts=None):
        ts = ts or datetime.now()
        stale_after = max(
            self.port_scan_window,
            (self.beacon_interval + self.beacon_tolerance) * self.beacon_window,
        )
        if self._last_cleanup is None or (ts - self._last_cleanup).total_seconds() >= 60:
            for old_ip, last_seen in list(self._last_activity.items()):
                if (ts - last_seen).total_seconds() > stale_after:
                    self.ports_seen.pop(old_ip, None)
                    self.connections.pop(old_ip, None)
                    del self._last_activity[old_ip]
            self._last_cleanup = ts
        self._last_activity[src_ip] = ts
        cutoff = ts - timedelta(seconds=self.port_scan_window)

        ports = self.ports_seen[src_ip]
        for old_port, seen_at in list(ports.items()):
            if seen_at < cutoff:
                del ports[old_port]
        if port is not None:
            ports[port] = ts

        connections = self.connections[src_ip]
        connections.append(ts)
        del connections[:-self.beacon_window]

    def check_port_scan(self, src_ip):
        return len(self.ports_seen[src_ip]) >= self.port_scan_threshold

    def check_beacon(self, src_ip):
        conns = self.connections[src_ip]
        if len(conns) < 3:
            return False
        intervals = [(b - a).total_seconds() for a, b in zip(conns, conns[1:])]
        return all(
            abs(interval - self.beacon_interval) <= self.beacon_tolerance
            for interval in intervals
        )

    def check(self, src_ip):
        flags = []
        if self.check_port_scan(src_ip):
            flags.append(f"PORT SCAN ({len(self.ports_seen[src_ip])} ports)")
        if self.check_beacon(src_ip):
            flags.append("BEACONING (regular interval)")
        return flags
