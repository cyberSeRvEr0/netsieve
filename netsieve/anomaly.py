from collections import defaultdict
from datetime import datetime

class AnomalyDetector:
    def __init__(self, port_scan_threshold=10, beacon_interval=60, beacon_tolerance=15):
        self.port_scan_threshold = port_scan_threshold
        self.beacon_interval = beacon_interval
        self.beacon_tolerance = beacon_tolerance
        self.ports_seen = defaultdict(set)
        self.connections = defaultdict(list)

    def record(self, src_ip, port, ts=None):
        ts = ts or datetime.now()
        self.ports_seen[src_ip].add(port)
        self.connections[src_ip].append(ts)

    def check_port_scan(self, src_ip):
        return len(self.ports_seen[src_ip]) >= self.port_scan_threshold

    def check_beacon(self, src_ip):
        conns = self.connections[src_ip]
        if len(conns) < 3:
            return False
        intervals = [(b - a).total_seconds() for a, b in zip(conns, conns[1:])]
        avg = sum(intervals) / len(intervals)
        return abs(avg - self.beacon_interval) <= self.beacon_tolerance

    def check(self, src_ip):
        flags = []
        if self.check_port_scan(src_ip):
            flags.append(f"PORT SCAN ({len(self.ports_seen[src_ip])} ports)")
        if self.check_beacon(src_ip):
            flags.append("BEACONING (regular interval)")
        return flags   