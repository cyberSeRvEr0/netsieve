import hashlib
import json
import os
import re
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scapy.all import IP, TCP, UDP, Raw
from scapy.layers.tls.all import TLS, TLSClientHello, TLS_Ext_SupportedGroups, TLS_Ext_SupportedPointFormat
from click.testing import CliRunner

from netsieve.anomaly import AnomalyDetector
from netsieve.capture import NetSieve
from netsieve.cli import _cli
from netsieve.config import load_config
from netsieve.detect import run_detect
from netsieve.report import generate_report
from netsieve.webhook import send_webhook


class MechanismTests(unittest.TestCase):
    def test_anomalies_detect_recent_ports_and_expire_old_ports(self):
        detector = AnomalyDetector(port_scan_threshold=3, port_scan_window=10)
        now = datetime.now()
        detector.record("192.0.2.1", 80, now - timedelta(seconds=20))
        detector.record("192.0.2.1", 81, now)
        detector.record("192.0.2.1", 82, now)
        detector.record("192.0.2.1", 83, now)
        self.assertTrue(detector.check_port_scan("192.0.2.1"))
        detector.record("192.0.2.1", 84, now + timedelta(seconds=11))
        self.assertFalse(detector.check_port_scan("192.0.2.1"))

    def test_beaconing_requires_each_interval_to_be_regular(self):
        detector = AnomalyDetector(beacon_interval=60, beacon_tolerance=15)
        now = datetime.now()
        detector.record("192.0.2.1", 443, now)
        detector.record("192.0.2.1", 443, now + timedelta(seconds=30))
        detector.record("192.0.2.1", 443, now + timedelta(seconds=120))
        self.assertFalse(detector.check_beacon("192.0.2.1"))

    def test_anomaly_state_expires_for_inactive_sources(self):
        detector = AnomalyDetector()
        now = datetime.now()
        detector.record("192.0.2.1", 443, now)
        detector.record("192.0.2.2", 443, now + timedelta(seconds=800))
        self.assertNotIn("192.0.2.1", detector._last_activity)
        self.assertNotIn("192.0.2.1", detector.ports_seen)

    def test_detect_processes_syn_packets_without_payload(self):
        packets = [
            IP(src="192.0.2.10", dst="198.51.100.1")
            / TCP(sport=40000 + port, dport=port, flags="S")
            for port in range(1000, 1010)
        ]

        def fake_sniff(iface, timeout, prn, store):
            for packet in packets:
                prn(packet)

        with patch("scapy.all.sniff", side_effect=fake_sniff):
            with patch("netsieve.detect.load_config", return_value={
                "interface": None,
                "webhook": None,
                "auto_block": False,
                "auto_block_threshold": 3,
            }):
                with patch("netsieve.detect.console.print") as print_mock:
                    run_detect(duration=1)
        output = " ".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("PORT SCAN (10 ports)", output)

    def test_detect_reports_regular_udp_beaconing_without_payload(self):
        packets = [
            IP(src="192.0.2.10", dst="198.51.100.1") / UDP(sport=40000, dport=53)
            for _ in range(3)
        ]
        timestamps = [
            datetime(2026, 1, 1, 0, 0, 0),
            datetime(2026, 1, 1, 0, 1, 0),
            datetime(2026, 1, 1, 0, 2, 0),
        ]

        def fake_sniff(iface, timeout, prn, store):
            for packet in packets:
                prn(packet)

        with patch("scapy.all.sniff", side_effect=fake_sniff), \
             patch("netsieve.detect.load_config", return_value={
                 "interface": None,
                 "webhook": None,
                 "auto_block": False,
                 "auto_block_threshold": 3,
             }), \
             patch("netsieve.anomaly.datetime") as datetime_mock, \
             patch("netsieve.detect.time.monotonic", side_effect=[0, 60, 120]), \
             patch("netsieve.detect.console.print") as print_mock:
            datetime_mock.now.side_effect = timestamps
            run_detect(duration=1)
        output = " ".join(str(call.args[0]) for call in print_mock.call_args_list if call.args)
        self.assertIn("BEACONING (regular interval)", output)

    def test_configured_auto_block_triggers_after_distinct_alerts(self):
        packets = [
            IP(src="192.0.2.10", dst=f"198.51.100.{i}")
            / TCP(sport=50000, dport=80)
            / Raw(load=b"GET /?id=1 UNION SELECT users HTTP/1.1")
            for i in range(1, 4)
        ]

        def fake_sniff(iface, timeout, prn, store):
            for packet in packets:
                prn(packet)

        with patch("scapy.all.sniff", side_effect=fake_sniff), \
             patch("netsieve.detect.load_config", return_value={
                 "interface": None,
                 "webhook": None,
                 "auto_block": True,
                 "auto_block_threshold": 3,
             }), \
             patch("netsieve.block.block_ip", return_value=True) as block_mock, \
             patch("netsieve.detect.console.print"):
            run_detect(duration=1)
        block_mock.assert_called_once_with("192.0.2.10")

    def test_capture_keeps_transport_ports_separate_and_can_skip_pcaps(self):
        with tempfile.TemporaryDirectory() as output:
            capture = NetSieve(output_dir=output, save_pcap=False)
            for destination_port in (80, 443):
                packet = (
                    IP(src="192.0.2.10", dst="198.51.100.1")
                    / TCP(sport=50000, dport=destination_port)
                    / Raw(load=b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n")
                )
                capture._handle(packet)
            self.assertEqual(len(capture.flows), 2)
            with patch("netsieve.capture.console.print"):
                capture.save_all()
            files = list(Path(output).rglob("*"))
            self.assertEqual(len([path for path in files if path.suffix == ".txt"]), 2)
            self.assertFalse(any(path.suffix == ".pcap" for path in files))

    def test_capture_pcap_keeps_packets_without_readable_payload(self):
        with tempfile.TemporaryDirectory() as output:
            capture = NetSieve(output_dir=output, min_payload_size=20)
            capture._handle(
                IP(src="192.0.2.10", dst="198.51.100.1")
                / TCP(sport=50000, dport=443, flags="S")
            )
            capture._handle(
                IP(src="192.0.2.10", dst="198.51.100.1")
                / TCP(sport=50000, dport=443)
                / Raw(load=b"short")
            )
            self.assertEqual(len(capture.flows), 1)
            self.assertEqual(next(iter(capture.flows.values())).packet_count, 2)
            self.assertEqual(len(next(iter(capture.raw_packets.values()))), 2)
            with patch("netsieve.capture.console.print"):
                capture.save_all()
            self.assertEqual(len(list(Path(output).rglob("*.pcap"))), 1)

    def test_capture_cli_uses_configuration_and_cli_overrides(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps({
                "output_dir": str(Path(directory) / "configured"),
                "interface": "configured0",
                "min_payload_size": 77,
                "save_pcap": True,
            }))
            with patch.dict("os.environ", {"NETSIEVE_CONFIG": str(config_path)}):
                with patch("netsieve.capture.NetSieve") as capture_class:
                    result = CliRunner().invoke(
                        _cli,
                        ["capture", "--interface", "override0", "--output", str(Path(directory) / "override"),
                         "--min-payload-size", "12", "--no-save-pcap"],
                    )
            self.assertEqual(result.exit_code, 0, result.output)
            kwargs = capture_class.call_args.kwargs
            self.assertEqual(kwargs["interface"], "override0")
            self.assertEqual(kwargs["output_dir"], str(Path(directory) / "override"))
            self.assertEqual(kwargs["min_payload_size"], 12)
            self.assertFalse(kwargs["save_pcap"])

    def test_report_contains_verifiable_body_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.txt"
            with patch("netsieve.report.reverse_dns", return_value=None), \
                 patch("netsieve.report.geoip_lookup", return_value=None), \
                 patch("netsieve.report.threat_intel_check", return_value=None), \
                 patch("netsieve.trace.traceroute_enriched", return_value=[]):
                generate_report("192.0.2.1", output=str(output))
            report = output.read_text()
            body, integrity = report.split("--- EVIDENCE INTEGRITY ---", 1)
            recorded_hash = re.search(r"SHA-256 \(report body\): ([0-9a-f]{64})", integrity).group(1)
            self.assertEqual(recorded_hash, hashlib.sha256(body.encode("utf-8")).hexdigest())

    def test_udp_packet_is_counted_for_anomaly_detection(self):
        detector = AnomalyDetector(port_scan_threshold=2)
        detector.record("192.0.2.10", 53)
        detector.record("192.0.2.10", 123)
        self.assertTrue(detector.check_port_scan("192.0.2.10"))

    def test_ja3_fingerprint_excludes_grease_values(self):
        import hashlib

        with tempfile.TemporaryDirectory() as output:
            capture = NetSieve(output_dir=output)
            hello = SimpleNamespace(
                version=771,
                ciphers=[4865, 2570, 4866],
                ext=[
                    SimpleNamespace(type=10, groups=[29, 10794, 23]),
                    SimpleNamespace(type=11, ecpl=[0, 1]),
                    SimpleNamespace(type=2570),
                ],
            )
            expected = hashlib.md5(
                b"771,4865-4866,10-11,29-23,0-1",
                usedforsecurity=False,
            ).hexdigest()
            self.assertEqual(capture._compute_ja3(hello), expected)

    def test_capture_extracts_ja3_from_dissected_client_hello(self):
        with tempfile.TemporaryDirectory() as output:
            capture = NetSieve(output_dir=output)
            packet = (
                IP(src="192.0.2.10", dst="198.51.100.1")
                / TCP(sport=50000, dport=443)
                / TLS(msg=[TLSClientHello(
                    version=0x0303,
                    ciphers=[0x1301, 0x1302],
                    ext=[
                        TLS_Ext_SupportedGroups(groups=[29, 23]),
                        TLS_Ext_SupportedPointFormat(ecpl=[0, 1]),
                    ],
                )])
            )
            capture._handle(IP(bytes(packet)))
            self.assertTrue(any(flag.startswith("JA3:") for flag in capture.flows[next(iter(capture.flows))].flags))

    def test_config_rejects_invalid_values(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config_path.write_text(json.dumps({"auto_block_threshold": 0}))
            with patch.dict("os.environ", {"NETSIEVE_CONFIG": str(config_path)}):
                with self.assertRaisesRegex(ValueError, "auto_block_threshold"):
                    load_config()

    def test_blocking_validates_ip_and_uses_matching_firewall_family(self):
        from netsieve import block

        with tempfile.TemporaryDirectory() as directory:
            blocklist = Path(directory) / "blocked.json"
            with patch.object(block, "BLOCKLIST_FILE", blocklist), \
                 patch("netsieve.block.subprocess.run") as run_mock:
                run_mock.side_effect = [
                    SimpleNamespace(returncode=1, stderr=""),
                    SimpleNamespace(returncode=0, stderr=""),
                    SimpleNamespace(returncode=0, stderr=""),
                ]
                self.assertTrue(block.block_ip("2001:db8::1"))
                self.assertTrue(block.block_ip("2001:db8::1"))
                self.assertFalse(block.block_ip("not-an-ip"))
            self.assertEqual(run_mock.call_args_list[0].args[0][0], "ip6tables")
            self.assertEqual(run_mock.call_count, 3)
            self.assertEqual(json.loads(blocklist.read_text()), ["2001:db8::1"])

    def test_invalid_block_command_returns_failure_status(self):
        result = CliRunner().invoke(_cli, ["block", "not-an-ip"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("Invalid IP address", result.output)

    def test_unblock_clears_persisted_entry_when_rule_is_already_absent(self):
        from netsieve import block

        with tempfile.TemporaryDirectory() as directory:
            blocklist = Path(directory) / "blocked.json"
            blocklist.write_text(json.dumps(["192.0.2.1"]))
            with patch.object(block, "BLOCKLIST_FILE", blocklist), \
                 patch("netsieve.block.subprocess.run", return_value=SimpleNamespace(
                     returncode=1, stderr="Bad rule (does a matching rule exist?)"
                 )) as run_mock:
                self.assertTrue(block.unblock_ip("192.0.2.1"))
            self.assertEqual(run_mock.call_count, 1)
            self.assertEqual(json.loads(blocklist.read_text()), [])

    def test_webhook_treats_any_successful_http_status_as_success(self):
        response = SimpleNamespace(status_code=204)
        with patch("netsieve.webhook.requests.post", return_value=response), \
             patch("netsieve.webhook.console.print") as print_mock:
            send_webhook("https://discord.com/api/webhooks/test", "title", "body")
        self.assertIn("Alert sent", str(print_mock.call_args.args[0]))

    def test_service_unit_has_network_capabilities_and_quoted_arguments(self):
        import pwd
        from unittest.mock import mock_open

        service_file = mock_open()
        username = pwd.getpwuid(os.getuid()).pw_name
        with patch("netsieve.cli.os.geteuid", return_value=0), \
             patch.dict("os.environ", {"SUDO_USER": username}), \
             patch("shutil.which", return_value="/usr/bin/netsieve"), \
             patch("builtins.open", service_file), \
             patch("subprocess.run"), \
             patch("netsieve.cli.console.print"):
            result = CliRunner().invoke(
                _cli,
                ["service", "--interface", "eth0", "--webhook", "https://example.test/a b"],
            )
        self.assertEqual(result.exit_code, 0, result.output)
        unit = service_file().write.call_args.args[0]
        self.assertIn("AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN", unit)
        self.assertIn('User=' + username, unit)
        self.assertIn('"https://example.test/a b"', unit)


if __name__ == "__main__":
    unittest.main()
