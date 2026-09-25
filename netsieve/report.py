from datetime import datetime
from pathlib import Path
from netsieve.trace import reverse_dns, geoip_lookup, threat_intel_check, traceroute

def generate_report(ip, output=None):
    rdns = reverse_dns(ip)
    geo = geoip_lookup(ip)
    intel = threat_intel_check(ip)
    from netsieve.trace import traceroute_enriched
    hops = traceroute_enriched(ip)
    route_lines = []
    for hop_num, hop_ip, geo in hops:
        if geo:
            route_lines.append(f"  {hop_num:>2}  {hop_ip:<16} {geo['city']}, {geo['country']} | {geo['isp']}")
        else:
            route_lines.append(f"  {hop_num:>2}  {hop_ip:<16} Unknown")
    visible = [h for h in hops if h[2]]
    if visible:
        last = visible[-1]
        route_lines.append(f"\n  Carrier boundary: {last[1]} | {last[2]['isp']}, {last[2]['country']}")
    route = "\n".join(route_lines)   

    lines = []
    lines.append("=" * 50)
    lines.append("NETSIEVE FORENSIC REPORT")
    lines.append("=" * 50)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Target IP: {ip}")
    lines.append("")
    lines.append("--- IDENTIFICATION ---")
    lines.append(f"Reverse DNS: {rdns or 'None'}")
    if geo:
        lines.append(f"Country: {geo['country']}")
        lines.append(f"City: {geo['city']}")
        lines.append(f"ISP: {geo['isp']}")
        lines.append(f"Organization: {geo['org']}")
    lines.append("")
    lines.append("--- THREAT INTELLIGENCE ---")
    if intel:
        lines.append(f"AbuseIPDB Score: {intel['score']}/100")
        lines.append(f"Total Reports: {intel['reports']}")
    else:
        lines.append("No reports found.")
    lines.append("")
    lines.append("--- NETWORK PATH ---")
    lines.append(route)
    lines.append("")
    lines.append("--- RECOMMENDATIONS ---")
    lines.append("1. Block this IP at the firewall")
    lines.append("2. Check if other systems were targeted")
    lines.append("3. Preserve all capture files as evidence")
    lines.append("4. File a report with your national CERT")
    lines.append("")
    lines.append("=" * 50)

    report_text = "\n".join(lines)

    if not output:
        output = f"netsieve_report_{ip}.txt"

    Path(output).write_text(report_text)
    return output   