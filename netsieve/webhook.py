import json
import requests
from rich.console import Console
from rich.text import Text

console = Console()

def send_webhook(url, title, message, color=0xFF0000):
    """Send an alert to a Slack or Discord webhook."""
    if "discord.com" in url:
        payload = {
            "embeds": [{
                "title": title,
                "description": message,
                "color": color,
            }]
        }
    else:
        payload = {
            "text": f"*{title}*\n{message}",
        }

    try:
        r = requests.post(url, json=payload, timeout=5)
        if r.status_code == 200:
            console.print(Text("  [dim]Alert sent to webhook.[/]", style="dim"))
        else:
            console.print(Text(f"  [dim]Webhook failed: HTTP {r.status_code}[/]", style="yellow"))
    except Exception as e:
        console.print(Text(f"  [dim]Webhook error: {e}[/]", style="yellow"))

def format_alert(alert):
    """Format an alert dict into title and message strings."""
    title = f"NetSieve: {', '.join(alert['threats'])} detected"
    message = (
        f"Time: {alert['time']}\n"
        f"From: {alert['src']}{alert['port']}\n"
        f"To: {alert['dst']}\n"
        f"Threat: {', '.join(alert['threats'])}\n"
        f"Data: {alert['snippet']}"
    )
    return title, message   