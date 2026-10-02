import json
from pathlib import Path

DEFAULTS = {
    "output_dir": "~/captures",
    "min_payload_size": 20,
    "interface": None,
    "save_protocols": ["TCP", "UDP"],
    "auto_block": False,
    "auto_block_threshold": 3,
    "webhook": None,
    "shodan_key": None,
    "save_pcap": True,
}

def load_config():
    config_path = Path.home() / ".config" / "netsieve" / "config.json"
    if config_path.exists():
        user_cfg = json.loads(config_path.read_text())
        return {**DEFAULTS, **user_cfg}
    return DEFAULTS

def save_config(overrides):
    config_path = Path.home() / ".config" / "netsieve" / "config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    current = load_config()
    current.update(overrides)
    config_path.write_text(json.dumps(current, indent=2))   