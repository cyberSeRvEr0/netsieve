import json
import os
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

def _config_path():
    override = os.environ.get("NETSIEVE_CONFIG")
    if override:
        return Path(override).expanduser()
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        import pwd
        home = Path(pwd.getpwnam(sudo_user).pw_dir)
    else:
        home = Path.home()
    return home / ".config" / "netsieve" / "config.json"

def load_config():
    config_path = _config_path()
    if config_path.exists():
        user_cfg = json.loads(config_path.read_text())
        if not isinstance(user_cfg, dict):
            raise ValueError(f"Configuration must be a JSON object: {config_path}")
        config = {**DEFAULTS, **user_cfg}
    else:
        config = {**DEFAULTS}
    if not isinstance(config["output_dir"], str) or not config["output_dir"]:
        raise ValueError("config output_dir must be a non-empty string")
    if type(config["min_payload_size"]) is not int or config["min_payload_size"] < 0:
        raise ValueError("config min_payload_size must be a non-negative integer")
    if config["interface"] is not None and not isinstance(config["interface"], str):
        raise ValueError("config interface must be a string or null")
    if type(config["auto_block"]) is not bool:
        raise ValueError("config auto_block must be a boolean")
    if type(config["auto_block_threshold"]) is not int or config["auto_block_threshold"] < 1:
        raise ValueError("config auto_block_threshold must be a positive integer")
    if config["webhook"] is not None and not isinstance(config["webhook"], str):
        raise ValueError("config webhook must be a string or null")
    if config["shodan_key"] is not None and not isinstance(config["shodan_key"], str):
        raise ValueError("config shodan_key must be a string or null")
    if type(config["save_pcap"]) is not bool:
        raise ValueError("config save_pcap must be a boolean")
    if not isinstance(config["save_protocols"], list) or not all(
        isinstance(protocol, str) and protocol.upper() in {"TCP", "UDP"}
        for protocol in config["save_protocols"]
    ):
        raise ValueError("config save_protocols must contain only TCP and UDP")
    config["save_protocols"] = [protocol.upper() for protocol in config["save_protocols"]]
    return config

def save_config(overrides):
    config_path = _config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    current = load_config()
    current.update(overrides)
    config_path.write_text(json.dumps(current, indent=2))   