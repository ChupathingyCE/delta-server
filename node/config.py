"""The node's settings: a TOML file (config.example.toml has every one),
with secrets read from the environment or from files outside the
repository, never from the file itself.

SPDX-FileCopyrightText: 2026 Milenko x Horrible Dev
SPDX-License-Identifier: MIT
"""

import os
import re
from pathlib import Path

try:
    import tomllib
except ImportError:  # (Python before 3.11)
    tomllib = None

DEFAULTS = {
    "node": {
        "domain": "localhost",
        "address": "127.0.0.1",
        "port": 8390,
        "data": "./data",
        "database": "",
        "reserved_names": ["admin", "moderator", "staff", "support", "system", "root", "server", "official"],
        "behind_proxy": False,
    },
    "list": {
        "games_per_address": 4,
        "console_hosts": [],
        "anchors_file": "",
    },
    "delta_table": {
        "source": "",
        "keys": [],
    },
    "identity": {
        "issuer_cert_file": "",
        "roots": [],
        "signer_socket": "",
        "issuer_key_file": "",
        "audiences": [],
    },
    "federation": {
        "network": "",
        "roots_file": "",
        "networks_file": "",
    },
    "doorbell": {
        "key_file": "",
        "brokers": [],
        "user": "doorbell-site",
        "password_file": "",
    },
}

# environment variables that take a setting's place (secrets and paths a
# host keeps out of the file): DELTA_<SECTION>_<NAME>
ENVIRONMENT = re.compile(r"^DELTA_([A-Z_]+?)__([A-Z_]+)$")
SECRET_ENVIRONMENT = {
    # the doorbell brokers' password itself, in place of a password file
    "DELTA_DOORBELL_PASSWORD": ("doorbell", "password"),
}


class ConfigError(ValueError):
    pass


def load(path: str = "", environ=None) -> dict:
    """the settings: DEFAULTS, then the file's, then DELTA_SECTION__NAME
    environment variables (strings only)"""
    environ = os.environ if environ is None else environ
    settings = {section: dict(values) for section, values in DEFAULTS.items()}
    if path:
        if tomllib is None:
            raise ConfigError("reading a config file needs Python 3.11 or newer (tomllib)")
        with open(path, "rb") as handle:
            loaded = tomllib.load(handle)
        for section, values in loaded.items():
            if section not in settings or not isinstance(values, dict):
                raise ConfigError(f"unknown section [{section}]")
            for name, value in values.items():
                if name not in settings[section]:
                    raise ConfigError(f"unknown setting {section}.{name}")
                settings[section][name] = value
    for variable, value in environ.items():
        match = ENVIRONMENT.match(variable)
        if match:
            section, name = match.group(1).lower(), match.group(2).lower()
            if section in settings and name in settings[section] and isinstance(settings[section][name], str):
                settings[section][name] = value
    for variable, (section, name) in SECRET_ENVIRONMENT.items():
        if environ.get(variable):
            settings[section][name] = environ[variable]
    check(settings)
    return settings


def check(settings: dict) -> None:
    node = settings["node"]
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", str(node["domain"])):
        raise ConfigError("node.domain is this node's host name (a-z, 0-9, dots and dashes)")
    if not isinstance(node["port"], int) or not 0 <= node["port"] <= 65535:
        raise ConfigError("node.port is a port number")
    for section, name in (("node", "reserved_names"), ("list", "console_hosts"), ("delta_table", "keys"),
                          ("identity", "roots"), ("identity", "audiences"), ("doorbell", "brokers")):
        if not isinstance(settings[section][name], list):
            raise ConfigError(f"{section}.{name} is a list")
    for key in settings["delta_table"]["keys"] + settings["identity"]["roots"]:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", str(key)):
            raise ConfigError("public keys are 64 hex digits each")
    check_federation(settings)


def check_federation(settings: dict) -> None:
    network = settings["federation"]["network"]
    if network and not re.fullmatch(r"[a-z0-9.-]{4,253}", str(network)):
        raise ConfigError("federation.network is this network's domain (a-z, 0-9, dots and dashes)")


def data_folder(settings: dict) -> Path:
    folder = Path(settings["node"]["data"]).expanduser()
    folder.mkdir(parents=True, exist_ok=True)
    return folder
