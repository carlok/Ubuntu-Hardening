#!/usr/bin/env python3
"""Local configuration checks before creating Hetzner resources."""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping

from dotenv import load_dotenv


DEFAULTS = {
    "SERVER_NAME": "hardened-node",
    "SERVER_TYPE": "cx22",
    "LOCATION": "fsn1",
    "OS_IMAGE": "ubuntu-26.04",
    "SMTP_PORT": "587",
}

USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
SERVER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,50}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,50}$")


def _value(env: Mapping[str, str], name: str) -> str:
    return env.get(name, DEFAULTS.get(name, "")).strip()


def validate_config(env: Mapping[str, str]) -> list[str]:
    """Return human-readable validation errors for provisioner config."""
    errors: list[str] = []

    token = _value(env, "HCLOUD_TOKEN")
    if not token or token == "your_hetzner_api_token_here":
        errors.append("HCLOUD_TOKEN must be set to a Hetzner Cloud API token.")
    elif any(ch.isspace() for ch in token):
        errors.append("HCLOUD_TOKEN must not contain whitespace.")

    server_name = _value(env, "SERVER_NAME")
    if not SERVER_NAME_RE.fullmatch(server_name):
        errors.append("SERVER_NAME must be 1-51 chars: letters, digits, dot, underscore, or dash.")

    for name in ("SERVER_TYPE", "LOCATION", "OS_IMAGE"):
        value = _value(env, name)
        if not SLUG_RE.fullmatch(value):
            errors.append(f"{name} must be a non-empty Hetzner slug.")

    new_user = _value(env, "NEW_USER_NAME")
    if new_user and not USERNAME_RE.fullmatch(new_user):
        errors.append("NEW_USER_NAME must be a valid lowercase Linux username, max 32 chars.")

    smtp_port = _value(env, "SMTP_PORT")
    try:
        port = int(smtp_port)
    except ValueError:
        errors.append("SMTP_PORT must be an integer.")
    else:
        if not 1 <= port <= 65535:
            errors.append("SMTP_PORT must be between 1 and 65535.")

    smtp_host = _value(env, "SMTP_HOST")
    smtp_fields = ["SMTP_USER", "SMTP_PASS", "SMTP_FROM", "ALERT_EMAIL"]
    configured_smtp_fields = [name for name in smtp_fields if _value(env, name)]
    if configured_smtp_fields and not smtp_host:
        errors.append("SMTP_HOST must be set when SMTP credentials or alert addresses are configured.")
    if smtp_host:
        missing = [name for name in ("SMTP_FROM", "ALERT_EMAIL") if not _value(env, name)]
        if missing:
            errors.append("SMTP alerting requires: " + ", ".join(missing) + ".")

    return errors


def load_environment() -> None:
    env_path = "/app/.env"
    if os.path.isfile(env_path):
        load_dotenv(env_path, override=True)
    else:
        load_dotenv(override=True)


def main() -> int:
    load_environment()
    errors = validate_config(os.environ)
    if errors:
        print("Preflight failed:")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("Preflight OK: configuration is locally valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
