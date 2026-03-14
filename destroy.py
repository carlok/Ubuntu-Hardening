#!/usr/bin/env python3
"""
Hetzner VM Destroyer
====================
Finds a server by name or IP, then cleanly destroys:
  - The server itself       (releases its primary IPv4 & IPv6)
  - Its attached firewalls
  - Any orphaned prov-key-* SSH keys left from provisioning
  - Lists any floating IPs bound to the server (warns; does not auto-delete)

Usage:
    python destroy.py <server-name-or-ip>  [--yes]

    --yes   Skip the interactive confirmation prompt (useful in CI).
"""

import sys
import os
import time
import logging
import argparse
from dotenv import load_dotenv
from hcloud import Client
from hcloud.servers.domain import Server


# ─────────────────────────────────────────────────────────────
# Colored logging  (same formatter as provision.py)
# ─────────────────────────────────────────────────────────────

class _ColorFormatter(logging.Formatter):
    _RESET = "\033[0m"
    _LEVEL_STYLES = {
        logging.DEBUG:    "\033[38;5;244m",
        logging.INFO:     "\033[32m",
        logging.WARNING:  "\033[33m",
        logging.ERROR:    "\033[31m",
        logging.CRITICAL: "\033[1;31m",
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_STYLES.get(record.levelno, self._RESET)
        ts    = self.formatTime(record, "%H:%M:%S")
        level = f"{color}{record.levelname:<8}{self._RESET}"
        return f"{ts} {level} {record.getMessage()}"


def _setup_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter())
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    logging.getLogger("hcloud").setLevel(logging.WARNING)
    return logging.getLogger(__name__)


logger = _setup_logging()


# ─────────────────────────────────────────────────────────────
# Lookup helpers
# ─────────────────────────────────────────────────────────────

def find_server(client: Client, target: str) -> Server | None:
    """Find a server by exact name or by primary IPv4 address."""
    # Try by name first
    server = client.servers.get_by_name(target)
    if server:
        return server
    # Try by IP
    for s in client.servers.get_all():
        if s.public_net.ipv4 and s.public_net.ipv4.ip == target:
            return s
    return None


def find_attached_firewalls(client: Client, server: Server) -> list:
    """Return all Hetzner firewalls currently attached to the server."""
    fw_ids = {
        ref.firewall.id
        for ref in (server.public_net.firewalls or [])
    }
    if not fw_ids:
        return []
    return [client.firewalls.get_by_id(fid) for fid in fw_ids]


def find_orphaned_prov_keys(client: Client) -> list:
    """Return any SSH keys whose name matches the prov-key-* pattern."""
    return [k for k in client.ssh_keys.get_all() if k.name.startswith("prov-key-")]


def find_floating_ips(client: Client, server: Server) -> list:
    """Return floating IPs assigned to this server."""
    return [
        fip for fip in client.floating_ips.get_all()
        if fip.server and fip.server.id == server.id
    ]


# ─────────────────────────────────────────────────────────────
# Destruction
# ─────────────────────────────────────────────────────────────

def destroy(client: Client, server: Server, skip_confirm: bool = False) -> None:
    server_ip  = server.public_net.ipv4.ip if server.public_net.ipv4 else "n/a"
    firewalls  = find_attached_firewalls(client, server)
    prov_keys  = find_orphaned_prov_keys(client)
    floating   = find_floating_ips(client, server)

    # ── Summary ────────────────────────────────────────────────
    logger.info("=" * 55)
    logger.info(f"Server      : {server.name}  ({server_ip})")
    logger.info(f"Firewalls   : {[fw.name for fw in firewalls] or '(none)'}")
    logger.info(f"Prov keys   : {[k.name  for k  in prov_keys] or '(none)'}")
    if floating:
        logger.warning(f"Floating IPs: {[fip.ip for fip in floating]}")
        logger.warning("  ↳ Floating IPs are NOT auto-deleted (they cost money even unassigned).")
        logger.warning("    Delete them manually via Hetzner console if they are no longer needed.")
    logger.info("=" * 55)

    if not skip_confirm:
        answer = input("\nDestroy this server and its resources? [yes/N]: ").strip().lower()
        if answer != "yes":
            logger.info("Aborted — nothing was deleted.")
            return

    # ── Delete server first — this auto-detaches all firewalls ──
    # Deleting the server releases its primary IPv4/IPv6 back to the pool.
    logger.info(f"Deleting server '{server.name}' (releases IPv4 {server_ip})...")
    try:
        result = client.servers.delete(server)
        logger.info("Waiting for server deletion to complete...")
        result.wait_until_finished()
        logger.info(f"Server '{server.name}' deleted. IPv4 {server_ip} released.")
    except Exception as exc:
        logger.error(f"Failed to delete server: {exc}")
        raise

    # ── Delete now-detached firewalls ──────────────────────────
    for fw in firewalls:
        logger.info(f"Deleting firewall '{fw.name}'...")
        try:
            client.firewalls.delete(fw)
            logger.info(f"Firewall '{fw.name}' deleted.")
        except Exception as exc:
            logger.error(f"Failed to delete firewall '{fw.name}': {exc}")

    # ── Clean up orphaned provisioning SSH keys ────────────────
    for key in prov_keys:
        logger.info(f"Deleting orphaned provisioning key '{key.name}'...")
        try:
            client.ssh_keys.delete(key)
            logger.info(f"Key '{key.name}' deleted.")
        except Exception as exc:
            logger.warning(f"Could not delete key '{key.name}': {exc}")

    logger.info("Destruction complete.")


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Destroy a Hetzner VM and all associated provisioner resources."
    )
    parser.add_argument(
        "target",
        help="Server name (e.g. hardened-node-a1b2c3) or primary IPv4 address.",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmation (for scripts/CI).",
    )
    args = parser.parse_args()

    env_path = "/app/.env"
    if os.path.isfile(env_path):
        load_dotenv(env_path, override=True)
    else:
        load_dotenv(override=True)
    raw_token = os.getenv("HCLOUD_TOKEN", "")
    token = raw_token.strip()
    if not token:
        logger.critical("HCLOUD_TOKEN is not set in environment or .env file.")
        sys.exit(1)
    if len(raw_token) != len(token):
        logger.warning(f"Token had {len(raw_token) - len(token)} leading/trailing whitespace chars — stripped.")

    client = Client(token=token)

    logger.info(f"Looking up server: {args.target!r} ...")
    server = find_server(client, args.target)
    if server is None:
        logger.error(f"No server found matching '{args.target}'.")
        sys.exit(1)

    destroy(client, server, skip_confirm=args.yes)


if __name__ == "__main__":
    main()
