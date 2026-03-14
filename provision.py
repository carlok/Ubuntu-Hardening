#!/usr/bin/env python3
"""
Hetzner VM Provisioner — Two-Phase Hardening
=============================================
Phase 1 (~30s): Immediate lockdown — custom user, key-only SSH, random port,
                UFW, sysctl hardening. Runs as root on port 22.
                Hetzner firewall is closed to port 22 as soon as Phase 1 finishes.

Phase 2 (mins):  Full CIS hardening — package updates, auditd, AIDE, fail2ban,
                 msmtp, logwatch, rkhunter, Podman. Runs as the new user via sudo.
"""

import io
import os
import time
import uuid
import secrets
import string
import logging
from dotenv import load_dotenv
from hcloud import Client
from hcloud.server_types.domain import ServerType
from hcloud.images.domain import Image
from hcloud.locations.domain import Location
from hcloud.firewalls.domain import FirewallRule
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import paramiko


# ─────────────────────────────────────────────────────────────
# Colored logging
# ─────────────────────────────────────────────────────────────

class _ColorFormatter(logging.Formatter):
    _RESET  = "\033[0m"
    _BOLD   = "\033[1m"
    _LEVEL_STYLES = {
        logging.DEBUG:    "\033[38;5;244m",  # grey
        logging.INFO:     "\033[32m",         # green
        logging.WARNING:  "\033[33m",         # yellow
        logging.ERROR:    "\033[31m",         # red
        logging.CRITICAL: "\033[1;31m",       # bold red
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self._LEVEL_STYLES.get(record.levelno, self._RESET)
        ts    = self.formatTime(record, "%H:%M:%S")
        level = f"{color}{record.levelname:<8}{self._RESET}"
        msg   = record.getMessage()
        return f"{ts} {level} {msg}"


def _setup_logging() -> logging.Logger:
    handler = logging.StreamHandler()
    handler.setFormatter(_ColorFormatter())
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    # Quiet noisy libraries
    logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
    logging.getLogger("hcloud").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
    return logging.getLogger(__name__)


logger = _setup_logging()


# ─────────────────────────────────────────────────────────────
# SSH key helpers
# ─────────────────────────────────────────────────────────────

def generate_ssh_keypair() -> tuple[str, str]:
    """Return (private_key_pem, public_key_openssh) as strings."""
    logger.info("Generating RSA-4096 SSH keypair...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_openssh = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_pem, public_openssh


def generate_random_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and sum(c.isdigit() for c in pwd) >= 3):
            return pwd


# ─────────────────────────────────────────────────────────────
# SSH / SFTP helpers
# ─────────────────────────────────────────────────────────────

def wait_for_ssh(
    ip: str,
    username: str,
    *,
    key_filename: str | None = None,
    password: str | None = None,
    port: int = 22,
    timeout: int = 300,
) -> paramiko.SSHClient:
    logger.info(f"Waiting for SSH at {username}@{ip}:{port} ...")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip, port=port, username=username,
                key_filename=key_filename, password=password,
                timeout=10, banner_timeout=30, auth_timeout=30,
            )
            _, stdout, _ = client.exec_command("echo ready")
            if stdout.channel.recv_exit_status() == 0:
                logger.info(f"SSH connection established on port {port}.")
                return client
            client.close()
        except Exception as exc:
            logger.debug(f"SSH not ready: {exc}")
            time.sleep(5)
    raise TimeoutError(f"SSH at {ip}:{port} did not become available within {timeout}s.")


def upload_string(ssh_client: paramiko.SSHClient, content: str, remote_path: str) -> None:
    """Upload a string as a file on the remote host."""
    sftp = ssh_client.open_sftp()
    with sftp.file(remote_path, "w") as f:
        f.write(content)
    sftp.close()
    logger.debug(f"Uploaded content to {remote_path}")


def execute_remote_script(
    ssh_client: paramiko.SSHClient,
    local_path: str,
    args: str = "",
    use_sudo: bool = False,
    max_sftp_retries: int = 8,
) -> None:
    """Upload a local script via SFTP and execute it on the remote host."""
    logger.info(f"Uploading {os.path.basename(local_path)}...")
    sftp = None
    for attempt in range(1, max_sftp_retries + 1):
        try:
            sftp = ssh_client.open_sftp()
            break
        except Exception as exc:
            logger.warning(f"SFTP attempt {attempt}/{max_sftp_retries} failed: {exc}")
            time.sleep(5)
    if sftp is None:
        raise RuntimeError("Could not open SFTP channel.")

    remote_path = f"/tmp/{os.path.basename(local_path)}"
    sftp.put(local_path, remote_path)
    sftp.close()

    sudo = "sudo " if use_sudo else ""
    cmd  = f"chmod +x {remote_path} && {sudo}{remote_path} {args}".strip()
    logger.info(f"Executing: {cmd}")
    _, stdout, stderr = ssh_client.exec_command(cmd, get_pty=True)

    for line in iter(stdout.readline, ""):
        logger.info(f"  [remote] {line.rstrip()}")

    exit_code = stdout.channel.recv_exit_status()
    if exit_code not in (0, -1):   # -1 = channel closed (e.g. sshd restart at end of phase1)
        err = stderr.read().decode(errors="replace").strip()
        raise RuntimeError(f"Script exited {exit_code}: {err}")
    logger.info(f"{os.path.basename(local_path)} finished (exit {exit_code}).")


# ─────────────────────────────────────────────────────────────
# Hetzner firewall helpers
# ─────────────────────────────────────────────────────────────

def lockdown_firewall(firewall, ssh_port: int) -> None:
    """Replace all inbound rules with: only the new SSH port."""
    logger.info(f"Locking down Hetzner firewall — closing port 22, opening {ssh_port}/tcp ...")
    firewall.set_rules([
        FirewallRule(
            direction="in",
            protocol="tcp",
            port=str(ssh_port),
            source_ips=["0.0.0.0/0", "::/0"],
        )
    ])
    logger.info("Hetzner firewall locked down.")


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main() -> None:
    # Try explicit container path first, fall back to cwd search
    env_path = "/app/.env"
    if os.path.isfile(env_path):
        loaded = load_dotenv(env_path, override=True)
        logger.debug(f"Loaded .env from {env_path} (result={loaded})")
    else:
        loaded = load_dotenv(override=True)
        logger.debug(f"{env_path} not found — load_dotenv() cwd search, result={loaded}")

    raw_token = os.getenv("HCLOUD_TOKEN", "")
    token = raw_token.strip()

    if not token:
        logger.critical("HCLOUD_TOKEN is not set or is empty. Aborting.")
        return

    # Diagnostic — never logs the actual token value
    quotes = ('"', "'")
    has_quotes = token[0] in quotes or token[-1] in quotes
    has_ws = any(c.isspace() for c in token)
    logger.debug(
        f"Token diagnostics: len={len(token)} (raw_len={len(raw_token)}) "
        f"first4={token[:4]!r} last4={token[-4:]!r} "
        f"has_whitespace={has_ws} has_quotes={has_quotes}"
    )
    if len(raw_token) != len(token):
        logger.warning(f"Token had {len(raw_token) - len(token)} leading/trailing whitespace chars — stripped.")

    client = Client(token=token)

    # ── Configuration ──────────────────────────────────────────
    base_name   = os.getenv("SERVER_NAME", "hardened-node")
    server_name = f"{base_name}-{uuid.uuid4().hex[:6]}"
    server_type = os.getenv("SERVER_TYPE", "cx22")
    location    = os.getenv("LOCATION",    "fsn1")
    os_image    = os.getenv("OS_IMAGE",    "ubuntu-24.04")

    new_user = os.getenv("NEW_USER_NAME") or f"svc_{uuid.uuid4().hex[:8]}"
    ssh_port = secrets.choice(range(10_000, 60_000))

    # SMTP (optional) — forwarded to Phase 2 for msmtp setup
    smtp_env_content = None
    smtp_host = os.getenv("SMTP_HOST", "")
    if smtp_host:
        smtp_env_content = "\n".join([
            f"SMTP_HOST={smtp_host}",
            f"SMTP_PORT={os.getenv('SMTP_PORT', '587')}",
            f"SMTP_USER={os.getenv('SMTP_USER', '')}",
            f"SMTP_PASS={os.getenv('SMTP_PASS', '')}",
            f"SMTP_FROM={os.getenv('SMTP_FROM', '')}",
            f"ALERT_EMAIL={os.getenv('ALERT_EMAIL', 'root')}",
        ])

    key_path = "/workspace/id_rsa"

    # Resources that need rollback on failure
    server       = None
    firewall     = None
    ssh_client   = None
    hcloud_key   = None

    try:
        # ── Generate keypair ───────────────────────────────────
        priv_key, pub_key = generate_ssh_keypair()
        with open(key_path, "w") as fh:
            fh.write(priv_key)
        os.chmod(key_path, 0o600)
        logger.info(f"Private key saved to {key_path}")

        # ── Upload key to Hetzner (for root access at VM boot) ─
        hcloud_key_name = f"prov-key-{uuid.uuid4().hex[:6]}"
        hcloud_key = client.ssh_keys.create(name=hcloud_key_name, public_key=pub_key)
        logger.info(f"Hetzner SSH key uploaded: {hcloud_key_name}")

        # ── Create Hetzner firewall (port 22 only, temporary) ──
        logger.info("Creating Hetzner firewall (port 22 — temporary, Phase 1 only)...")
        fw_resp = client.firewalls.create(
            name=f"fw-{server_name}",
            rules=[FirewallRule(
                direction="in", protocol="tcp", port="22",
                source_ips=["0.0.0.0/0", "::/0"],
            )],
        )
        firewall = fw_resp.firewall

        # ── Create VM ──────────────────────────────────────────
        logger.info(f"Creating VM '{server_name}' ({server_type}) in {location} ...")
        vm_resp = client.servers.create(
            name=server_name,
            server_type=ServerType(name=server_type),
            image=Image(name=os_image),
            location=Location(name=location),
            firewalls=[firewall],
            ssh_keys=[hcloud_key],
        )
        server = vm_resp.server
        vm_resp.action.wait_until_finished()
        server = client.servers.get_by_id(server.id)
        server_ip = server.public_net.ipv4.ip
        logger.info(f"VM ready. IP: {server_ip}")

        # ══════════════════════════════════════════════════════
        # PHASE 1 — Immediate lockdown (~30 seconds)
        # ══════════════════════════════════════════════════════
        logger.info("=" * 55)
        logger.info("PHASE 1 — Immediate lockdown")
        logger.info("=" * 55)

        ssh_client = wait_for_ssh(server_ip, "root", key_filename=key_path)

        # Upload the public key so Phase 1 can install it for the new user
        upload_string(ssh_client, pub_key, "/tmp/provisioner_pub_key")
        logger.debug("Public key uploaded to /tmp/provisioner_pub_key")

        # Run Phase 1 — creates user, hardens SSH, UFW, sysctl
        execute_remote_script(
            ssh_client,
            "harden-phase1.sh",
            args=f"{new_user} {ssh_port}",
            use_sudo=False,
        )
        ssh_client.close()
        ssh_client = None
        logger.info("Phase 1 script finished. sshd is restarting on the new port...")

        # Brief pause: let sshd fully restart before we close port 22
        # (the script backgrounds `sleep 2 && systemctl restart ssh`)
        logger.info("Waiting 8s for sshd to come up on the new port before firewall lockdown...")
        time.sleep(8)

        # ── Close port 22 at Hetzner level — VM is now locked down ──
        lockdown_firewall(firewall, ssh_port)

        # ── Clean up Hetzner SSH key (no longer needed) ───────
        logger.info("Removing temporary Hetzner provisioning key...")
        client.ssh_keys.delete(hcloud_key)
        hcloud_key = None
        logger.info("Hetzner provisioning key removed.")

        # ══════════════════════════════════════════════════════
        # PHASE 2 — Full CIS hardening
        # ══════════════════════════════════════════════════════
        logger.info("=" * 55)
        logger.info("PHASE 2 — Full CIS hardening (this takes several minutes)")
        logger.info("=" * 55)

        # Reconnect as the new user on the randomised port
        ssh_client = wait_for_ssh(
            server_ip, new_user,
            key_filename=key_path,
            port=ssh_port,
        )

        # Upload SMTP credentials if provided
        if smtp_env_content:
            upload_string(ssh_client, smtp_env_content, "/tmp/smtp.env")
            logger.info("SMTP credentials uploaded for msmtp configuration.")

        execute_remote_script(
            ssh_client,
            "harden-phase2.sh",
            use_sudo=True,
        )
        ssh_client.close()
        ssh_client = None

        # ── Done ───────────────────────────────────────────────
        logger.info("=" * 55)
        logger.info("PROVISIONING COMPLETE")
        logger.info("=" * 55)
        logger.info(f"Server IP  : {server_ip}")
        logger.info(f"SSH Port   : {ssh_port}")
        logger.info(f"Username   : {new_user}")
        logger.info(f"Private Key: {key_path}  (mounted at ./keys/id_rsa on your host)")
        logger.info("")
        logger.info(f"Connect with:")
        logger.info(f"  ssh -i ./keys/id_rsa -p {ssh_port} {new_user}@{server_ip}")

    except Exception as exc:
        logger.error(f"Fatal error: {exc}")
        logger.warning("Rolling back Hetzner resources...")

        if ssh_client:
            try:
                ssh_client.close()
            except Exception:
                pass

        if server:
            logger.warning(f"Deleting server {server.name} ...")
            try:
                action = client.servers.delete(server)
                logger.warning("Waiting for server deletion to complete...")
                action.action.wait_until_finished()
                logger.warning(f"Server {server.name} deleted.")
            except Exception as e:
                logger.error(f"Could not delete server: {e}")

        if hcloud_key:
            try:
                client.ssh_keys.delete(hcloud_key)
            except Exception:
                pass

        if firewall:
            logger.warning(f"Deleting firewall {firewall.name} ...")
            try:
                client.firewalls.delete(firewall)
            except Exception as e:
                logger.error(f"Could not delete firewall: {e}")

        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
