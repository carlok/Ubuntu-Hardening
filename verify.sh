#!/bin/bash
# =============================================================
# Post-Provisioning Health Check
#
# Verifies that both Phase 1 and Phase 2 hardening completed
# successfully.  Run via sudo after Phase 2 finishes.
#
# Usage: verify.sh <expected_user> <expected_ssh_port> [smtp]
#   smtp — if passed, also checks msmtp configuration
#
# Exit code: number of failed checks (0 = all passed)
# =============================================================

set -uo pipefail

USER_CHECK="${1:-}"
PORT_CHECK="${2:-}"
CHECK_SMTP="${3:-}"

PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS]  $*"; ((PASS++)); }
fail() { echo "  [FAIL]  $*"; ((FAIL++)); }
warn() { echo "  [WARN]  $*"; ((WARN++)); }

check() {
    local desc="$1"
    shift
    if eval "$@" >/dev/null 2>&1; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

echo ""
echo "======================================================="
echo "  Post-Provisioning Health Check"
echo "======================================================="
echo ""

# ── SSH hardening ─────────────────────────────────────────
echo "--- SSH ---"
if [[ -n "$PORT_CHECK" ]]; then
    check "sshd listening on port $PORT_CHECK" \
        "ss -tlnp | grep -q ':${PORT_CHECK}'"
    check "sshd NOT listening on port 22" \
        "! ss -tlnp | grep -q ':22 '"
fi
check "PermitRootLogin no" \
    "sshd -T 2>/dev/null | grep -qi 'permitrootlogin no'"
check "PasswordAuthentication no" \
    "sshd -T 2>/dev/null | grep -qi 'passwordauthentication no'"
check "ChallengeResponseAuthentication no" \
    "sshd -T 2>/dev/null | grep -qi 'kbdinteractiveauthentication no'"
check "ssh.socket disabled" \
    "! systemctl is-enabled ssh.socket 2>/dev/null | grep -q enabled"
if [[ -n "$USER_CHECK" ]]; then
    check "AllowUsers includes $USER_CHECK" \
        "sshd -T 2>/dev/null | grep -qi 'allowusers.*${USER_CHECK}'"
fi
echo ""

# ── User & root ───────────────────────────────────────────
echo "--- Users ---"
if [[ -n "$USER_CHECK" ]]; then
    check "User $USER_CHECK exists" \
        "id '$USER_CHECK'"
    check "User $USER_CHECK has authorized_keys" \
        "test -f /home/${USER_CHECK}/.ssh/authorized_keys"
    check "User $USER_CHECK has sudoers entry" \
        "test -f /etc/sudoers.d/90-${USER_CHECK}"
fi
check "Root account locked" \
    "passwd -S root 2>/dev/null | grep -q 'L'"
echo ""

# ── Firewall ──────────────────────────────────────────────
echo "--- Firewall ---"
check "UFW active" \
    "ufw status | grep -qi 'Status: active'"
if [[ -n "$PORT_CHECK" ]]; then
    check "UFW allows port $PORT_CHECK" \
        "ufw status | grep -q '${PORT_CHECK}/tcp'"
fi
check "UFW default deny incoming" \
    "ufw status verbose | grep -qi 'Default:.*deny (incoming)'"
echo ""

# ── Kernel hardening ──────────────────────────────────────
echo "--- Kernel / sysctl ---"
check "SYN cookies enabled" \
    "test $(sysctl -n net.ipv4.tcp_syncookies) -eq 1"
check "IP forwarding disabled" \
    "test $(sysctl -n net.ipv4.ip_forward) -eq 0"
check "Reverse path filtering" \
    "test $(sysctl -n net.ipv4.conf.all.rp_filter) -eq 1"
check "IPv6 disabled" \
    "test $(sysctl -n net.ipv6.conf.all.disable_ipv6) -eq 1"
check "ASLR enabled (randomize_va_space=2)" \
    "test $(sysctl -n kernel.randomize_va_space) -eq 2"
check "dmesg restricted" \
    "test $(sysctl -n kernel.dmesg_restrict) -eq 1"
check "Core dumps disabled (suid_dumpable=0)" \
    "test $(sysctl -n fs.suid_dumpable) -eq 0"
echo ""

# ── Services ──────────────────────────────────────────────
echo "--- Services ---"
check "auditd running" \
    "systemctl is-active --quiet auditd"
check "fail2ban running" \
    "systemctl is-active --quiet fail2ban"
check "AppArmor loaded" \
    "aa-status --enabled 2>/dev/null || systemctl is-active --quiet apparmor"
check "rsyslog running" \
    "systemctl is-active --quiet rsyslog"
check "process accounting active" \
    "systemctl is-active --quiet acct"
echo ""

# ── File integrity & rootkit detection ────────────────────
echo "--- Integrity / Detection ---"
check "AIDE database exists" \
    "test -f /var/lib/aide/aide.db"
check "rkhunter baseline exists" \
    "test -f /var/lib/rkhunter/db/rkhunter.dat"
check "rkhunter cron job" \
    "test -f /etc/cron.d/rkhunter-nightly || crontab -l 2>/dev/null | grep -q rkhunter"
echo ""

# ── Email alerts (optional) ──────────────────────────────
echo "--- Email (msmtp) ---"
if [[ "$CHECK_SMTP" == "smtp" ]]; then
    check "msmtp installed" \
        "command -v msmtp"
    check "msmtp config exists" \
        "test -f /etc/msmtprc"
    check "msmtp wired as system MTA" \
        "update-alternatives --query mta 2>/dev/null | grep -q msmtp || readlink /usr/sbin/sendmail 2>/dev/null | grep -q msmtp"
else
    warn "SMTP checks skipped (no smtp flag)"
fi
echo ""

# ── Podman ────────────────────────────────────────────────
echo "--- Podman ---"
check "Podman installed" \
    "command -v podman"
if [[ -n "$USER_CHECK" ]]; then
    check "subuid configured for $USER_CHECK" \
        "grep -q '${USER_CHECK}' /etc/subuid"
    check "subgid configured for $USER_CHECK" \
        "grep -q '${USER_CHECK}' /etc/subgid"
fi
echo ""

# ── Misc ──────────────────────────────────────────────────
echo "--- Misc ---"
check "ctrl-alt-del masked" \
    "systemctl is-masked ctrl-alt-del.target 2>/dev/null | grep -q masked || test -L /etc/systemd/system/ctrl-alt-del.target"
check "Login banner exists" \
    "test -s /etc/issue.net"
check "TCP wrappers deny all" \
    "grep -q 'ALL: ALL' /etc/hosts.deny"
echo ""

# ── Summary ───────────────────────────────────────────────
TOTAL=$((PASS + FAIL))
echo "======================================================="
echo "  Results: $PASS/$TOTAL passed, $FAIL failed, $WARN warnings"
echo "======================================================="
echo ""

exit "$FAIL"
