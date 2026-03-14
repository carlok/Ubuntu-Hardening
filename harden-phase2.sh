#!/bin/bash
# =============================================================
# Phase 2: Full CIS-Level Hardening
#
# Derived from Cloud-Ubuntu-Hardening-2026.sh (upstream fork).
# Runs after Phase 1 as the unprivileged user via sudo.
#
# Key differences from upstream:
#   - Section 5.1: SSH uses drop-in config only (preserves Phase 1
#     port/AllowUsers settings); does NOT overwrite sshd_config.
#   - Section 5.4: Skips PasswordAuthentication (set in Phase 1).
#   - New Section 8: fail2ban, msmtp, logwatch, needrestart,
#     rkhunter, Podman rootless setup.
#   - Uses full-upgrade (security + kernel) not just upgrade.
#   - Adds apt autoremove/clean.
#
# Pre-conditions:
#   - Phase 1 already ran: user exists, SSH port locked down.
#   - Optional: /tmp/smtp.env with SMTP credentials for msmtp.
# =============================================================

export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a          # auto-restart services, no interactive scanning

LOG_DIR="/var/log/hardening"
mkdir -p "$LOG_DIR/sections"

CURRENT_SECTION=""

start_section() {
    CURRENT_SECTION="$1"
    echo ""
    echo "[$(date '+%H:%M:%S')] ===[ SECTION $CURRENT_SECTION ]================================="
    mkdir -p "$LOG_DIR/sections/$CURRENT_SECTION"
}

log_ok()  { echo "  [✓] $1" | tee -a "$LOG_DIR/sections/$CURRENT_SECTION/ok.log"; }
log_err() { echo "  [✗] $1" | tee -a "$LOG_DIR/sections/$CURRENT_SECTION/err.log"; }

run_cmd() {
    local cmd="$1"
    local desc="$2"
    echo "  --> $desc"
    if output=$(eval "$cmd" 2>&1); then
        log_ok "$desc"
    else
        log_err "FAILED: $desc | $output"
    fi
}

echo "[$(date '+%H:%M:%S')] Starting Phase 2: Full CIS Hardening..."

# ===============[ SECTION 1: Initial Setup ]===============

start_section "1.1 — Filesystem module blacklisting"
run_cmd 'for fs in cramfs freevxfs hfs hfsplus squashfs udf jffs2 usb-storage; do
    echo "install $fs /bin/false" > "/etc/modprobe.d/disable_${fs}.conf"
    rmmod "$fs" 2>/dev/null || true
done' "Disable unnecessary kernel filesystem modules"
run_cmd "systemctl mask autofs 2>/dev/null || true" "Mask autofs service"

start_section "1.2 — Package updates"
run_cmd "apt-get update -qq" "Update package index"
run_cmd "apt-get full-upgrade -y" "Apply all security and kernel updates (full-upgrade)"
run_cmd "apt-get autoremove -y" "Remove obsolete packages"
run_cmd "apt-get clean" "Clean package cache"
run_cmd "chown root:root /boot/grub/grub.cfg 2>/dev/null || true" "Set grub.cfg ownership"
run_cmd "chmod og-rwx /boot/grub/grub.cfg 2>/dev/null || true" "Set grub.cfg permissions"

start_section "1.3 — AppArmor & kernel hardening"
run_cmd "apt-get install -y apparmor-utils apparmor-profiles apparmor-profiles-extra" "Install AppArmor utils"
for profile in /etc/apparmor.d/*; do
    [[ -f "$profile" ]] && grep -q '^profile ' "$profile" && \
        run_cmd "aa-complain '$profile' >/dev/null 2>&1 || true" "Complain mode: $(basename "$profile")"
done
run_cmd 'echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/60-aslr.conf' "Enable ASLR"
run_cmd 'echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/60-yama.conf' "Restrict ptrace scope"
run_cmd "sysctl --system >/dev/null" "Apply all sysctl settings"

start_section "1.4 — Core dump hardening"
run_cmd 'grep -q "^\* hard core 0" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >> /etc/security/limits.conf' "Disable core dumps (limits.conf)"
run_cmd 'echo "fs.suid_dumpable = 0" > /etc/sysctl.d/60-coredump.conf' "Disable suid core dumping"
run_cmd "sysctl -p /etc/sysctl.d/60-coredump.conf" "Apply coredump sysctl"

start_section "1.5 — Remove prelink/apport; enable unattended-upgrades"
run_cmd "dpkg -l prelink &>/dev/null && apt-get purge -y prelink || true" "Remove prelink"
run_cmd "dpkg -l apport  &>/dev/null && apt-get purge -y apport  || true" "Remove apport"
run_cmd "apt-get install -y unattended-upgrades" "Install unattended-upgrades"
# Configure security-only automatic updates
cat > /etc/apt/apt.conf.d/50unattended-upgrades-hardened << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
run_cmd "dpkg-reconfigure -plow unattended-upgrades" "Enable unattended-upgrades daemon"

start_section "1.6 — MOTD / login banner"
# Banner was already written by Phase 1; just disable the dynamic MOTD scripts
run_cmd "chmod -x /etc/update-motd.d/* 2>/dev/null || true" "Disable dynamic MOTD scripts"
run_cmd "chmod 644 /etc/issue.net /etc/issue /etc/motd 2>/dev/null || true" "Fix banner permissions"

start_section "1.7 — Remove GUI"
run_cmd "dpkg -l gdm3 &>/dev/null && apt-get purge -y gdm3 || true" "Remove GDM3 display manager"

start_section "1.8 — Secure tmpfs mounts"
run_cmd 'grep -q "^tmpfs /tmp"     /etc/fstab || echo "tmpfs /tmp     tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab' "Mount /tmp as noexec tmpfs"
run_cmd 'grep -q "^tmpfs /dev/shm" /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab' "Mount /dev/shm as noexec tmpfs"
run_cmd 'grep -q "^/tmp /var/tmp"  /etc/fstab || echo "/tmp /var/tmp none bind 0 0"                            >> /etc/fstab' "Bind /var/tmp → /tmp"
run_cmd "mount -a || true" "Apply fstab mounts"

# ===============[ SECTION 2: Services ]===============

start_section "2.1 — Remove unnecessary network services"
UNWANTED_SERVICES=(
    avahi-daemon autofs isc-dhcp-server bind9 dnsmasq vsftpd slapd
    nfs-kernel-server ypserv cups rpcbind rsync samba snmpd tftpd-hpa
    squid apache2 nginx xinetd xserver-common telnetd
    nis rsh-client talk talkd telnet inetutils-telnet ldap-utils ftp tnftp
)
for svc in "${UNWANTED_SERVICES[@]}"; do
    run_cmd "dpkg -l $svc &>/dev/null && apt-get purge -y $svc || true" "Purge $svc"
done

# Remove postfix specifically (we use msmtp instead)
run_cmd "dpkg -l postfix &>/dev/null && apt-get purge -y postfix || true" "Purge postfix (msmtp used instead)"

start_section "2.4 — NTP (timesyncd)"
run_cmd "dpkg -l chrony &>/dev/null && apt-get purge -y chrony || true" "Remove chrony"
cat >> /etc/systemd/timesyncd.conf << 'EOF'

[Time]
NTP=time-a-wwv.nist.gov time-d-wwv.nist.gov
FallbackNTP=time-b-wwv.nist.gov time-c-wwv.nist.gov
EOF
run_cmd "systemctl restart systemd-timesyncd" "Restart timesyncd"
run_cmd "systemctl enable systemd-timesyncd" "Enable timesyncd"

start_section "2.5 — Cron permissions"
run_cmd "chown root:root /etc/crontab /etc/cron.{hourly,daily,weekly,monthly,d}" "Set cron ownership"
run_cmd "chmod og-rwx   /etc/crontab /etc/cron.{hourly,daily,weekly,monthly,d}" "Set cron permissions"
run_cmd "echo 'root' > /etc/cron.allow && chmod 600 /etc/cron.allow" "Restrict cron to root only"

# ===============[ SECTION 3: Network Configuration ]===============

start_section "3.1 — Disable IPv6 & Bluetooth"
# Phase 1 already wrote sysctl rules; this section creates the CIS-referenced file
run_cmd 'cat > /etc/sysctl.d/60-ipv6.conf << "EOF"
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF' "Write /etc/sysctl.d/60-ipv6.conf"
run_cmd "sysctl -p /etc/sysctl.d/60-ipv6.conf || true" "Apply IPv6 disable settings"
run_cmd "dpkg -l bluez &>/dev/null && apt-get purge -y bluez bluetooth || true" "Remove Bluetooth"

start_section "3.2 — Disable unused network protocols"
for mod in dccp tipc rds sctp; do
    run_cmd "echo 'install $mod /bin/false' > /etc/modprobe.d/disable_${mod}.conf" "Blacklist $mod kernel module"
    run_cmd "modprobe -r $mod 2>/dev/null || true" "Unload $mod module"
done

start_section "3.3 — Network sysctl hardening"
cat > /etc/sysctl.d/60-net-hardening.conf << 'EOF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
EOF
run_cmd "sysctl -p /etc/sysctl.d/60-net-hardening.conf" "Apply network sysctl hardening"

# ===============[ SECTION 4: Host Firewall (UFW) ]===============

start_section "4.1 — UFW additional rules"
# UFW was already enabled and configured by Phase 1.
# We only add rules that Phase 1 didn't set.
run_cmd "dpkg -l iptables-persistent &>/dev/null && apt-get purge -y iptables-persistent || true" "Remove iptables-persistent"
# Phase 1 already set: default deny incoming, allow outgoing, allow lo, allow SSH port
# Add: deny external traffic claiming loopback source
run_cmd "ufw deny in from 127.0.0.0/8  2>/dev/null || true" "UFW: deny external loopback source (idempotent)"
run_cmd "ufw deny in from ::1           2>/dev/null || true" "UFW: deny external IPv6 loopback source (idempotent)"

# ===============[ SECTION 5: SSH & Authentication ]===============

start_section "5.1 — SSH crypto hardening (drop-in, preserves Phase 1 config)"
# IMPORTANT: We do NOT overwrite /etc/ssh/sshd_config.
# Phase 1 already set Port, AllowUsers, PermitRootLogin, PasswordAuthentication.
# We add cipher/MAC/logging hardening via a sshd_config.d drop-in.
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/50-cis-hardening.conf << 'EOF'
# CIS Phase 2 drop-in — crypto & logging hardening
# Does not override Phase 1 settings (Port, AllowUsers, etc.)
LogLevel VERBOSE
IgnoreRhosts yes
GSSAPIAuthentication no
HostbasedAuthentication no
ClientAliveInterval 15
ClientAliveCountMax 2
AcceptEnv LANG LC_*

# Disable weak ciphers (keep chacha20 and aes-gcm which are strong)
Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc

# Disable weak key exchanges
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1

# Disable weak MACs
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com
EOF
run_cmd "sshd -t" "Validate sshd config (drop-in)"
run_cmd "systemctl reload ssh" "Reload SSH (no connection drop)"

start_section "5.2 — sudo hardening"
cat > /etc/sudoers.d/01_cis_base << 'EOF'
Defaults logfile=/var/log/sudo.log
Defaults log_input,log_output
Defaults use_pty
Defaults env_reset, timestamp_timeout=15
EOF
run_cmd "chmod 440 /etc/sudoers.d/01_cis_base" "Set sudoers drop-in permissions"
run_cmd "visudo -c -f /etc/sudoers.d/01_cis_base" "Validate sudoers drop-in"

start_section "5.4 — Password & PAM policy"
run_cmd 'sed -i "/^PASS_MAX_DAYS/c\PASS_MAX_DAYS   180" /etc/login.defs' "Password max age: 180 days"
run_cmd 'sed -i "/^PASS_MIN_DAYS/c\PASS_MIN_DAYS   7"   /etc/login.defs' "Password min age: 7 days"
run_cmd 'sed -i "/^PASS_WARN_AGE/c\PASS_WARN_AGE   14"  /etc/login.defs' "Password warning: 14 days"
run_cmd 'sed -i "/^ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512" /etc/login.defs' "Password hashing: SHA512"
run_cmd 'sed -i "/^UMASK/c\UMASK 077" /etc/login.defs' "Default umask: 077"
run_cmd 'useradd -D -f 30' "Lock inactive accounts after 30 days"

run_cmd "apt-get install -y libpam-pwquality" "Install pam_pwquality"
run_cmd 'grep -q "pam_faillock.so" /etc/pam.d/common-auth || sed -i "/pam_unix.so/i auth required pam_faillock.so preauth silent deny=4 unlock_time=900\nauth [default=die] pam_faillock.so authfail deny=4 unlock_time=900" /etc/pam.d/common-auth' "Configure faillock: 4 attempts, 15 min lockout"
run_cmd 'grep -q "pam_pwquality.so" /etc/pam.d/common-password || sed -i "/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" /etc/pam.d/common-password' "Enforce password complexity (14 char min)"
run_cmd 'grep -q "pam_pwhistory.so" /etc/pam.d/common-password || echo "password required pam_pwhistory.so remember=5 use_authtok" >> /etc/pam.d/common-password' "Prevent password reuse (last 5)"

cat > /etc/profile.d/session-timeout.sh << 'EOF'
# CIS 5.4: 30-minute inactivity timeout
readonly TMOUT=1800
export TMOUT
EOF
chmod +x /etc/profile.d/session-timeout.sh

run_cmd 'grep -q "umask 027" /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc' "Set bash umask 027"
run_cmd "awk -F: '(\$2 == \"\") { print \$1 }' /etc/shadow | xargs -r -n 1 passwd -l" "Lock empty-password accounts"

# ===============[ SECTION 6: Logging & Auditing ]===============

start_section "6.1 — auditd"
run_cmd "apt-get install -y auditd audispd-plugins" "Install auditd"
run_cmd "systemctl enable --now auditd" "Enable and start auditd"

cat > /etc/audit/rules.d/50-cis-hardening.rules << 'EOF'
-D
-b 8192
-f 1

# Audit log access
-w /var/log/audit/ -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools

# Time changes
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time

# User/group modifications
-w /etc/group  -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow  -k etcpasswd
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/useradd  -p x -k user_modification
-w /usr/sbin/usermod  -p x -k user_modification

# Privilege escalation
-w /bin/su          -p x  -k priv_esc
-w /usr/bin/sudo    -p x  -k priv_esc
-w /etc/sudoers     -p rw -k priv_esc
-w /etc/sudoers.d   -p wa -k scope

# Login events
-w /etc/login.defs     -p wa -k login
-w /var/log/faillog    -p wa -k login
-w /var/log/lastlog    -p wa -k login
-w /var/run/faillock   -p wa -k logins

# Network config
-w /etc/hosts   -p wa -k system-locale
-w /etc/network -p wa -k system-locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale

# SSH config changes
-w /etc/ssh/sshd_config    -k sshd
-w /etc/ssh/sshd_config.d/ -k sshd

# PAM changes
-w /etc/pam.d/             -p wa -k pam
-w /etc/security/limits.conf -p wa -k pam

# AppArmor policy
-w /etc/apparmor/   -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy

# Sessions
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session

# Root commands
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd

# User emulation (sudo -u)
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation

# Module loading
-w /sbin/insmod  -p x -k modules
-w /sbin/rmmod   -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/bin/kmod  -p x -k modules

# Process execution
-w /usr/bin/ -p x -k processes
-a always,exit -F arch=b64 -S execve -k processes

# Power events
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot   -p x -k power
-w /sbin/halt     -p x -k power
EOF
run_cmd "augenrules --load 2>/dev/null || service auditd restart" "Load audit rules"

cat > /etc/audit/auditd.conf << 'EOF'
local_events = yes
write_logs = yes
log_file = /var/log/audit/audit.log
log_group = adm
log_format = RAW
flush = INCREMENTAL_ASYNC
freq = 50
max_log_file = 50
max_log_file_action = rotate
num_logs = 10
priority_boost = 4
space_left = 75
space_left_action = syslog
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = rotate
disk_error_action = syslog
EOF
run_cmd "chmod 640 /etc/audit/auditd.conf" "Secure auditd.conf permissions"

start_section "6.2 — rsyslog"
run_cmd "apt-get install -y rsyslog" "Install rsyslog"
run_cmd "systemctl enable --now rsyslog" "Enable rsyslog"
cat > /etc/rsyslog.d/50-hardening.conf << 'EOF'
*.emerg :omusrmsg:*
auth,authpriv.* /var/log/auth.log
EOF
run_cmd "chmod 640 /etc/rsyslog.d/50-hardening.conf" "Secure rsyslog config"
run_cmd "systemctl restart rsyslog" "Restart rsyslog"

start_section "6.3 — Log rotation & journald"
cat > /etc/logrotate.d/sudo << 'EOF'
/var/log/sudo.log {
    rotate 12
    monthly
    compress
    missingok
    notifempty
}
EOF

mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/hardening.conf << 'EOF'
[Journal]
Storage=persistent
SystemMaxUse=500M
ForwardToSyslog=yes
Compress=yes
EOF
run_cmd "systemctl restart systemd-journald" "Restart journald with persistent storage"

start_section "6.4 — Process accounting"
run_cmd "apt-get install -y acct" "Install process accounting (acct)"
run_cmd "systemctl enable acct || true" "Enable process accounting"

start_section "6.5 — AIDE file integrity"
run_cmd "apt-get install -y aide aide-common" "Install AIDE"
run_cmd "aideinit --yes --force || true" "Initialise AIDE database (slow — full filesystem scan)"
run_cmd "cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true" "Activate AIDE database"
echo "0 5 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" > /etc/cron.d/aide
run_cmd "chmod 644 /etc/cron.d/aide" "Schedule daily AIDE integrity check (05:00)"

# ===============[ SECTION 7: File Permissions ]===============

start_section "7.1 — Critical file permissions"
run_cmd "chmod 644 /etc/passwd  && chown root:root   /etc/passwd"  "Secure /etc/passwd"
run_cmd "chmod 000 /etc/shadow  && chown root:shadow /etc/shadow"  "Lock /etc/shadow"
run_cmd "chmod 644 /etc/group   && chown root:root   /etc/group"   "Secure /etc/group"
run_cmd "chmod 000 /etc/gshadow && chown root:shadow /etc/gshadow" "Lock /etc/gshadow"
run_cmd "chmod 600 /etc/passwd- && chown root:root   /etc/passwd-" "Secure /etc/passwd- backup"
run_cmd "chmod 600 /etc/shadow- && chown root:shadow /etc/shadow-" "Secure /etc/shadow- backup"
run_cmd "chmod 600 /etc/group-  && chown root:root   /etc/group-"  "Secure /etc/group- backup"
run_cmd "chmod 600 /etc/gshadow-&& chown root:shadow /etc/gshadow-" "Secure /etc/gshadow- backup"

start_section "7.2 — Log file permissions"
run_cmd 'find /var/log -type f -exec chmod 640 {} \;' "Restrict log file permissions"
run_cmd 'find /var/log -type d -exec chmod 750 {} \;' "Restrict log dir permissions"
run_cmd "touch /var/log/sudo.log && chmod 640 /var/log/sudo.log" "Secure sudo log"

# ===============[ SECTION 8: Additional Tooling ]===============

start_section "8.1 — fail2ban"
run_cmd "apt-get install -y fail2ban" "Install fail2ban"
cat > /etc/fail2ban/jail.d/hardening.conf << 'EOF'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd

[sshd]
enabled = true
port    = ssh
EOF
run_cmd "systemctl enable --now fail2ban" "Enable fail2ban"

start_section "8.2 — msmtp (lightweight SMTP client)"
run_cmd "apt-get install -y msmtp msmtp-mta" "Install msmtp + MTA shim"
if [[ -f /tmp/smtp.env ]]; then
    # shellcheck source=/dev/null
    source /tmp/smtp.env
    cat > /etc/msmtprc << EOF
# System-wide msmtp configuration
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        /var/log/msmtp.log

account        default
host           ${SMTP_HOST}
port           ${SMTP_PORT:-587}
from           ${SMTP_FROM}
user           ${SMTP_USER}
password       ${SMTP_PASS}
EOF
    chmod 640 /etc/msmtprc
    chown root:mail /etc/msmtprc
    # Wire msmtp as the system MTA
    update-alternatives --set mta /usr/bin/msmtp 2>/dev/null || true
    rm -f /tmp/smtp.env
    log_ok "msmtp configured with provided SMTP credentials."
else
    log_ok "No /tmp/smtp.env found — msmtp installed but not configured. Set SMTP_* in .env to enable."
fi

start_section "8.3 — logwatch (daily security digest)"
run_cmd "apt-get install -y logwatch" "Install logwatch"
cat > /etc/logwatch/conf/logwatch.conf << 'EOF'
Output = mail
Format = html
MailTo = root
MailFrom = logwatch
Detail = Med
Service = All
Range = yesterday
EOF
run_cmd "chmod 644 /etc/logwatch/conf/logwatch.conf" "Configure logwatch"

start_section "8.4 — needrestart (post-upgrade service restarter)"
run_cmd "apt-get install -y needrestart" "Install needrestart"
# Set automatic (non-interactive) mode
run_cmd "sed -i 's/^#\$nrconf{restart}.*$/\$nrconf{restart} = \"a\";/' /etc/needrestart/needrestart.conf || true" "Configure needrestart auto-restart mode"

start_section "8.5 — rkhunter (rootkit detection)"
run_cmd "apt-get install -y rkhunter" "Install rkhunter"
run_cmd "rkhunter --update || true" "Update rkhunter data files"
run_cmd "rkhunter --propupd" "Build rkhunter baseline (initial file properties)"
# Schedule nightly scan
echo "30 3 * * * root rkhunter --check --skip-keypress --report-warnings-only 2>&1 | mail -s 'rkhunter report' root" > /etc/cron.d/rkhunter
run_cmd "chmod 644 /etc/cron.d/rkhunter" "Schedule nightly rkhunter scan (03:30)"

start_section "8.6 — Podman (rootless container runtime)"
run_cmd "apt-get install -y podman uidmap slirp4netns fuse-overlayfs" "Install Podman + rootless deps"

# Detect the provisioned user (non-root, non-system, has home dir)
PODMAN_USER=$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 != "/usr/sbin/nologin" {print $1}' /etc/passwd | head -1)
if [[ -n "$PODMAN_USER" ]]; then
    run_cmd "loginctl enable-linger $PODMAN_USER" "Enable systemd linger for $PODMAN_USER (rootless Podman)"
    run_cmd "su - $PODMAN_USER -c 'podman system migrate' 2>/dev/null || true" "Migrate Podman storage for $PODMAN_USER"
    log_ok "Rootless Podman configured for user: $PODMAN_USER"
else
    log_err "Could not detect provisioned user for Podman setup"
fi

# ===============[ Final Summary ]===============
echo ""
echo "[$(date '+%H:%M:%S')] ===[ Phase 2 Complete ]=============================="
echo ""
echo "Error summary:"
grep -r "\[✗\]" "$LOG_DIR/sections/" 2>/dev/null | tee "$LOG_DIR/error_summary.log" || echo "  (none)"
echo ""
echo "Full logs: $LOG_DIR"
