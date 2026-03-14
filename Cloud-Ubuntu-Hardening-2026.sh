#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

# Global Variables
LOG_DIR="/home/${SUDO_USER:-root}/setup_logs/hardening.log"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
CURRENT_SECTION=""

# Setup directories
mkdir -p "$LOG_DIR/section_logs"

# Logging functions
start_section() {
    CURRENT_SECTION="$1"
    echo "[$(date '+%H:%M:%S')] Starting SECTION $CURRENT_SECTION" | tee -a "$LOG_DIR/main.log"
    mkdir -p "$LOG_DIR/section_logs/$CURRENT_SECTION"
}

log_success() {
    echo "  [✓] $1" | tee -a "$LOG_DIR/section_logs/$CURRENT_SECTION/success.log"
}

log_error() {
    echo "  [✗] $1" | tee -a "$LOG_DIR/section_logs/$CURRENT_SECTION/error.log"
}

run_command() {
    local cmd="$1"
    local desc="$2"

    echo "Executing: $desc"
    # To catch errors properly but not fail script if we use || true
    if ! output=$(eval "$cmd" 2>&1); then
        log_error "Failed to execute '$cmd': $output"
    else
        log_success "$desc"
        echo -e "\n$output\n" >> "$LOG_DIR/section_logs/$CURRENT_SECTION.log"
    fi
}

echo "Starting Hardening Script..."

# ===============[ SECTION 1: Initial Setup ]===============
start_section "1.1"
run_command 'for fs in cramfs freevxfs hfs hfsplus squashfs udf jffs2 usb-storage; do echo "install $fs /bin/false" > /etc/modprobe.d/disable_${fs}.conf; rmmod $fs 2>/dev/null || true; done' "1.1.1 Disable unnecessary filesystems"
run_command "systemctl mask autofs 2>/dev/null || true" "1.1.2 Disable autofs service"

start_section "1.2"
run_command "apt update && apt upgrade -y" "1.2.1 Update system packages"
run_command "chown root:root /boot/grub/grub.cfg" "1.2.2 Set grub.cfg ownership"
run_command "chmod og-rwx /boot/grub/grub.cfg" "1.2.3 Set grub.cfg permissions"

start_section "1.3"
run_command "apt install -y apparmor-utils apparmor-profiles apparmor-profiles-extra" "1.3.1 Install AppArmor"
run_command "echo 'Enabling in Complain all AppArmor profiles'" "1.3.2 Set AppArmor profiles to complain mode"
for profile in /etc/apparmor.d/*; do
  if [ -f "$profile" ] && grep -q '^profile ' "$profile"; then
    run_command "aa-complain \"$profile\" >/dev/null 2>&1 || true" "Complain mode for $profile"
  fi
done
run_command 'echo "kernel.randomize_va_space = 2" > /etc/sysctl.d/60-aslr.conf' "1.3.3 Enable ASLR"
run_command 'echo "kernel.yama.ptrace_scope = 1" > /etc/sysctl.d/60-yama.conf' "1.3.4 Restrict ptrace"
run_command "sysctl --system" "1.3.5 Apply kernel settings"

start_section "1.4"
run_command 'grep -q "* hard core 0" /etc/security/limits.conf 2>/dev/null || echo "* hard core 0" >> /etc/security/limits.conf' "1.4.1 Disable core dumps"
run_command 'echo "fs.suid_dumpable = 0" > /etc/sysctl.d/60-coredump.conf' "1.4.2 Disable suid dumping"
run_command "sysctl -p /etc/sysctl.d/60-coredump.conf" "1.4.3 Apply coredump settings"

start_section "1.5"
run_command "dpkg -l prelink >/dev/null 2>&1 && apt purge -y prelink || true" "1.5.1 Remove prelink"
run_command "dpkg -l apport >/dev/null 2>&1 && apt purge -y apport || true" "1.5.2 Remove apport"
run_command "apt install -y unattended-upgrades" "1.5.2 Install unattended-upgrades"

start_section "1.6"
BANNER=$(cat << 'EOF'
******************************************************
*                                                    *
*          Authorized Access Only                    *
*                                                    *
******************************************************

This system is for authorized use only. Unauthorized access or use is prohibited and may result in disciplinary action and/or civil and criminal penalties.

All activities on this system are subject to monitoring and recording. By using this system, you expressly consent to such monitoring and recording.

Legal Notice:
-------------
Use of this system constitutes consent to security monitoring and testing. All activities are logged and monitored.
Unauthorized access, use, or modification of this system or its data may result in disciplinary action, civil, and/or criminal penalties.

**Important Security Measures:**
1. **Do not share your login credentials.**
2. **Report any suspicious activity to IT security immediately.**
3. **Adhere to the security policies and guidelines.**
EOF
)
run_command "echo '$BANNER' > /etc/issue.net" "1.6.1 Set login banner"
run_command "echo '$BANNER' > /etc/issue" "1.6.1 Set login banner"
run_command "echo '$BANNER' > /etc/motd" "1.6.1 Set login banner"
run_command "chmod -x /etc/update-motd.d/* 2>/dev/null || true" "1.6.1 Disable standard motd scripts"
run_command "chmod 644 /etc/issue.net /etc/issue /etc/motd" "1.6.2 Set banner permissions"
run_command "chown root:root /etc/issue.net /etc/issue /etc/motd" "1.6.3 Set banner ownership"

start_section "1.7"
run_command "dpkg -l gdm3 >/dev/null 2>&1 && apt purge -y gdm3 || true" "1.7.1 Remove GDM3 if installed"

start_section "1.8"
run_command 'grep -q "/tmp tmpfs" /etc/fstab || echo "tmpfs /tmp tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab' "1.8.1 Mount /tmp as tmpfs"
run_command 'grep -q "/dev/shm tmpfs" /etc/fstab || echo "tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0" >> /etc/fstab' "1.8.2 Mount /dev/shm as tmpfs"
run_command 'grep -q "/var/tmp none" /etc/fstab || echo "/tmp /var/tmp none bind 0 0" >> /etc/fstab' "1.8.3 Bind mount /var/tmp to /tmp"
run_command 'mount -a || true' "1.8.4 Apply fstab mounts safely"

# ===============[ SECTION 2: Services ]===============
start_section "2.1"
services=(
    avahi-daemon autofs isc-dhcp-server bind9 dnsmasq vsftpd slapd
    nfs-kernel-server ypserv cups rpcbind rsync samba snmpd tftpd-hpa
    squid apache2 nginx xinetd xserver-common telnetd postfix
    nis rsh-client talk talkd telnet inetutils-telnet ldap-utils ftp tnftp lp
)
for service in "${services[@]}"; do
    run_command "dpkg -l $service >/dev/null 2>&1 && apt purge -y $service || true" "2.1.1 Remove $service"
done

start_section "2.4"
run_command "dpkg -l chrony >/dev/null 2>&1 && apt purge -y chrony || true" "2.4.1 Remove Chrony"
run_command "grep -q '^\\[Time\\]' /etc/systemd/timesyncd.conf || echo '[Time]' >> /etc/systemd/timesyncd.conf" "2.4.2 Configure timesyncd"
run_command "sed -i '/^\\[Time\\]/!b; /NTP=time-a/! a\\NTP=time-a-wwv.nist.gov time-d-wwv.nist.gov' /etc/systemd/timesyncd.conf" "2.4.3 Set NTP servers"
run_command "sed -i '/^\\[Time\\]/!b; /FallbackNTP=time-b/! a\\FallbackNTP=time-b-wwv.nist.gov time-c-wwv.nist.gov' /etc/systemd/timesyncd.conf" "2.4.4 Set fallback NTP"
run_command "systemctl restart systemd-timesyncd" "2.4.5 Restart timesync"
run_command "systemctl enable systemd-timesyncd" "2.4.6 Enable timesync"

start_section "2.5"
run_command "chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d" "2.5.1 Set cron ownership"
run_command "chmod og-rwx /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d" "2.5.2 Set cron permissions"

# ===============[ SECTION 3: Network Configuration ]===============
start_section "3.1"
run_command 'echo "net.ipv6.conf.all.disable_ipv6 = 1" > /etc/sysctl.d/60-ipv6.conf' "3.1.1 Disable IPv6"
run_command 'echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.d/60-ipv6.conf' "3.1.2 Disable IPv6 default"
run_command 'echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.d/60-ipv6.conf' "3.1.3 Disable IPv6 loopback"
run_command "sysctl -p /etc/sysctl.d/60-ipv6.conf || true" "3.1.4 Apply IPv6 settings"
run_command "dpkg -l bluez >/dev/null 2>&1 && apt purge -y bluez bluetooth || true" "3.1.5 Remove Bluetooth"

start_section "3.2"
modules=(dccp tipc rds sctp)
for mod in "${modules[@]}"; do
    run_command "echo 'install $mod /bin/false' > /etc/modprobe.d/disable_$mod.conf" "3.2.1 Disable $mod"
    run_command "modprobe -r $mod 2>/dev/null || true" "3.2.2 Unload $mod"
done

start_section "3.3"
cat << 'EOF' > /etc/sysctl.d/60-net.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
EOF
run_command "sysctl -p /etc/sysctl.d/60-net.conf" "3.3.8 Apply network settings"

# ===============[ SECTION 4: Host Based Firewall ]===============
start_section "4.1"
run_command "dpkg -l iptables-persistent >/dev/null 2>&1 && apt purge -y iptables-persistent || true" "4.1.1 Remove iptables-persistent"
run_command "ufw --force enable" "4.1.2 Enable UFW"
run_command "ufw allow in on lo" "4.1.3 Allow loopback inbound"
run_command "ufw allow out on lo" "4.1.4 Allow loopback outbound"
run_command "ufw deny in from 127.0.0.0/8" "4.1.5 Block external loopback"
run_command "ufw allow in from 192.168.10.0/24" "4.1.5 Allow internal network"
run_command "ufw default deny incoming" "4.1.6 Default deny incoming"
run_command "ufw default allow outgoing" "4.1.7 Default allow outgoing"
run_command "ufw deny in from ::1" "4.1.8 Block IPv6 loopback"


# ===============[ SECTION 5: Configure SSH Server ]===============
start_section "5.1"
SSH_CONF=$(cat << 'EOF'
Include /etc/ssh/sshd_config.d/*.conf
LogLevel VERBOSE
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
IgnoreRhosts yes
PermitEmptyPasswords no
KbdInteractiveAuthentication no
UsePAM yes
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
TCPKeepAlive no
PermitUserEnvironment no
ClientAliveCountMax 2
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server
LoginGraceTime 60
MaxStartups 10:30:60
ClientAliveInterval 15
Banner /etc/issue.net
Ciphers -3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,chacha20-poly1305@openssh.com
DisableForwarding yes
GSSAPIAuthentication no
HostbasedAuthentication no
IgnoreRhosts yes
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
KexAlgorithms -diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha1
MACs -hmac-md5,hmac-md5-96,hmac-ripemd160,hmac-sha1-96,umac-64@openssh.com,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-ripemd160-etm@openssh.com,hmac-sha1-96-etm@openssh.com,umac-64-etm@openssh.com,umac-128-etm@openssh.com
PermitUserEnvironment no
EOF
)
run_command "echo '$SSH_CONF' > /etc/ssh/sshd_config" "5.1.* Configuration of SSH server"
run_command "sudo systemctl enable ssh" "5.1.1 Enable SSH service"
run_command "sudo systemctl restart ssh" "5.1.2 Restart SSH service"

start_section "5.2"
run_command 'echo "Defaults logfile=/var/log/sudo.log" > /etc/sudoers.d/01_base' "5.2.1 Configure sudo logging"
run_command 'echo "Defaults log_input,log_output" >> /etc/sudoers.d/01_base' "5.2.2 Configure sudo I/O logging"
run_command 'echo "Defaults use_pty" >> /etc/sudoers.d/01_base' "5.2.3 Enable sudo PTY constraint"
run_command 'echo "Defaults env_reset, timestamp_timeout=15" >> /etc/sudoers.d/01_base' "5.2.6 Reset in 15 minutes"
run_command 'chmod 440 /etc/sudoers.d/01_base' "5.2.4 Set sudoers file permissions"
run_command 'visudo -c -f /etc/sudoers.d/01_base' "5.2.5 Validate sudoers syntax"

start_section "5.4"
run_command 'sed -i "/^PASS_MAX_DAYS/c\PASS_MAX_DAYS 180" /etc/login.defs' "5.4.1.1 Set password max days to 180"
run_command 'sed -i "/^PASS_MIN_DAYS/c\PASS_MIN_DAYS 7" /etc/login.defs' "5.4.1.1 Set password min days to 7"
run_command 'sed -i "/^PASS_WARN_AGE/c\PASS_WARN_AGE 14" /etc/login.defs' "5.4.1.1 Set password warning age to 14"
run_command 'useradd -D -f 30' "5.4.1.2 Set inactive account lock to 30 days"

run_command 'apt install -y libpam-pwquality' "5.4.1.3 Install pam_pwquality"
run_command 'sed -i "s/^PasswordAuthentication.*/PasswordAuthentication no/" /etc/ssh/sshd_config' "5.4.1.4 Ensure PasswordAuthentication is disabled for SSH"
run_command 'grep -q "pam_faillock.so" /etc/pam.d/common-auth || sed -i "/pam_unix.so/i auth required pam_faillock.so preauth silent deny=4 unlock_time=900\nauth [default=die] pam_faillock.so authfail deny=4 unlock_time=900\nauth sufficient pam_faillock.so authsucc deny=4 unlock_time=900" /etc/pam.d/common-auth' "5.4.1.5 Configure faillock (4 attempts, 15 min lock)"

run_command 'grep -q "pam_pwquality.so" /etc/pam.d/common-password || sed -i "/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1" /etc/pam.d/common-password' "5.4.1.6 Enforce password complexity"

run_command 'grep -q "pam_pwhistory.so" /etc/pam.d/common-password || echo "password required pam_pwhistory.so remember=5 use_authtok" >> /etc/pam.d/common-password' "5.4.1.7 Limit password reuse (5)"
run_command 'sed -i "/^ENCRYPT_METHOD/c\ENCRYPT_METHOD SHA512" /etc/login.defs' "5.4.1.8 Set password hashing to SHA512"
run_command 'sed -i "/^UMASK/c\UMASK 077" /etc/login.defs' "5.4.2 Set default umask to 077"

cat << 'EOF' > /etc/profile.d/timeout.sh
readonly TMOUT=1800
export TMOUT
EOF

run_command 'chmod +x /etc/profile.d/timeout.sh' "5.4.2 Make timeout script executable"
run_command 'passwd -l root' "5.4.3 Lock root account"
run_command 'grep -q "umask 027" /etc/bash.bashrc || echo "umask 027" >> /etc/bash.bashrc' "5.4.4 Set bash default umask"
run_command 'grep -q "umask 027" /root/.bash_profile 2>/dev/null || echo "umask 027" >> /root/.bash_profile' "5.4.4 Set bash default root umask"
run_command 'grep -q "umask 027" /root/.bashrc 2>/dev/null || echo "umask 027" >> /root/.bashrc' "5.4.4 Set bash default root umask"

run_command "awk -F: '(\$2 == \"\") { print \$1 }' /etc/shadow | xargs -r -n 1 passwd -l" "5.5.6 Lock empty password accounts"
run_command 'grep "^+:" /etc/passwd | tee /var/log/legacy_passwd_entries.log' "5.5.2 Audit legacy NIS entries (passwd)"
run_command 'awk -F: '\''($3 == 0) { print $1 }'\'' /etc/passwd | grep -v "^root$" | tee /var/log/uid0_accounts.log' "5.5.3 Audit duplicate UID 0 accounts"
# Fixed the quoting issue in awk
run_command 'awk -F: '\''$3=="0"{print $1":"$3}'\'' /etc/group | tee /var/log/gid0_accounts.log' "5.5.4 Audit duplicate GID 0 accounts"

# ===============[ SECTION 6: Logging and Auditing ]===============
start_section "6.1"

run_command 'apt install -y auditd audispd-plugins' "6.1.1 Install auditd"
run_command 'systemctl --now enable auditd' "6.1.1 Enable auditd service"

RULES=$(cat << 'EOF'
-D
-b 8192
-f 1
-w /var/log/audit/ -k auditlog
-w /etc/audit/ -p wa -k auditconfig
-w /etc/libaudit.conf -p wa -k auditconfig
-w /etc/audisp/ -p wa -k audispconfig
-w /sbin/auditctl -p x -k audittools
-w /sbin/auditd -p x -k audittools
-a exit,always -F arch=b32 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b64 -S mknod -S mknodat -k specialfiles
-a exit,always -F arch=b32 -S mount -S umount -S umount2 -k mount
-a exit,always -F arch=b64 -S mount -S umount2 -k mount
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S clock_settime -k time
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time
-w /usr/sbin/stunnel -p x -k stunnel
-w /etc/cron.allow -p wa -k cron
-w /etc/cron.deny -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /etc/crontab -p wa -k cron
-w /etc/group -p wa -k etcgroup
-w /etc/passwd -p wa -k etcpasswd
-w /etc/gshadow -k etcgroup
-w /etc/shadow -k etcpasswd
-w /etc/security/opasswd -k opasswd
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /usr/sbin/addgroup -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/adduser -p x -k user_modification
-w /etc/login.defs -p wa -k login
-w /etc/securetty -p wa -k login
-w /var/log/faillog -p wa -k login
-w /var/log/lastlog -p wa -k login
-w /var/log/tallylog -p wa -k login
-w /etc/hosts -p wa -k hosts
-w /etc/network/ -p wa -k network
-w /etc/inittab -p wa -k init
-w /etc/init.d/ -p wa -k init
-w /etc/init/ -p wa -k init
-w /etc/ld.so.conf -p wa -k libpath
-w /etc/localtime -p wa -k localtime
-w /etc/sysctl.conf -p wa -k sysctl
-w /etc/modprobe.conf -p wa -k modprobe
-w /etc/pam.d/ -p wa -k pam
-w /etc/security/limits.conf -p wa  -k pam
-w /etc/security/pam_env.conf -p wa -k pam
-w /etc/security/namespace.conf -p wa -k pam
-w /etc/security/namespace.init -p wa -k pam
-w /etc/aliases -p wa -k mail
-w /etc/postfix/ -p wa -k mail
-w /etc/ssh/sshd_config -k sshd
-a exit,always -F arch=b32 -S sethostname -k hostname
-a exit,always -F arch=b64 -S sethostname -k hostname
-w /etc/issue -p wa -k etcissue
-w /etc/issue.net -p wa -k etcissue
-a exit,always -F arch=b64 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b32 -F euid=0 -S execve -k rootcmd
-a exit,always -F arch=b64 -S open -F dir=/etc -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/bin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/usr/sbin -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/var -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/home -F success=0 -k unauthedfileacess
-a exit,always -F arch=b64 -S open -F dir=/srv -F success=0 -k unauthedfileacess
-w /bin/su -p x -k priv_esc
-w /usr/bin/sudo -p x -k priv_esc
-w /etc/sudoers -p rw -k priv_esc
-w /sbin/shutdown -p x -k power
-w /sbin/poweroff -p x -k power
-w /sbin/reboot -p x -k power
-w /sbin/halt -p x -k power
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d -p wa -k scope
-a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/networks -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock -p wa -k logins
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
EOF
)
run_command "echo '$RULES' > /etc/audit/rules.d/50-scope.rules" "6.1.2 Configure audit rules"

# 6.1.3 - Configure auditd storage
cat << 'EOF' > /etc/audit/auditd.conf
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
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = rotate
disk_error_action = syslog
tcp_listen_queue = 5
tcp_max_per_addr = 1
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
EOF
run_command "chmod 640 /etc/audit/auditd.conf" "6.1.3 Configure auditd log storage"

start_section "6.2"

# 6.2.1 - Configure rsyslog
run_command 'apt install -y rsyslog' "6.2.1 Install rsyslog"
run_command 'systemctl --now enable rsyslog' "6.2.1 Enable rsyslog"

# 6.2.2 - Configure logging
cat << 'EOF' > /etc/rsyslog.d/50-remote.conf
*.emerg :omusrmsg:*
mail.* -/var/log/mail.log
auth,authpriv.* /var/log/auth.log
EOF
run_command "chmod 644 /etc/rsyslog.d/50-remote.conf" "6.2.2 Configure rsyslog logging rules"

# 6.2.3 - Configure log permissions
run_command 'find /var/log -type f -exec chmod 640 {} \;' "6.2.3 Secure log file permissions"
run_command 'find /var/log -type d -exec chmod 750 {} \;' "6.2.3 Secure log directory permissions"
run_command 'chmod 640 /var/log/sudo.log' "6.2.3 Secure sudo log"

start_section "6.3"

# 6.3.1 - Configure logrotate
cat << 'EOF' > /etc/logrotate.d/sudo
/var/log/sudo.log {
  rotate 12
  monthly
  compress
  missingok
}
EOF
run_command "chmod 644 /etc/logrotate.d/sudo" "6.3.1 Configure sudo log rotation"

# 6.3.2 - Configure systemd-journal
cat << 'EOF' > /etc/systemd/journald.conf.d/hardening.conf
[Journal]
Storage=persistent
SystemMaxUse=250M
ForwardToSyslog=yes
Compress=yes
EOF
run_command 'systemctl restart systemd-journald' "6.3.2 Restart journald"

start_section "6.4"

# 6.4.1 - Enable process accounting
run_command 'apt install -y acct' "6.4.1 Install process accounting"
run_command 'systemctl enable acct' "6.4.1 Enable process accounting"

# 6.4.2 - Configure auditd process tracking
cat << 'EOF' > /etc/audit/rules.d/50-processes.rules
-w /usr/bin/ -p x -k processes
-a always,exit -F arch=b64 -S execve -k processes
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-w /usr/bin/kmod -p x -k modules
EOF
run_command 'service auditd restart' "6.4.2 Reload audit rules"

# ===============[ SECTION 6.5: AIDE Integrity Checking ]===============
start_section "6.5"
run_command 'apt install -y aide aide-common' "6.5.1 Install AIDE"
run_command 'aideinit --yes --force || true' "6.5.2 Initialize AIDE Database (may take time)"
run_command 'cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db || true' "6.5.3 Activate AIDE Database"
run_command 'echo "0 5 * * * root /usr/bin/aide.wrapper --config /etc/aide/aide.conf --check" > /etc/cron.d/aide' "6.5.4 Schedule daily AIDE check"

# ===============[ SECTION 7: File Permissions ]===============
start_section "7.1"
run_command 'chmod 644 /etc/passwd' "7.1.1 Set /etc/passwd permissions (644)"
run_command 'chown root:root /etc/passwd' "7.1.1 Verify /etc/passwd ownership"
run_command 'chmod 000 /etc/shadow' "7.1.2 Lock /etc/shadow permissions (000)"
run_command 'chown root:shadow /etc/shadow' "7.1.2 Set /etc/shadow ownership"
run_command 'chmod 644 /etc/group' "7.1.3 Set /etc/group permissions (644)"
run_command 'chown root:root /etc/group' "7.1.3 Verify /etc/group ownership"
run_command 'chmod 000 /etc/gshadow' "7.1.4 Lock /etc/gshadow permissions (000)"
run_command 'chown root:shadow /etc/gshadow' "7.1.4 Set /etc/gshadow ownership"
run_command 'chmod 600 /etc/passwd-' "7.1.5 Secure /etc/passwd- backup (600)"
run_command 'chown root:root /etc/passwd-' "7.1.5 Verify /etc/passwd- ownership"
run_command 'chmod 600 /etc/shadow-' "7.1.6 Secure /etc/shadow- backup (600)"
run_command 'chown root:shadow /etc/shadow-' "7.1.6 Set /etc/shadow- ownership"
run_command 'chmod 600 /etc/group-' "7.1.7 Secure /etc/group- backup (600)"
run_command 'chown root:root /etc/group-' "7.1.7 Verify /etc/group- ownership"
run_command 'chmod 600 /etc/gshadow-' "7.1.8 Secure /etc/gshadow- backup (600)"
run_command 'chown root:shadow /etc/gshadow-' "7.1.8 Set /etc/gshadow- ownership"

# Final report
echo -e "\nHardening complete. Summary of errors:"
grep -r "[✗]" "$LOG_DIR/section_logs/" | tee "$LOG_DIR/error_summary.log"
echo -e "\nFull logs available in: $LOG_DIR"
