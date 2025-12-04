# SYSTEM-LEVEL OPSEC FRAMEWORK
## Complete Computer Protection & Hardening Guide

```
Copyright © 2025 Security Research Operations
All Rights Reserved.

PROPRIETARY AND CONFIDENTIAL
```

---

## 🛡️ EXECUTIVE SUMMARY

This framework extends OPSEC protection from bug bounty operations to your **entire computer system**, providing military-grade security for:

- **Operating System Hardening**
- **Network Security & Privacy**
- **File System Protection**
- **Malware & Intrusion Prevention**
- **Data Encryption**
- **Privacy Protection**
- **Anti-Forensics**
- **Endpoint Security**

---

## TABLE OF CONTENTS

1. [System Hardening](#system-hardening)
2. [Network Protection](#network-protection)
3. [File System Security](#file-system-security)
4. [Privacy Protection](#privacy-protection)
5. [Malware Prevention](#malware-prevention)
6. [Data Encryption](#data-encryption)
7. [Monitoring & Detection](#monitoring--detection)
8. [Anti-Forensics](#anti-forensics)
9. [Emergency Response](#emergency-response)
10. [Automation](#automation)

---

## SYSTEM HARDENING

### Windows Security (WSL Environment)

#### Disable Unnecessary Services
```powershell
# Run as Administrator
# Disable Remote Desktop (if not needed)
Stop-Service -Name "TermService" -Force
Set-Service -Name "TermService" -StartupType Disabled

# Disable Remote Registry
Stop-Service -Name "RemoteRegistry" -Force
Set-Service -Name "RemoteRegistry" -StartupType Disabled

# Disable Windows Remote Management
Stop-Service -Name "WinRM" -Force
Set-Service -Name "WinRM" -StartupType Disabled
```

#### Windows Firewall Hardening
```powershell
# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Block all inbound by default
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block

# Allow outbound by default (but monitor)
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow

# Enable logging
Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True -LogBlocked True
```

### Linux/WSL Hardening

#### Secure SSH Configuration
```bash
# Edit /etc/ssh/sshd_config
sudo tee /etc/ssh/sshd_config.d/opsec_hardening.conf <<EOF
# OPSEC SSH Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers yourusername
EOF
```

#### Kernel Hardening
```bash
# Create sysctl hardening config
sudo tee /etc/sysctl.d/99-opsec-hardening.conf <<EOF
# OPSEC Kernel Hardening

# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable SYN cookies
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Disable IPv6 (if not needed)
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Protect against TCP time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Increase system file descriptor limit
fs.file-max = 65535

# Protect kernel pointers
kernel.kptr_restrict = 2

# Restrict kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel performance events
kernel.perf_event_paranoid = 3
EOF

# Apply settings
sudo sysctl -p /etc/sysctl.d/99-opsec-hardening.conf
```

#### File System Hardening
```bash
# Set restrictive umask
echo "umask 077" >> ~/.bashrc
echo "umask 077" >> ~/.profile

# Secure /tmp, /var/tmp
sudo tee -a /etc/fstab <<EOF
tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0
tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev 0 0
EOF
```

---

## NETWORK PROTECTION

### Firewall Configuration (UFW)

```bash
# Install and configure UFW
sudo apt-get install -y ufw

# Default policies: deny incoming, allow outgoing
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow only essential services
# sudo ufw allow 22/tcp  # SSH (only if needed)
# sudo ufw allow from 192.168.1.0/24 to any port 22  # Restrict to local network

# Enable firewall
sudo ufw enable

# Enable logging
sudo ufw logging high
```

### Network Monitoring

```bash
# Install monitoring tools
sudo apt-get install -y nethogs iftop tcpdump

# Monitor active connections
sudo netstat -tulpn

# Monitor bandwidth usage
sudo iftop

# Check for suspicious connections
sudo ss -tunap | grep ESTABLISHED
```

### DNS Security

```bash
# Use encrypted DNS (DNS over HTTPS)
# Configure in /etc/resolv.conf or use systemd-resolved

# Option 1: Cloudflare DNS
sudo tee /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 1.0.0.1
options edns0 trust-ad
EOF

# Option 2: Quad9 (privacy-focused)
# nameserver 9.9.9.9
# nameserver 149.112.112.112

# Make immutable to prevent changes
sudo chattr +i /etc/resolv.conf
```

---

## FILE SYSTEM SECURITY

### File Integrity Monitoring (AIDE)

```bash
# Install AIDE
sudo apt-get install -y aide

# Initialize database
sudo aideinit

# Move database
sudo mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Run daily checks (cron)
echo "0 4 * * * root /usr/bin/aide --check | mail -s 'AIDE Integrity Check' root" | sudo tee -a /etc/crontab
```

### Secure File Permissions

```bash
# Audit and fix permissions
# World-writable files (dangerous)
sudo find / -xdev -type f -perm -0002 -ls 2>/dev/null

# Files without owner
sudo find / -xdev -nouser -ls 2>/dev/null

# SUID/SGID files (potential privilege escalation)
sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -ls 2>/dev/null

# Secure home directory
chmod 700 ~
chmod 600 ~/.ssh/*
chmod 644 ~/.ssh/*.pub
chmod 700 ~/.ssh
```

### Encrypted Directories

```bash
# Install eCryptfs
sudo apt-get install -y ecryptfs-utils

# Create encrypted private directory
mkdir -p ~/Private
sudo mount -t ecryptfs ~/Private ~/Private

# Auto-mount on login (add to ~/.profile)
echo "mount -t ecryptfs ~/Private ~/Private" >> ~/.profile
```

---

## PRIVACY PROTECTION

### Browser Hardening

#### Firefox Privacy Configuration
```bash
# Create user.js for Firefox privacy
cat > ~/.mozilla/firefox/*/user.js <<EOF
// OPSEC Firefox Privacy Configuration

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("datareporting.healthreport.uploadEnabled", false);

// Disable location tracking
user_pref("geo.enabled", false);

// Disable WebRTC (prevents IP leaks)
user_pref("media.peerconnection.enabled", false);

// Enhanced tracking protection
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);

// Disable fingerprinting
user_pref("privacy.resistFingerprinting", true);

// Clear history on close
user_pref("privacy.sanitize.sanitizeOnShutdown", true);

// Disable DNS prefetching
user_pref("network.dns.disablePrefetch", true);

// Disable link prefetching
user_pref("network.prefetch-next", false);

// HTTPS-only mode
user_pref("dom.security.https_only_mode", true);

// Disable WebGL
user_pref("webgl.disabled", true);
EOF
```

#### Chrome Privacy Settings
```bash
# Start Chrome with privacy flags
google-chrome \
  --disable-background-networking \
  --disable-default-apps \
  --disable-sync \
  --disable-translate \
  --disable-webrtc-multiple-routes \
  --disable-webrtc-hw-decoding \
  --enforce-webrtc-ip-permission-check \
  --no-pings \
  --disable-remote-fonts
```

### Privacy Tools

```bash
# Install privacy tools
sudo apt-get install -y \
  tor \
  torsocks \
  proxychains4 \
  mat2 \
  bleachbit

# Configure Tor
sudo systemctl enable tor
sudo systemctl start tor

# Configure proxychains for Tor
sudo tee /etc/proxychains4.conf <<EOF
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
EOF
```

### Metadata Removal

```bash
# Remove metadata from files
# Install MAT2
sudo apt-get install -y mat2

# Remove metadata from image
mat2 image.jpg

# Remove metadata from PDF
mat2 document.pdf

# Remove metadata from all files in directory
mat2 --inplace *.jpg *.png *.pdf
```

---

## MALWARE PREVENTION

### Antivirus Installation

```bash
# Install ClamAV
sudo apt-get install -y clamav clamav-daemon

# Update virus definitions
sudo freshclam

# Run scan
sudo clamscan -r --bell -i /home

# Schedule daily scans
echo "0 3 * * * root clamscan -r --bell -i /home > /var/log/clamav/scan.log 2>&1" | sudo tee -a /etc/crontab
```

### Rootkit Detection

```bash
# Install rkhunter
sudo apt-get install -y rkhunter

# Update database
sudo rkhunter --update

# Run check
sudo rkhunter --check

# Schedule weekly checks
echo "0 5 * * 0 root rkhunter --check --skip-keypress | mail -s 'Rootkit Check' root" | sudo tee -a /etc/crontab

# Install chkrootkit
sudo apt-get install -y chkrootkit

# Run check
sudo chkrootkit
```

### Application Whitelisting

```bash
# Install AppArmor
sudo apt-get install -y apparmor apparmor-utils

# Enable AppArmor
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Check status
sudo aa-status

# Set profiles to enforce mode
sudo aa-enforce /etc/apparmor.d/*
```

---

## DATA ENCRYPTION

### Full Disk Encryption (for new installations)
```bash
# Use LUKS during OS installation
# Or encrypt existing partition:

# Install cryptsetup
sudo apt-get install -y cryptsetup

# Encrypt partition (WARNING: DESTROYS DATA)
# sudo cryptsetup luksFormat /dev/sdX
# sudo cryptsetup luksOpen /dev/sdX encrypted_volume
# sudo mkfs.ext4 /dev/mapper/encrypted_volume
```

### File Encryption (GPG)

```bash
# Encrypt file
gpg --symmetric --cipher-algo AES256 sensitive_file.txt

# Decrypt file
gpg sensitive_file.txt.gpg

# Encrypt with public key
gpg --encrypt --recipient your@email.com file.txt

# Decrypt
gpg --decrypt file.txt.gpg > file.txt
```

### Encrypted Containers (VeraCrypt)

```bash
# Install VeraCrypt
# Download from: https://www.veracrypt.fr/

# Create encrypted container via GUI
# Or use command line:
# veracrypt --create /path/to/container

# Mount container
veracrypt /path/to/container /mnt/encrypted

# Dismount
veracrypt -d /mnt/encrypted
```

---

## MONITORING & DETECTION

### Intrusion Detection (Fail2Ban)

```bash
# Install Fail2Ban
sudo apt-get install -y fail2ban

# Configure
sudo tee /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = your@email.com
sendername = Fail2Ban

[sshd]
enabled = true
port = 22
logpath = /var/log/auth.log
EOF

# Start service
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Check status
sudo fail2ban-client status
```

### System Monitoring

```bash
# Install monitoring tools
sudo apt-get install -y \
  sysstat \
  htop \
  iotop \
  vnstat \
  auditd

# Enable audit daemon
sudo systemctl enable auditd
sudo systemctl start auditd

# Monitor failed login attempts
sudo cat /var/log/auth.log | grep "Failed password"

# Monitor sudo usage
sudo cat /var/log/auth.log | grep "sudo"

# Real-time log monitoring
sudo tail -f /var/log/syslog
```

### Process Monitoring

```bash
# Install psacct (process accounting)
sudo apt-get install -y acct

# Enable
sudo systemctl enable acct
sudo systemctl start acct

# View process history
sudo lastcomm

# View user activity
sudo ac -d
```

---

## ANTI-FORENSICS

### Secure File Deletion

```bash
# Install secure-delete
sudo apt-get install -y secure-delete

# Secure delete file
srm -vz sensitive_file.txt

# Secure delete directory
srm -vfz -r sensitive_directory/

# Wipe free space
sfill -vz /path/to/directory

# Wipe swap space
sudo swapoff -a
sudo sswap /dev/sda5  # Your swap partition
sudo swapon -a
```

### RAM Clearing

```bash
# Clear RAM cache (run as root)
sudo sync
sudo echo 3 > /proc/sys/vm/drop_caches

# Clear swap
sudo swapoff -a
sudo swapon -a
```

### History Clearing

```bash
# Disable bash history
unset HISTFILE
export HISTSIZE=0

# Clear current session
history -c

# Clear history file
cat /dev/null > ~/.bash_history

# Prevent history recording
set +o history  # Disable
set -o history  # Re-enable
```

---

## EMERGENCY RESPONSE

### Panic Script

See: `scripts/opsec_system_panic.sh`

### Emergency Procedures

1. **Suspected Compromise**
   ```bash
   # Disconnect from network immediately
   sudo ip link set <interface> down
   
   # Kill suspicious processes
   sudo pkill -9 <process_name>
   
   # Run integrity check
   sudo aide --check
   
   # Check for rootkits
   sudo rkhunter --check
   ```

2. **Data Breach Response**
   ```bash
   # Rotate all credentials immediately
   ./scripts/opsec_secrets_manager.sh rotate_all
   
   # Enable maximum logging
   sudo auditctl -e 2
   
   # Create forensic image
   sudo dd if=/dev/sda of=/mnt/external/forensic_image.dd
   ```

3. **Legal Warrant Response**
   ```bash
   # Encrypted containers should be dismounted
   veracrypt -d
   
   # Clear RAM
   sudo sync && echo 3 > /proc/sys/vm/drop_caches
   
   # Power off (do NOT suspend/hibernate)
   sudo poweroff
   ```

---

## AUTOMATION

### Daily Security Tasks

See: `scripts/opsec_system_daily.sh`

### Automated Hardening

See: `scripts/opsec_system_harden.sh`

---

## QUICK REFERENCE

### Essential Commands

```bash
# System hardening
./scripts/opsec_system_harden.sh

# Daily security check
./scripts/opsec_system_daily.sh

# Monitor system
./scripts/opsec_system_monitor.sh

# Emergency panic
./scripts/opsec_system_panic.sh
```

---

**Copyright © 2025 Security Research Operations. All Rights Reserved.**

**Status:** 🟢 OPERATIONAL  
**Last Updated:** November 3, 2025  
**Version:** 1.0.0

