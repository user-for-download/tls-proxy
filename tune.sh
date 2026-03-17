#!/bin/bash

# Ensure BBR module is loaded into the kernel
modprobe tcp_bbr
echo "tcp_bbr" > /etc/modules-load.d/bbr.conf

# Overwrite (>) instead of append (>>) so the script is idempotent
cat > /etc/sysctl.d/99-proxy.conf << 'EOF'
# Network stack tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.optmem_max = 65535

# TCP tuning (min, default, max)
# Default is 128KB to save RAM. Linux will auto-tune up to 16MB for active downloads.
net.ipv4.tcp_rmem = 4096 131072 16777216
net.ipv4.tcp_wmem = 4096 131072 16777216

# Connection & Port limitations
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3

# CRITICAL FOR PROXIES: Increase outbound ephemeral port range
net.ipv4.ip_local_port_range = 1024 65535

# Enable BBR (fq must come before bbr)
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# File descriptors
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

# Apply sysctl limits immediately
sysctl -p /etc/sysctl.d/99-proxy.conf

# Increase file limits for PAM / L