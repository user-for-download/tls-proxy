#!/bin/bash
# Run as root or with sudo

echo "🔧 Tuning Linux for maximum performance..."

# Increase file descriptor limits
ulimit -n 1048576
echo "1048576" > /proc/sys/fs/nr_open 2>/dev/null || true

# TCP tuning
sysctl -w net.core.somaxconn=8192
sysctl -w net.ipv4.tcp_max_syn_backlog=8192
sysctl -w net.core.netdev_max_backlog=8192

# TCP FastOpen
sysctl -w net.ipv4.tcp_fastopen=3

# Buffer sizes
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# Connection reuse
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fin_timeout=15

echo "✅ System tuned for high performance"
echo ""
echo "Verify with:"
echo "  sysctl net.core.somaxconn"
echo "  ulimit -n"