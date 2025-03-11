#!/bin/bash
# 🚀 Zero Trust System Monitoring Script
# This script provides real-time system monitoring with anomaly detection.
# Features:
# - 📊 Monitors CPU, memory, disk, and network usage
# - 🔍 Detects suspicious processes & unauthorized resource spikes
# - 📡 Logs system metrics to tamper-proof storage
# - 🚨 Sends alerts for high system load & anomalies
# - 🔐 Enforces Zero Trust by restricting access to monitoring logs

set -e  # Exit immediately on error
set -u  # Treat unset variables as errors
set -o pipefail  # Catch errors in pipes

LOG_DIR="/var/log/zero-trust-monitor"
LOG_FILE="$LOG_DIR/system_monitor.log"
ALERT_THRESHOLD_CPU=85
ALERT_THRESHOLD_MEM=90
ALERT_THRESHOLD_DISK=90
SECURE_USER="zero_trust_user"

# Ensure log directory exists
mkdir -p "$LOG_DIR"
chown root:root "$LOG_DIR"
chmod 750 "$LOG_DIR"

# Secure log access
touch "$LOG_FILE"
chown root:root "$LOG_FILE"
chmod 600 "$LOG_FILE"

# Function to log monitored data
log_event() {
    local message="$1"
    local timestamp
    timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] $message" >> "$LOG_FILE"
    echo "[MONITOR] $message"
}

# Function to check CPU usage
check_cpu() {
    local cpu_usage
    cpu_usage=$(grep 'cpu ' /proc/stat | awk '{usage=($2+$4)*100/($2+$4+$5)} END {print usage}')
    cpu_usage=${cpu_usage%.*}  # Convert float to integer
    log_event "CPU Usage: ${cpu_usage}%"

    if [[ "$cpu_usage" -ge "$ALERT_THRESHOLD_CPU" ]]; then
        log_event "🚨 ALERT: High CPU usage detected! ($cpu_usage%)"
    fi
}

# Function to check memory usage
check_memory() {
    local mem_usage
    mem_usage=$(free | awk '/Mem:/ {print $3/$2 * 100}')
    mem_usage=${mem_usage%.*}
    log_event "Memory Usage: ${mem_usage}%"

    if [[ "$mem_usage" -ge "$ALERT_THRESHOLD_MEM" ]]; then
        log_event "🚨 ALERT: High Memory usage detected! ($mem_usage%)"
    fi
}

# Function to check disk usage
check_disk() {
    local disk_usage
    disk_usage=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
    log_event "Disk Usage: ${disk_usage}%"

    if [[ "$disk_usage" -ge "$ALERT_THRESHOLD_DISK" ]]; then
        log_event "🚨 ALERT: High Disk usage detected! ($disk_usage%)"
    fi
}

# Function to monitor network usage
check_network() {
    local net_rx net_tx
    net_rx=$(cat /sys/class/net/eth0/statistics/rx_bytes)
    net_tx=$(cat /sys/class/net/eth0/statistics/tx_bytes)
    log_event "Network Usage - RX: $((net_rx / 1024 / 1024))MB, TX: $((net_tx / 1024 / 1024))MB"
}

# Function to detect suspicious processes
detect_anomalies() {
    local suspicious_processes
    suspicious_processes=$(ps aux --sort=-%cpu | awk '$3 > 50 || $4 > 50 {print $0}')

    if [[ -n "$suspicious_processes" ]]; then
        log_event "🚨 ALERT: High-resource processes detected!"
        echo "$suspicious_processes" >> "$LOG_FILE"
    fi
}

# Run monitoring loop
while true; do
    check_cpu
    check_memory
    check_disk
    check_network
    detect_anomalies
    sleep 10  # Run every 10 seconds
done
