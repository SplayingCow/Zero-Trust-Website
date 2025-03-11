#!/bin/bash
# 🚀 Zero Trust Secure Deployment Script
# This script automates the deployment of the Rust-based Zero Trust website.
# Features:
# - 🔐 Cryptographic binary verification before execution
# - 🛠️ Hardened Linux configurations for minimal attack surface
# - ⚡ Automatic deployment to cloud or bare metal
# - ✅ System integrity enforcement before launch
# - 🔄 Service auto-restart & logging setup

set -e  # Exit immediately on error
set -u  # Treat unset variables as errors
set -o pipefail  # Catch errors in pipes

PROJECT_NAME="zero-trust-website"
DEPLOY_DIR="/opt/zero-trust"
BINARY_PATH="target/release/$PROJECT_NAME"
SERVICE_NAME="zero-trust.service"
HASH_FILE="/opt/zero-trust/build-hash.sha256"
SECURE_USER="zero_trust_user"

echo "[DEPLOY] 🚀 Initiating Zero Trust deployment..."

# Ensure required commands are available
for cmd in cargo sha256sum systemctl useradd chmod chown; do
    if ! command -v $cmd &> /dev/null; then
        echo "[ERROR] ❌ Missing required command: $cmd. Install it before proceeding."
        exit 1
    fi
done

# Verify system integrity
echo "[DEPLOY] 🔍 Verifying system integrity..."
if ! sha256sum -c "$HASH_FILE" --status 2>/dev/null; then
    echo "[ERROR] ❌ Binary integrity check failed! Deployment aborted."
    exit 1
fi
echo "[DEPLOY] ✅ Binary verification passed."

# Create deployment directory
echo "[DEPLOY] 📂 Setting up deployment directory..."
mkdir -p "$DEPLOY_DIR"
cp "$BINARY_PATH" "$DEPLOY_DIR/"
chown root:root "$DEPLOY_DIR/$PROJECT_NAME"
chmod 755 "$DEPLOY_DIR/$PROJECT_NAME"

# Create a dedicated least-privilege system user
if ! id "$SECURE_USER" &>/dev/null; then
    echo "[DEPLOY] 🔐 Creating a secure user for execution..."
    useradd -r -s /usr/sbin/nologin "$SECURE_USER"
fi
chown "$SECURE_USER:$SECURE_USER" "$DEPLOY_DIR/$PROJECT_NAME"

# Harden system security settings
echo "[DEPLOY] 🛠️ Applying system hardening configurations..."
sysctl -w kernel.randomize_va_space=2  # Enable ASLR
sysctl -w fs.protected_hardlinks=1     # Restrict hardlink creation
sysctl -w fs.protected_symlinks=1      # Restrict symlink following
sysctl -w net.ipv4.conf.all.rp_filter=1  # Enable reverse path filtering
sysctl -w net.ipv4.tcp_syncookies=1    # Enable TCP SYN cookies
sysctl -w kernel.dmesg_restrict=1      # Restrict dmesg access

# Deploy as a systemd service for automatic management
echo "[DEPLOY] 🔄 Setting up systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME <<EOL
[Unit]
Description=Zero Trust Secure Web Service
After=network.target

[Service]
ExecStart=$DEPLOY_DIR/$PROJECT_NAME
User=$SECURE_USER
Restart=always
LimitNOFILE=1048576
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true
ReadOnlyPaths=/
MemoryDenyWriteExecute=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable & start service
echo "[DEPLOY] 🚀 Enabling and starting the service..."
systemctl daemon-reload
systemctl enable $SERVICE_NAME
systemctl start $SERVICE_NAME

echo "[DEPLOY] ✅ Deployment completed successfully."
