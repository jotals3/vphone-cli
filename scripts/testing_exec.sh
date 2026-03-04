#!/usr/bin/env zsh
set -euo pipefail

# Quick testing flow:
#   pkill -9 vphone-cli
#   make fw_prepare
#   make fw_patch_jb
#   make testing_ramdisk_build
#   make testing_ramdisk_send &
#   make boot_dfu

PROJECT_DIR="$(cd "$(dirname "${0:a:h}")" && pwd)"
cd "$PROJECT_DIR"

VM_DIR="${VM_DIR:-vm}"

echo "[testing_exec] killing existing vphone-cli..."
pkill -9 vphone-cli 2>/dev/null || true
sleep 1

echo "[testing_exec] fw_prepare..."
make fw_prepare VM_DIR="$VM_DIR"

echo "[testing_exec] fw_patch_jb..."
make fw_patch_jb VM_DIR="$VM_DIR"

echo "[testing_exec] testing_ramdisk_build..."
make testing_ramdisk_build VM_DIR="$VM_DIR"

echo "[testing_exec] testing_ramdisk_send (background)..."
make testing_ramdisk_send VM_DIR="$VM_DIR" &
SEND_PID=$!

echo "[testing_exec] boot_dfu..."
make boot_dfu VM_DIR="$VM_DIR"

wait "$SEND_PID" 2>/dev/null || true
