#!/usr/bin/env zsh
set -euo pipefail

# Save a reusable kernel checkpoint for variant testing.
#
# BASE_PATCH chooses the patch pipeline before saving the checkpoint:
#   normal -> fw_patch
#   dev    -> fw_patch_dev
#   jb     -> fw_patch_jb

PROJECT_DIR="$(cd "$(dirname "${0:a:h}")" && pwd)"
cd "$PROJECT_DIR"

VM_DIR="${VM_DIR:-vm}"
BASE_PATCH="${BASE_PATCH:-jb}"

case "$BASE_PATCH" in
    normal)
        PATCH_TARGET="fw_patch"
        ;;
    dev)
        PATCH_TARGET="fw_patch_dev"
        ;;
    jb)
        PATCH_TARGET="fw_patch_jb"
        ;;
    *)
        echo "[-] Invalid BASE_PATCH: $BASE_PATCH"
        echo "    Use BASE_PATCH=normal|dev|jb"
        exit 1
        ;;
esac

echo "[checkpoint] base_patch=$BASE_PATCH"

echo "[checkpoint] killing existing vphone-cli..."
pkill -9 vphone-cli 2>/dev/null || true
sleep 1

echo "[checkpoint] fw_prepare..."
make fw_prepare VM_DIR="$VM_DIR"

echo "[checkpoint] $PATCH_TARGET..."
make "$PATCH_TARGET" VM_DIR="$VM_DIR"

RESTORE_DIR=$(find "$VM_DIR" -maxdepth 1 -type d -name '*Restore*' | head -1)
if [[ -z "$RESTORE_DIR" ]]; then
    echo "[-] No *Restore* directory found in $VM_DIR"
    exit 1
fi

KERNEL_PATH=$(find "$RESTORE_DIR" -name 'kernelcache.research.vphone600' | head -1)
if [[ -z "$KERNEL_PATH" ]]; then
    echo "[-] kernelcache not found in $RESTORE_DIR"
    exit 1
fi

SOURCE_KERNEL="$KERNEL_PATH"
if [[ "$BASE_PATCH" == "jb" ]]; then
    RAMDISK_SOURCE="${KERNEL_PATH}.ramdisk"
    if [[ -f "$RAMDISK_SOURCE" ]]; then
        SOURCE_KERNEL="$RAMDISK_SOURCE"
        echo "[checkpoint] using JB base snapshot: $(basename "$RAMDISK_SOURCE")"
    fi
fi

CHECKPOINT_PATH="${KERNEL_PATH}.checkpoint.${BASE_PATCH}.backup"
cp "$SOURCE_KERNEL" "$CHECKPOINT_PATH"

echo "[checkpoint] saved: $CHECKPOINT_PATH ($(wc -c < "$CHECKPOINT_PATH") bytes)"
