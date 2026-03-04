#!/usr/bin/env python3
"""
testing_ramdisk_build.py — Build a minimal signed boot chain for testing.

Packs firmware components (iBSS, iBEC, SPTM, DeviceTree, SEP, TXM,
kernelcache) with the stock ramdisk into signed IMG4 files. No SSH
tools or CFW — just the base boot chain for quick patch verification.

Usage:
    python3 testing_ramdisk_build.py [vm_directory]

Prerequisites:
    pip install pyimg4
    Run fw_patch.py first to patch boot-chain components.
"""

import glob
import gzip
import os
import plistlib
import shutil
import subprocess
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from pyimg4 import IM4M, IM4P, IMG4

from fw_patch import (
    load_firmware,
    _save_im4p_with_payp,
    find_restore_dir,
    find_file,
)

# ══════════════════════════════════════════════════════════════════
# Configuration
# ══════════════════════════════════════════════════════════════════

OUTPUT_DIR = "TestingRamdisk"
TEMP_DIR = "testing_ramdisk_temp"

# IM4P fourccs for restore mode
TXM_FOURCC = "trxm"
KERNEL_FOURCC = "rkrn"


# ══════════════════════════════════════════════════════════════════
# SHSH / signing helpers
# ══════════════════════════════════════════════════════════════════


def find_shsh(shsh_dir):
    """Find first SHSH blob in directory."""
    for ext in ("*.shsh", "*.shsh2"):
        matches = sorted(glob.glob(os.path.join(shsh_dir, ext)))
        if matches:
            return matches[0]
    return None


def extract_im4m(shsh_path, im4m_path):
    """Extract IM4M manifest from SHSH blob (handles gzip-compressed)."""
    raw = open(shsh_path, "rb").read()
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    tmp = shsh_path + ".tmp"
    try:
        open(tmp, "wb").write(raw)
        subprocess.run(
            ["pyimg4", "im4m", "extract", "-i", tmp, "-o", im4m_path],
            check=True,
            capture_output=True,
        )
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def sign_img4(im4p_path, img4_path, im4m_path, tag=None):
    """Create IMG4 from IM4P + IM4M using pyimg4 Python API."""
    im4p = IM4P(open(im4p_path, "rb").read())
    if tag:
        im4p.fourcc = tag
    im4m = IM4M(open(im4m_path, "rb").read())
    img4 = IMG4(im4p=im4p, im4m=im4m)
    with open(img4_path, "wb") as f:
        f.write(img4.output())


# ══════════════════════════════════════════════════════════════════
# Firmware extraction
# ══════════════════════════════════════════════════════════════════


def extract_to_raw(src_path, raw_path):
    """Extract IM4P payload to .raw file. Returns (im4p_obj, data, original_raw)."""
    im4p, data, was_im4p, original_raw = load_firmware(src_path)
    with open(raw_path, "wb") as f:
        f.write(bytes(data))
    return im4p, data, original_raw


def create_im4p_uncompressed(raw_data, fourcc, description, output_path):
    """Create uncompressed IM4P from raw data."""
    new_im4p = IM4P(
        fourcc=fourcc,
        description=description,
        payload=bytes(raw_data),
    )
    with open(output_path, "wb") as f:
        f.write(new_im4p.output())


# ══════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════


def main():
    vm_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.getcwd())

    if not os.path.isdir(vm_dir):
        print(f"[-] Not a directory: {vm_dir}")
        sys.exit(1)

    # Find SHSH
    shsh_dir = os.path.join(vm_dir, "shsh")
    shsh_path = find_shsh(shsh_dir)
    if not shsh_path:
        print(f"[-] No SHSH blob found in {shsh_dir}/")
        print("    Place your .shsh file in the shsh/ directory.")
        sys.exit(1)

    # Find restore directory
    restore_dir = find_restore_dir(vm_dir)
    if not restore_dir:
        print(f"[-] No *Restore* directory found in {vm_dir}")
        sys.exit(1)

    # Create temp and output directories
    temp_dir = os.path.join(vm_dir, TEMP_DIR)
    output_dir = os.path.join(vm_dir, OUTPUT_DIR)
    for d in (temp_dir, output_dir):
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    print(f"[*] Testing ramdisk — boot chain only (no SSH, no CFW)")
    print(f"[*] VM directory:      {vm_dir}")
    print(f"[*] Restore directory: {restore_dir}")
    print(f"[*] SHSH blob:         {shsh_path}")

    # Extract IM4M from SHSH
    im4m_path = os.path.join(temp_dir, "vphone.im4m")
    print(f"\n[*] Extracting IM4M from SHSH...")
    extract_im4m(shsh_path, im4m_path)

    # ── 1. iBSS (already patched — extract & sign) ───────────────
    print(f"\n{'=' * 60}")
    print(f"  1. iBSS (already patched — extract & sign)")
    print(f"{'=' * 60}")
    ibss_src = find_file(
        restore_dir,
        ["Firmware/dfu/iBSS.vresearch101.RELEASE.im4p"],
        "iBSS",
    )
    ibss_raw = os.path.join(temp_dir, "iBSS.raw")
    ibss_im4p = os.path.join(temp_dir, "iBSS.im4p")
    im4p_obj, data, _ = extract_to_raw(ibss_src, ibss_raw)
    create_im4p_uncompressed(data, im4p_obj.fourcc, im4p_obj.description, ibss_im4p)
    sign_img4(
        ibss_im4p,
        os.path.join(output_dir, "iBSS.vresearch101.RELEASE.img4"),
        im4m_path,
    )
    print(f"  [+] iBSS.vresearch101.RELEASE.img4")

    # ── 2. iBEC (already patched — sign as-is, no boot-args change)
    print(f"\n{'=' * 60}")
    print(f"  2. iBEC (already patched — sign as-is)")
    print(f"{'=' * 60}")
    ibec_src = find_file(
        restore_dir,
        ["Firmware/dfu/iBEC.vresearch101.RELEASE.im4p"],
        "iBEC",
    )
    ibec_raw = os.path.join(temp_dir, "iBEC.raw")
    ibec_im4p = os.path.join(temp_dir, "iBEC.im4p")
    im4p_obj, data, _ = extract_to_raw(ibec_src, ibec_raw)
    create_im4p_uncompressed(data, im4p_obj.fourcc, im4p_obj.description, ibec_im4p)
    sign_img4(
        ibec_im4p,
        os.path.join(output_dir, "iBEC.vresearch101.RELEASE.img4"),
        im4m_path,
    )
    print(f"  [+] iBEC.vresearch101.RELEASE.img4")

    # ── 3. SPTM (sign only) ─────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  3. SPTM (sign only)")
    print(f"{'=' * 60}")
    sptm_src = find_file(
        restore_dir,
        ["Firmware/sptm.vresearch1.release.im4p"],
        "SPTM",
    )
    sign_img4(
        sptm_src,
        os.path.join(output_dir, "sptm.vresearch1.release.img4"),
        im4m_path,
        tag="sptm",
    )
    print(f"  [+] sptm.vresearch1.release.img4")

    # ── 4. DeviceTree (sign only) ────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  4. DeviceTree (sign only)")
    print(f"{'=' * 60}")
    dt_src = find_file(
        restore_dir,
        ["Firmware/all_flash/DeviceTree.vphone600ap.im4p"],
        "DeviceTree",
    )
    sign_img4(
        dt_src,
        os.path.join(output_dir, "DeviceTree.vphone600ap.img4"),
        im4m_path,
        tag="rdtr",
    )
    print(f"  [+] DeviceTree.vphone600ap.img4")

    # ── 5. SEP (sign only) ───────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  5. SEP (sign only)")
    print(f"{'=' * 60}")
    sep_src = find_file(
        restore_dir,
        ["Firmware/all_flash/sep-firmware.vresearch101.RELEASE.im4p"],
        "SEP",
    )
    sign_img4(
        sep_src,
        os.path.join(output_dir, "sep-firmware.vresearch101.RELEASE.img4"),
        im4m_path,
        tag="rsep",
    )
    print(f"  [+] sep-firmware.vresearch101.RELEASE.img4")

    # ── 6. TXM (already patched — repack & sign) ─────────────────
    print(f"\n{'=' * 60}")
    print(f"  6. TXM (already patched — repack & sign)")
    print(f"{'=' * 60}")
    txm_src = find_file(
        restore_dir,
        ["Firmware/txm.iphoneos.research.im4p"],
        "TXM",
    )
    txm_raw = os.path.join(temp_dir, "txm.raw")
    im4p_obj, data, original_raw = extract_to_raw(txm_src, txm_raw)
    txm_im4p = os.path.join(temp_dir, "txm.im4p")
    _save_im4p_with_payp(txm_im4p, TXM_FOURCC, data, original_raw)
    sign_img4(txm_im4p, os.path.join(output_dir, "txm.img4"), im4m_path)
    print(f"  [+] txm.img4")

    # ── 7. Kernelcache (already patched — repack as rkrn) ────────
    print(f"\n{'=' * 60}")
    print(f"  7. Kernelcache (already patched — repack as rkrn)")
    print(f"{'=' * 60}")
    kc_src = find_file(
        restore_dir,
        ["kernelcache.research.vphone600"],
        "kernelcache",
    )
    kc_raw = os.path.join(temp_dir, "kcache.raw")
    im4p_obj, data, original_raw = extract_to_raw(kc_src, kc_raw)
    print(f"  format: IM4P, {len(data)} bytes")
    kc_im4p = os.path.join(temp_dir, "krnl.im4p")
    _save_im4p_with_payp(kc_im4p, KERNEL_FOURCC, data, original_raw)
    sign_img4(kc_im4p, os.path.join(output_dir, "krnl.img4"), im4m_path)
    print(f"  [+] krnl.img4")

    # ── 8. Base ramdisk + trustcache ─────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  8. Base ramdisk + trustcache")
    print(f"{'=' * 60}")

    tc_bin = shutil.which("trustcache")
    if not tc_bin:
        print("[-] trustcache not found. Run: make setup_tools")
        sys.exit(1)

    # Read RestoreRamDisk path from BuildManifest
    bm_path = os.path.join(restore_dir, "BuildManifest.plist")
    with open(bm_path, "rb") as f:
        bm = plistlib.load(f)
    ramdisk_rel = bm["BuildIdentities"][0]["Manifest"]["RestoreRamDisk"]["Info"]["Path"]
    ramdisk_src = os.path.join(restore_dir, ramdisk_rel)

    # Extract base ramdisk DMG
    ramdisk_raw = os.path.join(temp_dir, "ramdisk.raw.dmg")
    subprocess.run(
        ["pyimg4", "im4p", "extract", "-i", ramdisk_src, "-o", ramdisk_raw],
        check=True,
        capture_output=True,
    )

    # Mount base ramdisk, build trustcache from its contents
    mountpoint = os.path.join(vm_dir, "testing_ramdisk_mnt")
    os.makedirs(mountpoint, exist_ok=True)
    try:
        subprocess.run(
            ["sudo", "hdiutil", "attach", "-mountpoint", mountpoint,
             ramdisk_raw, "-owners", "off"],
            check=True,
        )

        print("  Building trustcache from base ramdisk...")
        tc_raw = os.path.join(temp_dir, "ramdisk.tc")
        tc_im4p = os.path.join(temp_dir, "trustcache.im4p")
        subprocess.run([tc_bin, "create", tc_raw, mountpoint], check=True, capture_output=True)
        subprocess.run(
            ["pyimg4", "im4p", "create", "-i", tc_raw, "-o", tc_im4p, "-f", "rtsc"],
            check=True,
            capture_output=True,
        )
        sign_img4(tc_im4p, os.path.join(output_dir, "trustcache.img4"), im4m_path)
        print(f"  [+] trustcache.img4")
    finally:
        subprocess.run(
            ["sudo", "hdiutil", "detach", "-force", mountpoint], capture_output=True
        )

    # Sign base ramdisk as-is
    rd_im4p = os.path.join(temp_dir, "ramdisk.im4p")
    subprocess.run(
        ["pyimg4", "im4p", "create", "-i", ramdisk_raw, "-o", rd_im4p, "-f", "rdsk"],
        check=True,
        capture_output=True,
    )
    sign_img4(rd_im4p, os.path.join(output_dir, "ramdisk.img4"), im4m_path)
    print(f"  [+] ramdisk.img4 (base, unmodified)")

    # ── Cleanup ──────────────────────────────────────────────────
    print(f"\n[*] Cleaning up {TEMP_DIR}/...")
    shutil.rmtree(temp_dir, ignore_errors=True)

    # ── Summary ──────────────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Testing ramdisk build complete!")
    print(f"  Output: {output_dir}/")
    print(f"  Note: boot chain only — no SSH, no CFW")
    print(f"{'=' * 60}")
    for f in sorted(os.listdir(output_dir)):
        size = os.path.getsize(os.path.join(output_dir, f))
        print(f"    {f:45s} {size:>10,} bytes")


if __name__ == "__main__":
    main()
