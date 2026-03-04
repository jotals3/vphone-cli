#!/usr/bin/env python3
"""
testing_kernel_patch.py — Restore a saved kernel checkpoint and apply selected patches.

Usage:
    python3 testing_kernel_patch.py <vm_dir> --base-patch jb patch_kcall10
    python3 testing_kernel_patch.py <vm_dir> --base-patch normal patch_apfs_get_dev_by_role_entitlement
    python3 testing_kernel_patch.py <vm_dir> patch_mac_mount patch_dounmount

Notes:
- `--base-patch` selects which checkpoint file to restore first:
    kernelcache.research.vphone600.checkpoint.<base_patch>.backup
  Fallback: legacy `.base_backup`.
- Patch names can come from either `KernelPatcher` (base) or `KernelJBPatcher` (JB).
"""

import argparse
import os
import shutil
import sys

from fw_patch import find_file, find_restore_dir, load_firmware, save_firmware
from patchers.kernel import KernelPatcher
from patchers.kernel_jb import KernelJBPatcher


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Restore checkpoint and apply selected kernel patch methods")
    parser.add_argument("vm_dir", help="VM directory (contains iPhone*_Restore)")
    parser.add_argument(
        "patch_names",
        nargs="+",
        help="Patch method names to apply (e.g. patch_kcall10)",
    )
    parser.add_argument(
        "--base-patch",
        choices=("normal", "dev", "jb"),
        default=os.environ.get("BASE_PATCH") or "jb",
        help="Checkpoint variant to restore first (default: jb)",
    )
    return parser.parse_args()


def resolve_checkpoint(kernel_path: str, base_patch: str) -> str:
    preferred = f"{kernel_path}.checkpoint.{base_patch}.backup"
    legacy = f"{kernel_path}.base_backup"

    if os.path.exists(preferred):
        return preferred
    if os.path.exists(legacy):
        print(f"[!] preferred checkpoint missing, using legacy backup: {legacy}")
        return legacy

    print(f"[-] No checkpoint found.")
    print(f"    Missing: {preferred}")
    print(f"    Missing: {legacy}")
    print(f"    Run 'make testing_checkpoint_save BASE_PATCH={base_patch}' first.")
    sys.exit(1)


def list_available_methods(base_patcher: KernelPatcher, jb_patcher: KernelJBPatcher) -> None:
    names = set()
    for obj in (base_patcher, jb_patcher):
        for name in dir(obj):
            if name.startswith("patch_") and callable(getattr(obj, name)):
                names.add(name)

    print("    Available patches:")
    for name in sorted(names):
        print(f"      {name}")


def main() -> None:
    args = parse_args()

    vm_dir = os.path.abspath(args.vm_dir)
    if not os.path.isdir(vm_dir):
        print(f"[-] Not a directory: {vm_dir}")
        sys.exit(1)

    restore_dir = find_restore_dir(vm_dir)
    if not restore_dir:
        print(f"[-] No *Restore* directory found in {vm_dir}")
        sys.exit(1)

    kernel_path = find_file(restore_dir, ["kernelcache.research.vphone600"], "kernelcache")
    checkpoint_path = resolve_checkpoint(kernel_path, args.base_patch)

    shutil.copy2(checkpoint_path, kernel_path)
    print(f"[*] Restored checkpoint: {checkpoint_path}")
    print(f"[*] Target kernel:        {kernel_path}")

    im4p, data, was_im4p, original_raw = load_firmware(kernel_path)
    fmt = "IM4P" if was_im4p else "raw"
    print(f"[*] Loaded: {fmt}, {len(data)} bytes")

    base_patcher = KernelPatcher(data)
    jb_patcher = KernelJBPatcher(data)

    selected = []
    for patch_name in args.patch_names:
        method = getattr(jb_patcher, patch_name, None)
        if callable(method):
            selected.append(("jb", patch_name, method))
            continue

        method = getattr(base_patcher, patch_name, None)
        if callable(method):
            selected.append(("base", patch_name, method))
            continue

        print(f"[-] Unknown patch: {patch_name}")
        list_available_methods(base_patcher, jb_patcher)
        sys.exit(1)

    print(f"[*] Applying {len(selected)} method(s)...")
    for scope, patch_name, method in selected:
        print(f"    - {patch_name} [{scope}]")
        method()

    applied = 0
    for off, patch_bytes, _ in base_patcher.patches:
        data[off : off + len(patch_bytes)] = patch_bytes
        applied += 1
    for off, patch_bytes, _ in jb_patcher.patches:
        data[off : off + len(patch_bytes)] = patch_bytes
        applied += 1

    print(f"[+] Applied low-level patches: {applied}")

    save_firmware(kernel_path, im4p, data, was_im4p, original_raw)
    print(f"[+] Saved: {kernel_path}")


if __name__ == "__main__":
    main()
