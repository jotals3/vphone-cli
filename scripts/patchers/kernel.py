#!/usr/bin/env python3
"""
kernel.py — Dynamic kernel patcher for iOS prelinked kernelcaches.

Finds all patch sites by string anchors, ADRP+ADD cross-references,
BL frequency analysis, and Mach-O structure parsing.  Nothing is hardcoded;
works across kernel variants (vresearch101, vphone600, etc.).

Dependencies:  keystone-engine, capstone
"""

# Re-export asm helpers for backward compatibility (kernel_jb.py imports from here)
from .kernel_asm import (
    asm,
    NOP,
    MOV_X0_0,
    MOV_X0_1,
    MOV_W0_0,
    MOV_W0_1,
    RET,
    CMP_W0_W0,
    CMP_X0_X0,
    _rd32,
    _rd64,
    _asm_u32,
    _verify_disas,
)
from .kernel_base import KernelPatcherBase
from .kernel_patch_apfs_snapshot import KernelPatchApfsSnapshotMixin
from .kernel_patch_apfs_seal import KernelPatchApfsSealMixin
from .kernel_patch_bsd_init import KernelPatchBsdInitMixin
from .kernel_patch_launch_constraints import KernelPatchLaunchConstraintsMixin
from .kernel_patch_debugger import KernelPatchDebuggerMixin
from .kernel_patch_post_validation import KernelPatchPostValidationMixin
from .kernel_patch_dyld_policy import KernelPatchDyldPolicyMixin
from .kernel_patch_apfs_graft import KernelPatchApfsGraftMixin
from .kernel_patch_apfs_mount import KernelPatchApfsMountMixin
from .kernel_patch_sandbox import KernelPatchSandboxMixin


class KernelPatcher(
    KernelPatchSandboxMixin,
    KernelPatchApfsMountMixin,
    KernelPatchApfsGraftMixin,
    KernelPatchDyldPolicyMixin,
    KernelPatchPostValidationMixin,
    KernelPatchDebuggerMixin,
    KernelPatchLaunchConstraintsMixin,
    KernelPatchBsdInitMixin,
    KernelPatchApfsSealMixin,
    KernelPatchApfsSnapshotMixin,
    KernelPatcherBase,
):
    """Dynamic kernel patcher — all offsets found at runtime."""

    def find_all(self):
        """Find and record all kernel patches.  Returns list of (offset, bytes, desc)."""
        self._reset_patch_state()
        self.patch_apfs_root_snapshot()  #  1
        self.patch_apfs_seal_broken()  #  2
        self.patch_bsd_init_rootvp()  #  3
        self.patch_proc_check_launch_constraints()  #  4-5
        self.patch_PE_i_can_has_debugger()  #  6-7
        self.patch_post_validation_nop()  #  8
        self.patch_post_validation_cmp()  #  9
        self.patch_check_dyld_policy()  # 10-11
        self.patch_apfs_graft()  # 12
        self.patch_apfs_vfsop_mount_cmp()  # 13
        self.patch_apfs_mount_upgrade_checks()  # 14
        self.patch_handle_fsioc_graft()  # 15
        self.patch_apfs_get_dev_by_role_entitlement()  # 16
        self.patch_sandbox_hooks()  # 17-26
        return self.patches

    def apply(self):
        """Find all patches and apply them to self.data.  Returns patch count."""
        self._patch_num = 0
        patches = self.find_all()
        # emit() already writes patches through to self.data,
        # but re-apply in case subclasses override find_all().
        for off, patch_bytes, desc in patches:
            self.data[off : off + len(patch_bytes)] = patch_bytes
        return len(patches)


# ── CLI entry point ──────────────────────────────────────────────
if __name__ == "__main__":
    import sys, argparse

    parser = argparse.ArgumentParser(
        description="Dynamic kernel patcher — find & apply patches on iOS kernelcaches"
    )
    parser.add_argument("kernelcache", help="Path to raw or IM4P kernelcache")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show detailed before/after disassembly for each patch",
    )
    parser.add_argument(
        "-c",
        "--context",
        type=int,
        default=5,
        help="Instructions of context before/after each patch (default: 5, requires -v)",
    )
    args = parser.parse_args()

    path = args.kernelcache
    print(f"Loading {path}...")
    file_raw = open(path, "rb").read()

    # Auto-detect IM4P vs raw Mach-O
    if file_raw[:4] == b"\xcf\xfa\xed\xfe":
        payload = file_raw
        print(f"  format: raw Mach-O")
    else:
        try:
            from pyimg4 import IM4P

            im4p = IM4P(file_raw)
            if im4p.payload.compression:
                im4p.payload.decompress()
            payload = im4p.payload.data
            print(f"  format: IM4P (fourcc={im4p.fourcc})")
        except Exception:
            payload = file_raw
            print(f"  format: unknown (treating as raw)")

    data = bytearray(payload)
    print(f"  size:   {len(data)} bytes ({len(data) / 1024 / 1024:.1f} MB)\n")

    kp = KernelPatcher(data, verbose=args.verbose)
    patches = kp.find_all()
    print(f"\n  {len(patches)} patches found")

    if args.verbose:
        # ── Print ranged before / after disassembly for every patch ──
        ctx = args.context

        print(f"\n{'═' * 72}")
        print(f"  {len(patches)} PATCHES — before / after disassembly (context={ctx})")
        print(f"{'═' * 72}")

        # Apply patches to get the "after" image
        after = bytearray(kp.raw)  # start from original
        for off, pb, _ in patches:
            after[off : off + len(pb)] = pb

        for i, (off, patch_bytes, desc) in enumerate(sorted(patches), 1):
            n_insns = len(patch_bytes) // 4
            start = max(off - ctx * 4, 0)
            end = off + n_insns * 4 + ctx * 4
            total = (end - start) // 4

            before_insns = kp._disas_n(kp.raw, start, total)
            after_insns = kp._disas_n(after, start, total)

            print(f"\n  ┌{'─' * 70}")
            print(f"  │ [{i:2d}] 0x{off:08X}: {desc}")
            print(f"  ├{'─' * 34}┬{'─' * 35}")
            print(f"  │ {'BEFORE':^33}│ {'AFTER':^34}")
            print(f"  ├{'─' * 34}┼{'─' * 35}")

            # Build line pairs
            max_lines = max(len(before_insns), len(after_insns))
            for j in range(max_lines):

                def fmt(insn):
                    if insn is None:
                        return " " * 33
                    h = insn.bytes.hex()
                    return f"0x{insn.address:07X} {h:8s} {insn.mnemonic:6s} {insn.op_str}"

                bi = before_insns[j] if j < len(before_insns) else None
                ai = after_insns[j] if j < len(after_insns) else None

                bl = fmt(bi)
                al = fmt(ai)

                # Mark if this address is inside the patched range
                addr = (bi.address if bi else ai.address) if (bi or ai) else 0
                in_patch = off <= addr < off + len(patch_bytes)
                marker = " ◄" if in_patch else "  "

                print(f"  │ {bl:33s}│ {al:33s}{marker}")

            print(f"  └{'─' * 34}┴{'─' * 35}")
