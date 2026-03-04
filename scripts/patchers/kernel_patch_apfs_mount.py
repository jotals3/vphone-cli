"""Mixin: APFS mount checks patches."""

from capstone.arm64_const import (
    ARM64_OP_IMM,
    ARM64_OP_REG,
    ARM64_REG_W0,
    ARM64_REG_W8,
    ARM64_REG_X0,
)

from .kernel_asm import CMP_X0_X0, MOV_W0_0, NOP, _PACIBSP_U32, _rd32


class KernelPatchApfsMountMixin:
    def patch_apfs_vfsop_mount_cmp(self):
        """Patch 13: cmp x0,x0 in _apfs_vfsop_mount (current_thread == kernel_task check).

        The target CMP follows the pattern: BL (returns current_thread in x0),
        ADRP + LDR + LDR (load kernel_task global), CMP x0, Xm, B.EQ.
        We require x0 as the first CMP operand to distinguish it from other
        CMP Xn,Xm instructions in the same function.
        """
        self._log("\n[13] _apfs_vfsop_mount: cmp x0,x0 (mount rw check)")

        refs_upgrade = self._find_by_string_in_range(
            b"apfs_mount_upgrade_checks\x00",
            self.apfs_text,
            "apfs_mount_upgrade_checks",
        )
        if not refs_upgrade:
            return False

        func_start = self.find_function_start(refs_upgrade[0][0])
        if func_start < 0:
            return False

        # Find BL callers of _apfs_mount_upgrade_checks
        callers = self.bl_callers.get(func_start, [])
        if not callers:
            for off_try in [func_start, func_start + 4]:
                callers = self.bl_callers.get(off_try, [])
                if callers:
                    break

        if not callers:
            self._log("  [-] no BL callers of _apfs_mount_upgrade_checks found")
            for off in range(self.apfs_text[0], self.apfs_text[1], 4):
                bl_target = self._is_bl(off)
                if bl_target >= 0 and func_start <= bl_target <= func_start + 4:
                    callers.append(off)

        for caller_off in callers:
            if not (self.apfs_text[0] <= caller_off < self.apfs_text[1]):
                continue
            # Scan a wider range — the CMP can be 0x800+ bytes before the BL
            caller_func = self.find_function_start(caller_off)
            scan_start = (
                caller_func
                if caller_func >= 0
                else max(caller_off - 0x800, self.apfs_text[0])
            )
            scan_end = min(caller_off + 0x100, self.apfs_text[1])

            for scan in range(scan_start, scan_end, 4):
                dis = self._disas_at(scan)
                if not dis or dis[0].mnemonic != "cmp":
                    continue
                ops = dis[0].operands
                if len(ops) < 2:
                    continue
                # Require CMP Xn, Xm (both register operands)
                if ops[0].type != ARM64_OP_REG or ops[1].type != ARM64_OP_REG:
                    continue
                # Require x0 as first operand (return value from BL)
                if ops[0].reg != ARM64_REG_X0:
                    continue
                # Skip CMP x0, x0 (already patched or trivial)
                if ops[0].reg == ops[1].reg:
                    continue
                self.emit(
                    scan,
                    CMP_X0_X0,
                    f"cmp x0,x0 (was {dis[0].mnemonic} {dis[0].op_str}) "
                    "[_apfs_vfsop_mount]",
                )
                return True

        self._log("  [-] CMP x0,Xm not found near mount_upgrade_checks caller")
        return False

    def patch_apfs_mount_upgrade_checks(self):
        """Patch 14: Replace TBNZ w0,#0xe with mov w0,#0 in _apfs_mount_upgrade_checks.

        Within the function, a BL calls a small flag-reading leaf function,
        then TBNZ w0,#0xe branches to the error path.  Replace the TBNZ
        with mov w0,#0 to force the success path.
        """
        self._log("\n[14] _apfs_mount_upgrade_checks: mov w0,#0 (tbnz bypass)")

        refs = self._find_by_string_in_range(
            b"apfs_mount_upgrade_checks\x00",
            self.apfs_text,
            "apfs_mount_upgrade_checks",
        )
        if not refs:
            return False

        func_start = self.find_function_start(refs[0][0])
        if func_start < 0:
            self._log("  [-] function start not found")
            return False

        # Scan for BL followed by TBNZ w0
        # Don't stop at ret/retab (early returns) — only stop at PACIBSP (new function)
        for scan in range(func_start, min(func_start + 0x200, self.size), 4):
            if scan > func_start + 8 and _rd32(self.raw, scan) == _PACIBSP_U32:
                break
            bl_target = self._is_bl(scan)
            if bl_target < 0:
                continue
            # Check if BL target is a small leaf function (< 0x20 bytes, ends with ret)
            is_leaf = False
            for k in range(0, 0x20, 4):
                if bl_target + k >= self.size:
                    break
                dis = self._disas_at(bl_target + k)
                if dis and dis[0].mnemonic == "ret":
                    is_leaf = True
                    break
            if not is_leaf:
                continue
            # Check next instruction is TBNZ w0, #0xe
            next_off = scan + 4
            insns = self._disas_at(next_off)
            if not insns:
                continue
            i = insns[0]
            if i.mnemonic == "tbnz" and len(i.operands) >= 1:
                if (
                    i.operands[0].type == ARM64_OP_REG
                    and i.operands[0].reg == ARM64_REG_W0
                ):
                    self.emit(
                        next_off, MOV_W0_0, "mov w0,#0 [_apfs_mount_upgrade_checks]"
                    )
                    return True

        self._log("  [-] BL + TBNZ w0 pattern not found")
        return False

    def patch_apfs_get_dev_by_role_entitlement(self):
        """Patch 16: bypass APFS get-dev-by-role entitlement gate.

        In handle_get_dev_by_role, APFS checks:
          1) context predicate (BL ... ; CBZ X0, deny)
          2) entitlement check for "com.apple.apfs.get-dev-by-role"
             (BL ... ; CBZ W0, deny)

        mount-phase-1 for /private/preboot and /private/xarts can fail here with:
          "%s:%d: %s This operation needs entitlement" (line 13101)

        We NOP the deny branches so the function continues into normal role lookup.
        """
        self._log("\n[16] handle_get_dev_by_role: bypass entitlement gate")

        str_off = self.find_string(b"com.apple.apfs.get-dev-by-role")
        if str_off < 0:
            self._log("  [-] entitlement string not found")
            return False

        refs = self.find_string_refs(str_off, *self.apfs_text)
        if not refs:
            self._log("  [-] no code refs to entitlement string")
            return False

        def _is_entitlement_error_block(target_off, func_end):
            """Heuristic: target block sets known entitlement-gate line IDs."""
            scan_end = min(target_off + 0x30, func_end)
            for off in range(target_off, scan_end, 4):
                ins = self._disas_at(off)
                if not ins:
                    continue
                i = ins[0]
                # Keep scan local to the direct target block.
                # Crossing a call/unconditional jump usually means a different path.
                if i.mnemonic in ("bl", "b", "ret", "retab"):
                    break
                if i.mnemonic != "mov" or len(i.operands) < 2:
                    continue
                if (
                    i.operands[0].type == ARM64_OP_REG
                    and i.operands[0].reg == ARM64_REG_W8
                    and i.operands[1].type == ARM64_OP_IMM
                    and i.operands[1].imm in (0x332D, 0x333B)
                ):
                    return True
            return False

        for ref in refs:
            ref_off = ref[0]
            func_start = self.find_function_start(ref_off)
            if func_start < 0:
                continue
            func_end = min(func_start + 0x1200, self.size)

            # Hardened logic:
            #   patch all CBZ/CBNZ on X0/W0 that jump into entitlement
            #   error blocks (line 0x33xx logger paths).
            candidates = []
            for off in range(func_start, func_end, 4):
                ins = self._disas_at(off)
                if not ins:
                    continue
                i = ins[0]
                if i.mnemonic not in ("cbz", "cbnz") or len(i.operands) < 2:
                    continue
                if (
                    i.operands[0].type != ARM64_OP_REG
                    or i.operands[1].type != ARM64_OP_IMM
                ):
                    continue
                if i.operands[0].reg not in (ARM64_REG_W0, ARM64_REG_X0):
                    continue

                target = i.operands[1].imm
                if not (func_start <= target < func_end):
                    continue
                if target <= off:
                    continue
                if not _is_entitlement_error_block(target, func_end):
                    continue

                # Keep deterministic order; avoid duplicate offsets.
                if all(prev_off != off for prev_off, _, _ in candidates):
                    candidates.append((off, i.operands[0].reg, target))

            if candidates:
                for off, reg, target in candidates:
                    gate = "context" if reg == ARM64_REG_X0 else "entitlement"
                    self.emit(
                        off,
                        NOP,
                        f"NOP [handle_get_dev_by_role {gate} check -> 0x{target:X}]",
                    )
                return True

        self._log("  [-] handle_get_dev_by_role entitlement gate pattern not found")
        return False
