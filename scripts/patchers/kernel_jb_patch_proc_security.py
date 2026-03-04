"""Mixin: KernelJBPatchProcSecurityMixin."""

from .kernel_jb_base import MOV_X0_0, RET, Counter, _rd32


class KernelJBPatchProcSecurityMixin:
    def patch_proc_security_policy(self):
        """Stub _proc_security_policy: mov x0,#0; ret.

        Anchor: find _proc_info via its distinctive switch-table pattern
        (sub wN,wM,#1; cmp wN,#0x21), then identify _proc_security_policy
        among BL targets — it's called 2+ times, is a small function
        (<0x200 bytes), and is NOT called from the proc_info prologue
        (it's called within switch cases, not before the switch dispatch).
        """
        self._log("\n[JB] _proc_security_policy: mov x0,#0; ret")

        # Try symbol first
        foff = self._resolve_symbol("_proc_security_policy")
        if foff >= 0:
            self.emit(foff, MOV_X0_0, "mov x0,#0 [_proc_security_policy]")
            self.emit(foff + 4, RET, "ret [_proc_security_policy]")
            return True

        # Find _proc_info by switch pattern:
        # sub wN,wM,#1 ; cmp wN,#0x21
        proc_info_func, switch_off = self._find_proc_info_anchor()
        ks, ke = self.kern_text

        if proc_info_func < 0:
            self._log("  [-] _proc_info function not found")
            return False

        proc_info_end = self._find_func_end(proc_info_func, 0x4000)
        self._log(
            f"  [+] _proc_info at 0x{proc_info_func:X} "
            f"(size 0x{proc_info_end - proc_info_func:X})"
        )

        # Count BL targets within _proc_info (only AFTER the switch dispatch,
        # since security policy is called from switch cases not the prologue)
        bl_targets = Counter()
        for off in range(switch_off, proc_info_end, 4):
            insn = _rd32(self.raw, off)
            if (insn & 0xFC000000) != 0x94000000:
                continue
            imm26 = insn & 0x3FFFFFF
            if imm26 & (1 << 25):
                imm26 -= 1 << 26
            target = off + imm26 * 4
            if ks <= target < ke:
                bl_targets[target] += 1

        if not bl_targets:
            self._log("  [-] no BL targets found in _proc_info switch cases")
            return False

        # Find _proc_security_policy among candidates.
        # It's called 2+ times, is a small function (<0x300 bytes),
        # and is NOT a utility like copyio (which is much larger).
        for foff, count in bl_targets.most_common():
            if count < 2:
                break

            func_end = self._find_func_end(foff, 0x400)
            func_size = func_end - foff

            self._log(
                f"  [*] candidate 0x{foff:X}: {count} calls, "
                f"size 0x{func_size:X}"
            )

            # Skip large functions (utilities like copyio are ~0x28C bytes)
            if func_size > 0x200:
                self._log(f"  [-] skipped (too large, likely utility)")
                continue

            # Skip tiny functions (< 0x40 bytes, likely trivial helpers)
            if func_size < 0x40:
                self._log(f"  [-] skipped (too small)")
                continue

            self._log(
                f"  [+] identified _proc_security_policy at 0x{foff:X} "
                f"({count} calls, size 0x{func_size:X})"
            )
            self.emit(foff, MOV_X0_0, "mov x0,#0 [_proc_security_policy]")
            self.emit(foff + 4, RET, "ret [_proc_security_policy]")
            return True

        self._log("  [-] _proc_security_policy not identified among BL targets")
        return False
