"""Mixin: debugger enablement patch."""

from .kernel_asm import MOV_X0_1, RET, _rd32, _rd64

_GPR_X8_NUM = 8


class KernelPatchDebuggerMixin:
    def _is_adrp_x8(self, insn):
        """Fast raw check: ADRP x8, <page>."""
        return (insn & 0x9F000000) == 0x90000000 and (insn & 0x1F) == _GPR_X8_NUM

    def _has_w_ldr_from_x8(self, func_off, max_insns=8):
        """Heuristic: first few instructions include ldr wN, [x8, ...]."""
        for k in range(1, max_insns + 1):
            off = func_off + k * 4
            if off >= self.size:
                break
            dk = self._disas_at(off)
            if (
                dk
                and dk[0].mnemonic == "ldr"
                and dk[0].op_str.startswith("w")
                and "x8" in dk[0].op_str
            ):
                return True
        return False

    def _find_debugger_by_bl_histogram(self, kern_text_start, kern_text_end):
        """Find target from BL call histogram to avoid full __text scan."""
        best_off = -1
        best_callers = 0
        for target_off, callers in self.bl_callers.items():
            n_callers = len(callers)
            # _PE_i_can_has_debugger is broadly used but far from panic-level fanout.
            if n_callers < 50 or n_callers > 250:
                continue
            if target_off < kern_text_start or target_off >= kern_text_end:
                continue
            if target_off + 4 > self.size or (target_off & 3):
                continue

            first_insn = _rd32(self.raw, target_off)
            if not self._is_adrp_x8(first_insn):
                continue

            if target_off >= 4 and not self._is_func_boundary(
                _rd32(self.raw, target_off - 4)
            ):
                continue

            if not self._has_w_ldr_from_x8(target_off):
                continue

            if n_callers > best_callers:
                best_callers = n_callers
                best_off = target_off

        return best_off, best_callers

    def patch_PE_i_can_has_debugger(self):
        """Patches 6-7: mov x0,#1; ret at _PE_i_can_has_debugger."""
        self._log("\n[6-7] _PE_i_can_has_debugger: stub with mov x0,#1; ret")

        # Strategy 1: find symbol name in __LINKEDIT and parse nearby VA
        str_off = self.find_string(b"\x00_PE_i_can_has_debugger\x00")
        if str_off < 0:
            str_off = self.find_string(b"PE_i_can_has_debugger")
        if str_off >= 0:
            linkedit = None
            for name, vmaddr, fileoff, filesize, _ in self.all_segments:
                if name == "__LINKEDIT":
                    linkedit = (fileoff, fileoff + filesize)
            if linkedit and linkedit[0] <= str_off < linkedit[1]:
                name_end = self.raw.find(b"\x00", str_off + 1)
                if name_end > 0:
                    for probe in range(name_end + 1, min(name_end + 32, self.size - 7)):
                        val = _rd64(self.raw, probe)
                        func_foff = val - self.base_va
                        if self.kern_text[0] <= func_foff < self.kern_text[1]:
                            first_insn = _rd32(self.raw, func_foff)
                            if first_insn != 0 and first_insn != 0xD503201F:
                                self.emit(
                                    func_foff,
                                    MOV_X0_1,
                                    "mov x0,#1 [_PE_i_can_has_debugger]",
                                )
                                self.emit(
                                    func_foff + 4, RET, "ret [_PE_i_can_has_debugger]"
                                )
                                return True

        # Strategy 2: pick candidates from BL histogram + lightweight signature checks.
        self._log("  [*] trying code pattern search...")

        # Determine kernel-only __text range from fileset entries if available
        kern_text_start, kern_text_end = self._get_kernel_text_range()

        best_off, best_callers = self._find_debugger_by_bl_histogram(
            kern_text_start, kern_text_end
        )

        if best_off >= 0:
            self._log(
                f"  [+] code pattern match at 0x{best_off:X} ({best_callers} callers)"
            )
            self.emit(best_off, MOV_X0_1, "mov x0,#1 [_PE_i_can_has_debugger]")
            self.emit(best_off + 4, RET, "ret [_PE_i_can_has_debugger]")
            return True

        # Strategy 3 (fallback): full-range scan with raw opcode pre-filtering.
        # Keeps cross-variant resilience while avoiding capstone on every address.
        self._log("  [*] trying full scan fallback...")
        best_off = -1
        best_callers = 0
        for off in range(kern_text_start, kern_text_end - 12, 4):
            first_insn = _rd32(self.raw, off)
            if not self._is_adrp_x8(first_insn):
                continue
            if off >= 4 and not self._is_func_boundary(_rd32(self.raw, off - 4)):
                continue
            if not self._has_w_ldr_from_x8(off):
                continue

            n_callers = len(self.bl_callers.get(off, []))
            if 50 <= n_callers <= 250 and n_callers > best_callers:
                best_callers = n_callers
                best_off = off

        if best_off >= 0:
            self._log(
                f"  [+] fallback match at 0x{best_off:X} ({best_callers} callers)"
            )
            self.emit(best_off, MOV_X0_1, "mov x0,#1 [_PE_i_can_has_debugger]")
            self.emit(best_off + 4, RET, "ret [_PE_i_can_has_debugger]")
            return True

        self._log("  [-] function not found")
        return False
