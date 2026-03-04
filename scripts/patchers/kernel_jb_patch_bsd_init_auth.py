"""Mixin: KernelJBPatchBsdInitAuthMixin."""

from .kernel_jb_base import MOV_X0_0, _rd32


class KernelJBPatchBsdInitAuthMixin:
    # ldr x0, [xN, #0x2b8]  (ignore xN/Rn)
    _LDR_X0_2B8_MASK = 0xFFFFFC1F
    _LDR_X0_2B8_VAL = 0xF9415C00
    # cbz {w0|x0}, <label> (mask drops sf bit)
    _CBZ_X0_MASK = 0x7F00001F
    _CBZ_X0_VAL = 0x34000000

    def patch_bsd_init_auth(self):
        """Bypass rootvp authentication check in _bsd_init.
        Pattern: ldr x0, [xN, #0x2b8]; cbz x0, ...; bl AUTH_FUNC
        Replace the BL with mov x0, #0.
        """
        self._log("\n[JB] _bsd_init: mov x0,#0 (auth bypass)")

        # Try symbol first
        foff = self._resolve_symbol("_bsd_init")
        if foff >= 0:
            func_end = self._find_func_end(foff, 0x2000)
            result = self._find_auth_bl(foff, func_end)
            if result:
                self.emit(result, MOV_X0_0, "mov x0,#0 [_bsd_init auth]")
                return True

        # Pattern search: ldr x0, [xN, #0x2b8]; cbz x0; bl
        ks, ke = self.kern_text
        candidates = self._collect_auth_bl_candidates(ks, ke)

        if not candidates:
            self._log("  [-] ldr+cbz+bl pattern not found")
            return False

        # Filter to kern_text range (exclude kexts)
        kern_candidates = [c for c in candidates if ks <= c < ke]
        if not kern_candidates:
            kern_candidates = candidates

        # Pick the last one in the kernel (bsd_init is typically late in boot)
        bl_off = kern_candidates[-1]
        self._log(
            f"  [+] auth BL at 0x{bl_off:X} ({len(kern_candidates)} kern candidates)"
        )
        self.emit(bl_off, MOV_X0_0, "mov x0,#0 [_bsd_init auth]")
        return True

    def _find_auth_bl(self, start, end):
        """Find ldr x0,[xN,#0x2b8]; cbz x0; bl pattern. Returns BL offset."""
        cands = self._collect_auth_bl_candidates(start, end)
        if cands:
            return cands[0]

        # Fallback for unexpected instruction variants.
        for off in range(start, end - 8, 4):
            d = self._disas_at(off, 3)
            if len(d) < 3:
                continue
            i0, i1, i2 = d[0], d[1], d[2]
            if i0.mnemonic == "ldr" and i1.mnemonic == "cbz" and i2.mnemonic == "bl":
                if i0.op_str.startswith("x0,") and "#0x2b8" in i0.op_str:
                    if i1.op_str.startswith("x0,"):
                        return off + 8
        return None

    def _collect_auth_bl_candidates(self, start, end):
        """Fast matcher using raw instruction masks (no capstone in hot loop)."""
        out = []
        limit = min(end - 8, self.size - 8)
        for off in range(max(start, 0), limit, 4):
            i0 = _rd32(self.raw, off)
            if (i0 & self._LDR_X0_2B8_MASK) != self._LDR_X0_2B8_VAL:
                continue

            i1 = _rd32(self.raw, off + 4)
            if (i1 & self._CBZ_X0_MASK) != self._CBZ_X0_VAL:
                continue

            i2 = _rd32(self.raw, off + 8)
            if (i2 & 0xFC000000) != 0x94000000:  # BL imm26
                continue

            out.append(off + 8)
        return out
