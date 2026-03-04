"""Mixin: KernelJBPatchProcPidinfoMixin."""

from .kernel_jb_base import NOP


class KernelJBPatchProcPidinfoMixin:
    def patch_proc_pidinfo(self):
        """Bypass pid-0 checks in _proc_info: NOP first 2 CBZ/CBNZ on w-regs.

        Anchor: find _proc_info via its switch-table pattern, then NOP the
        first two CBZ/CBNZ instructions that guard against pid 0.
        """
        self._log("\n[JB] _proc_pidinfo: NOP pid-0 guard (2 sites)")

        # Try symbol first
        foff = self._resolve_symbol("_proc_pidinfo")
        if foff >= 0:
            func_end = min(foff + 0x80, self.size)
            hits = []
            for off in range(foff, func_end, 4):
                d = self._disas_at(off)
                if (
                    d
                    and d[0].mnemonic in ("cbz", "cbnz")
                    and d[0].op_str.startswith("w")
                ):
                    hits.append(off)
            if len(hits) >= 2:
                self.emit(hits[0], NOP, "NOP [_proc_pidinfo pid-0 guard A]")
                self.emit(hits[1], NOP, "NOP [_proc_pidinfo pid-0 guard B]")
                return True

        # Reuse proc_info anchor from proc_security path (cached).
        proc_info_func, _ = self._find_proc_info_anchor()

        if proc_info_func < 0:
            self._log("  [-] _proc_info function not found")
            return False

        # Find first CBZ x0 (null proc check) and the CBZ/CBNZ wN after
        # the first BL in the prologue region
        hits = []
        prologue_end = min(proc_info_func + 0x80, self.size)
        for off in range(proc_info_func, prologue_end, 4):
            d = self._disas_at(off)
            if not d:
                continue
            i = d[0]
            if i.mnemonic in ("cbz", "cbnz"):
                # CBZ x0 (null check) or CBZ wN (pid-0 check)
                hits.append(off)

        if len(hits) < 2:
            self._log(f"  [-] expected 2+ early CBZ/CBNZ, found {len(hits)}")
            return False

        self.emit(hits[0], NOP, "NOP [_proc_pidinfo pid-0 guard A]")
        self.emit(hits[1], NOP, "NOP [_proc_pidinfo pid-0 guard B]")
        return True
