"""Base class with all infrastructure for kernel patchers."""

import struct, plistlib, threading
from collections import defaultdict

from capstone.arm64_const import (
    ARM64_OP_REG,
    ARM64_OP_IMM,
    ARM64_REG_W0,
    ARM64_REG_X0,
    ARM64_REG_X8,
)

from .kernel_asm import (
    _cs,
    _rd32,
    _rd64,
    _PACIBSP_U32,
    _FUNC_BOUNDARY_U32S,
)


class KernelPatcherBase:
    def __init__(self, data, verbose=False):
        self.data = data  # bytearray (mutable)
        self.raw = bytes(data)  # immutable snapshot for searching
        self.size = len(data)
        self.patches = []  # collected (offset, bytes, description)
        self._patch_by_off = {}  # offset -> (patch_bytes, desc)
        self.verbose = verbose
        self._patch_num = 0  # running counter for clean one-liners
        self._emit_lock = threading.Lock()

        # Hot-path caches (search/disassembly is repeated heavily in JB mode).
        self._disas_cache = {}
        self._disas_cache_limit = 200_000
        self._string_refs_cache = {}
        self._func_start_cache = {}

        self._log("[*] Parsing Mach-O segments …")
        self._parse_macho()

        self._log("[*] Discovering kext code ranges from __PRELINK_INFO …")
        self._discover_kext_ranges()

        self._log("[*] Building ADRP index …")
        self._build_adrp_index()

        self._log("[*] Building BL index …")
        self._build_bl_index()

        self._find_panic()
        self._log(
            f"[*] _panic at foff 0x{self.panic_off:X}  "
            f"({len(self.bl_callers[self.panic_off])} callers)"
        )

    # ── Logging ──────────────────────────────────────────────────
    def _log(self, msg):
        if self.verbose:
            print(msg)

    def _reset_patch_state(self):
        """Reset patch bookkeeping before a fresh find/apply pass."""
        self.patches = []
        self._patch_by_off = {}
        self._patch_num = 0

    # ── Mach-O / segment parsing ─────────────────────────────────
    def _parse_macho(self):
        """Parse top-level Mach-O: discover BASE_VA, segments, code ranges."""
        magic = _rd32(self.raw, 0)
        if magic != 0xFEEDFACF:
            raise ValueError(f"Not a 64-bit Mach-O (magic 0x{magic:08X})")

        self.code_ranges = []  # [(start_foff, end_foff), ...]
        self.all_segments = []  # [(name, vmaddr, fileoff, filesize, initprot)]
        self.base_va = None

        ncmds = struct.unpack_from("<I", self.raw, 16)[0]
        off = 32  # past mach_header_64
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.raw, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = self.raw[off + 8 : off + 24].split(b"\x00")[0].decode()
                vmaddr, vmsize, fileoff, filesize = struct.unpack_from(
                    "<QQQQ", self.raw, off + 24
                )
                initprot = struct.unpack_from("<I", self.raw, off + 60)[0]
                self.all_segments.append((segname, vmaddr, fileoff, filesize, initprot))
                if segname == "__TEXT":
                    self.base_va = vmaddr
                CODE_SEGS = ("__PRELINK_TEXT", "__TEXT_EXEC", "__TEXT_BOOT_EXEC")
                if segname in CODE_SEGS and filesize > 0:
                    self.code_ranges.append((fileoff, fileoff + filesize))
            off += cmdsize

        if self.base_va is None:
            raise ValueError("__TEXT segment not found — cannot determine BASE_VA")

        self.code_ranges.sort()
        total_mb = sum(e - s for s, e in self.code_ranges) / (1024 * 1024)
        self._log(f"  BASE_VA = 0x{self.base_va:016X}")
        self._log(
            f"  {len(self.code_ranges)} executable ranges, total {total_mb:.1f} MB"
        )

    def _va(self, foff):
        return self.base_va + foff

    def _foff(self, va):
        return va - self.base_va

    # ── Kext range discovery ─────────────────────────────────────
    def _discover_kext_ranges(self):
        """Parse __PRELINK_INFO + embedded kext Mach-Os to find code section ranges."""
        self.kext_ranges = {}  # bundle_id -> (text_start, text_end)

        # Find __PRELINK_INFO segment
        prelink_info = None
        for name, vmaddr, fileoff, filesize, _ in self.all_segments:
            if name == "__PRELINK_INFO":
                prelink_info = (fileoff, filesize)
                break

        if prelink_info is None:
            self._log("  [-] __PRELINK_INFO not found, using __TEXT_EXEC for all")
            self._set_fallback_ranges()
            return

        foff, fsize = prelink_info
        pdata = self.raw[foff : foff + fsize]

        # Parse the XML plist
        xml_start = pdata.find(b"<?xml")
        xml_end = pdata.find(b"</plist>")
        if xml_start < 0 or xml_end < 0:
            self._log("  [-] __PRELINK_INFO plist not found")
            self._set_fallback_ranges()
            return

        xml = pdata[xml_start : xml_end + len(b"</plist>")]
        pl = plistlib.loads(xml)
        items = pl.get("_PrelinkInfoDictionary", [])

        # Kexts we need ranges for
        WANTED = {
            "com.apple.filesystems.apfs": "apfs",
            "com.apple.security.sandbox": "sandbox",
            "com.apple.driver.AppleMobileFileIntegrity": "amfi",
        }

        for item in items:
            bid = item.get("CFBundleIdentifier", "")
            tag = WANTED.get(bid)
            if tag is None:
                continue

            exec_addr = item.get("_PrelinkExecutableLoadAddr", 0) & 0xFFFFFFFFFFFFFFFF
            kext_foff = exec_addr - self.base_va
            if kext_foff < 0 or kext_foff >= self.size:
                continue

            # Parse this kext's embedded Mach-O to find __TEXT_EXEC.__text
            text_range = self._parse_kext_text_exec(kext_foff)
            if text_range:
                self.kext_ranges[tag] = text_range
                self._log(
                    f"  {tag:10s} __text: 0x{text_range[0]:08X} - 0x{text_range[1]:08X} "
                    f"({(text_range[1] - text_range[0]) // 1024} KB)"
                )

        # Derive the ranges used by patch methods
        self._set_ranges_from_kexts()

    def _parse_kext_text_exec(self, kext_foff):
        """Parse an embedded kext Mach-O header and return (__text start, end) in file offsets."""
        if kext_foff + 32 > self.size:
            return None
        magic = _rd32(self.raw, kext_foff)
        if magic != 0xFEEDFACF:
            return None

        ncmds = struct.unpack_from("<I", self.raw, kext_foff + 16)[0]
        off = kext_foff + 32
        for _ in range(ncmds):
            if off + 8 > self.size:
                break
            cmd, cmdsize = struct.unpack_from("<II", self.raw, off)
            if cmd == 0x19:  # LC_SEGMENT_64
                segname = self.raw[off + 8 : off + 24].split(b"\x00")[0].decode()
                if segname == "__TEXT_EXEC":
                    vmaddr = struct.unpack_from("<Q", self.raw, off + 24)[0]
                    filesize = struct.unpack_from("<Q", self.raw, off + 48)[0]
                    nsects = struct.unpack_from("<I", self.raw, off + 64)[0]
                    # Parse sections to find __text
                    sect_off = off + 72
                    for _ in range(nsects):
                        if sect_off + 80 > self.size:
                            break
                        sectname = (
                            self.raw[sect_off : sect_off + 16]
                            .split(b"\x00")[0]
                            .decode()
                        )
                        if sectname == "__text":
                            sect_addr = struct.unpack_from(
                                "<Q", self.raw, sect_off + 32
                            )[0]
                            sect_size = struct.unpack_from(
                                "<Q", self.raw, sect_off + 40
                            )[0]
                            sect_foff = sect_addr - self.base_va
                            return (sect_foff, sect_foff + sect_size)
                        sect_off += 80
                    # No __text section found, use the segment
                    seg_foff = vmaddr - self.base_va
                    return (seg_foff, seg_foff + filesize)
            off += cmdsize
        return None

    def _set_ranges_from_kexts(self):
        """Set patch-method ranges from discovered kext info, with fallbacks."""
        # Full __TEXT_EXEC range
        text_exec = None
        for name, vmaddr, fileoff, filesize, _ in self.all_segments:
            if name == "__TEXT_EXEC":
                text_exec = (fileoff, fileoff + filesize)
                break

        if text_exec is None:
            text_exec = (0, self.size)

        self.text_exec_range = text_exec
        self.apfs_text = self.kext_ranges.get("apfs", text_exec)
        self.amfi_text = self.kext_ranges.get("amfi", text_exec)
        self.sandbox_text = self.kext_ranges.get("sandbox", text_exec)
        # Kernel code = full __TEXT_EXEC (includes all kexts, but that's OK)
        self.kern_text = text_exec

    def _set_fallback_ranges(self):
        """Use __TEXT_EXEC for everything when __PRELINK_INFO is unavailable."""
        text_exec = None
        for name, vmaddr, fileoff, filesize, _ in self.all_segments:
            if name == "__TEXT_EXEC":
                text_exec = (fileoff, fileoff + filesize)
                break
        if text_exec is None:
            text_exec = (0, self.size)

        self.text_exec_range = text_exec
        self.apfs_text = text_exec
        self.amfi_text = text_exec
        self.sandbox_text = text_exec
        self.kern_text = text_exec

    # ── Index builders ───────────────────────────────────────────
    def _build_adrp_index(self):
        """Index ADRP instructions by target page for O(1) string-ref lookup."""
        self.adrp_by_page = defaultdict(list)
        for rng_start, rng_end in self.code_ranges:
            for off in range(rng_start, rng_end, 4):
                insn = _rd32(self.raw, off)
                if (insn & 0x9F000000) != 0x90000000:
                    continue
                rd = insn & 0x1F
                immhi = (insn >> 5) & 0x7FFFF
                immlo = (insn >> 29) & 0x3
                imm = (immhi << 2) | immlo
                if imm & (1 << 20):
                    imm -= 1 << 21
                pc = self._va(off)
                page = (pc & ~0xFFF) + (imm << 12)
                self.adrp_by_page[page].append((off, rd))

        n = sum(len(v) for v in self.adrp_by_page.values())
        self._log(f"  {n} ADRP entries, {len(self.adrp_by_page)} distinct pages")

    def _build_bl_index(self):
        """Index BL instructions by target offset."""
        self.bl_callers = defaultdict(list)  # target_off -> [caller_off, ...]
        for rng_start, rng_end in self.code_ranges:
            for off in range(rng_start, rng_end, 4):
                insn = _rd32(self.raw, off)
                if (insn & 0xFC000000) != 0x94000000:
                    continue
                imm26 = insn & 0x3FFFFFF
                if imm26 & (1 << 25):
                    imm26 -= 1 << 26
                target = off + imm26 * 4
                self.bl_callers[target].append(off)

    def _find_panic(self):
        """Find _panic: most-called function whose callers reference '@%s:%d' strings."""
        candidates = sorted(self.bl_callers.items(), key=lambda x: -len(x[1]))[:15]
        for target_off, callers in candidates:
            if len(callers) < 2000:
                break
            confirmed = 0
            for caller_off in callers[:30]:
                for back in range(caller_off - 4, max(caller_off - 32, 0), -4):
                    insn = _rd32(self.raw, back)
                    # ADD x0, x0, #imm
                    if (insn & 0xFFC003E0) == 0x91000000:
                        add_imm = (insn >> 10) & 0xFFF
                        if back >= 4:
                            prev = _rd32(self.raw, back - 4)
                            if (prev & 0x9F00001F) == 0x90000000:  # ADRP x0
                                immhi = (prev >> 5) & 0x7FFFF
                                immlo = (prev >> 29) & 0x3
                                imm = (immhi << 2) | immlo
                                if imm & (1 << 20):
                                    imm -= 1 << 21
                                pc = self._va(back - 4)
                                page = (pc & ~0xFFF) + (imm << 12)
                                str_foff = self._foff(page + add_imm)
                                if 0 <= str_foff < self.size - 10:
                                    snippet = self.raw[str_foff : str_foff + 60]
                                    if b"@%s:%d" in snippet or b"%s:%d" in snippet:
                                        confirmed += 1
                                        break
                        break
            if confirmed >= 3:
                self.panic_off = target_off
                return
        self.panic_off = candidates[2][0] if len(candidates) > 2 else candidates[0][0]

    # ── Helpers ──────────────────────────────────────────────────
    def _disas_at(self, off, count=1):
        """Disassemble *count* instructions at file offset.  Returns a list."""
        if off < 0 or off >= self.size:
            return []

        key = None
        if count <= 4:
            key = (off, count)
            cached = self._disas_cache.get(key)
            if cached is not None:
                return cached

        end = min(off + count * 4, self.size)
        code = bytes(self.raw[off:end])
        insns = list(_cs.disasm(code, off, count))

        if key is not None:
            if len(self._disas_cache) >= self._disas_cache_limit:
                self._disas_cache.clear()
            self._disas_cache[key] = insns

        return insns

    def _is_bl(self, off):
        """Return BL target file offset, or -1 if not a BL."""
        insns = self._disas_at(off)
        if insns and insns[0].mnemonic == "bl":
            return insns[0].operands[0].imm
        return -1

    def _is_cond_branch_w0(self, off):
        """Return True if instruction is a conditional branch on w0 (cbz/cbnz/tbz/tbnz)."""
        insns = self._disas_at(off)
        if not insns:
            return False
        i = insns[0]
        if i.mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
            return (
                i.operands[0].type == ARM64_OP_REG and i.operands[0].reg == ARM64_REG_W0
            )
        return False

    def find_string(self, s, start=0):
        """Find string, return file offset of the enclosing C string start."""
        if isinstance(s, str):
            s = s.encode()
        off = self.raw.find(s, start)
        if off < 0:
            return -1
        # Walk backward to the preceding NUL — that's the C string start
        cstr = off
        while cstr > 0 and self.raw[cstr - 1] != 0:
            cstr -= 1
        return cstr

    def find_string_refs(self, str_off, code_start=None, code_end=None):
        """Find all (adrp_off, add_off, dest_reg) referencing str_off via ADRP+ADD."""
        key = (str_off, code_start, code_end)
        cached = self._string_refs_cache.get(key)
        if cached is not None:
            return cached

        target_va = self._va(str_off)
        target_page = target_va & ~0xFFF
        page_off = target_va & 0xFFF

        refs = []
        for adrp_off, rd in self.adrp_by_page.get(target_page, []):
            if code_start is not None and adrp_off < code_start:
                continue
            if code_end is not None and adrp_off >= code_end:
                continue
            if adrp_off + 4 >= self.size:
                continue
            nxt = _rd32(self.raw, adrp_off + 4)
            # ADD (imm) 64-bit: 1001_0001_00_imm12_Rn_Rd
            if (nxt & 0xFFC00000) != 0x91000000:
                continue
            add_rn = (nxt >> 5) & 0x1F
            add_imm = (nxt >> 10) & 0xFFF
            if add_rn == rd and add_imm == page_off:
                add_rd = nxt & 0x1F
                refs.append((adrp_off, adrp_off + 4, add_rd))
        self._string_refs_cache[key] = refs
        return refs

    def find_function_start(self, off, max_back=0x4000):
        """Walk backwards to find PACIBSP or STP x29,x30,[sp,#imm].

        When STP x29,x30 is found, continues backward up to 0x20 more
        bytes to look for PACIBSP (ARM64e functions may have several STP
        instructions in the prologue before STP x29,x30).
        """
        use_cache = max_back == 0x4000
        if use_cache:
            cached = self._func_start_cache.get(off)
            if cached is not None:
                return cached

        result = -1
        for o in range(off - 4, max(off - max_back, 0), -4):
            insn = _rd32(self.raw, o)
            if insn == _PACIBSP_U32:
                result = o
                break
            dis = self._disas_at(o)
            if dis and dis[0].mnemonic == "stp" and "x29, x30, [sp" in dis[0].op_str:
                # Check further back for PACIBSP (prologue may have
                # multiple STP instructions before x29,x30)
                for k in range(o - 4, max(o - 0x24, 0), -4):
                    if _rd32(self.raw, k) == _PACIBSP_U32:
                        result = k
                        break
                if result < 0:
                    result = o
                break

        if use_cache:
            self._func_start_cache[off] = result
        return result

    def _disas_n(self, buf, off, count):
        """Disassemble *count* instructions from *buf* at file offset *off*."""
        end = min(off + count * 4, len(buf))
        if off < 0 or off >= len(buf):
            return []
        code = bytes(buf[off:end])
        return list(_cs.disasm(code, off, count))

    def _fmt_insn(self, insn, marker=""):
        """Format one capstone instruction for display."""
        raw = insn.bytes
        hex_str = " ".join(f"{b:02x}" for b in raw)
        s = f"  0x{insn.address:08X}: {hex_str:12s}  {insn.mnemonic:8s} {insn.op_str}"
        if marker:
            s += f"  {marker}"
        return s

    def _print_patch_context(self, off, patch_bytes, desc):
        """Print disassembly before/after a patch site for debugging."""
        ctx = 3  # instructions of context before and after
        # -- BEFORE (original bytes) --
        lines = [f"  ┌─ PATCH 0x{off:08X}: {desc}"]
        lines.append("  │ BEFORE:")
        start = max(off - ctx * 4, 0)
        before_insns = self._disas_n(self.raw, start, ctx + 1 + ctx)
        for insn in before_insns:
            if insn.address == off:
                lines.append(self._fmt_insn(insn, "  ◄━━ PATCHED"))
            elif off < insn.address < off + len(patch_bytes):
                lines.append(self._fmt_insn(insn, "  ◄━━ PATCHED"))
            else:
                lines.append(self._fmt_insn(insn))

        # -- AFTER (new bytes) --
        lines.append("  │ AFTER:")
        after_insns = self._disas_n(self.raw, start, ctx)
        for insn in after_insns:
            lines.append(self._fmt_insn(insn))
        # Decode the patch bytes themselves
        patch_insns = list(_cs.disasm(patch_bytes, off, len(patch_bytes) // 4))
        for insn in patch_insns:
            lines.append(self._fmt_insn(insn, "  ◄━━ NEW"))
        # Trailing context after the patch
        trail_start = off + len(patch_bytes)
        trail_insns = self._disas_n(self.raw, trail_start, ctx)
        for insn in trail_insns:
            lines.append(self._fmt_insn(insn))
        lines.append(f"  └─")
        self._log("\n".join(lines))

    def emit(self, off, patch_bytes, desc):
        """Record a patch and apply it to self.data immediately.

        Writing through to self.data ensures _find_code_cave() sees
        previously allocated shellcode and won't reuse the same cave.
        """
        patch_bytes = bytes(patch_bytes)
        with self._emit_lock:
            existing = self._patch_by_off.get(off)
            if existing is not None:
                existing_bytes, existing_desc = existing
                if existing_bytes != patch_bytes:
                    raise RuntimeError(
                        f"Conflicting patch at 0x{off:08X}: "
                        f"{existing_desc!r} vs {desc!r}"
                    )
                return

            self._patch_by_off[off] = (patch_bytes, desc)
            self.patches.append((off, patch_bytes, desc))
            self.data[off : off + len(patch_bytes)] = patch_bytes
            self._patch_num += 1
            patch_num = self._patch_num
        print(f"  [{patch_num:2d}] 0x{off:08X}  {desc}")
        if self.verbose:
            self._print_patch_context(off, patch_bytes, desc)

    def _find_by_string_in_range(self, string, code_range, label):
        """Find string, find ADRP+ADD ref in code_range, return ref list."""
        str_off = self.find_string(string)
        if str_off < 0:
            self._log(f"  [-] string not found: {string!r}")
            return []
        refs = self.find_string_refs(str_off, code_range[0], code_range[1])
        if not refs:
            self._log(f"  [-] no code refs to {label} (str at 0x{str_off:X})")
        return refs

    # ── Chained fixup pointer decoding ───────────────────────────
    def _decode_chained_ptr(self, val):
        """Decode an arm64e chained fixup pointer to a file offset.

        - auth rebase (bit63=1):     foff = bits[31:0]
        - non-auth rebase (bit63=0): VA = (bits[50:43] << 56) | bits[42:0]
        """
        if val == 0:
            return -1
        if val & (1 << 63):  # auth rebase
            return val & 0xFFFFFFFF
        else:  # non-auth rebase
            target = val & 0x7FFFFFFFFFF  # bits[42:0]
            high8 = (val >> 43) & 0xFF
            full_va = (high8 << 56) | target
            if full_va > self.base_va:
                return full_va - self.base_va
            return -1

    # ═══════════════════════════════════════════════════════════════
    # Per-patch finders
    # ═══════════════════════════════════════════════════════════════

    _COND_BRANCH_MNEMONICS = frozenset(
        (
            "b.eq",
            "b.ne",
            "b.cs",
            "b.hs",
            "b.cc",
            "b.lo",
            "b.mi",
            "b.pl",
            "b.vs",
            "b.vc",
            "b.hi",
            "b.ls",
            "b.ge",
            "b.lt",
            "b.gt",
            "b.le",
            "b.al",
            "cbz",
            "cbnz",
            "tbz",
            "tbnz",
        )
    )

    def _decode_branch_target(self, off):
        """Decode conditional branch at off via capstone. Returns (target, mnemonic) or (None, None)."""
        insns = self._disas_at(off)
        if not insns:
            return None, None
        i = insns[0]
        if i.mnemonic in self._COND_BRANCH_MNEMONICS:
            # Target is always the last IMM operand
            for op in reversed(i.operands):
                if op.type == ARM64_OP_IMM:
                    return op.imm, i.mnemonic
        return None, None

    def _get_kernel_text_range(self):
        """Return (start, end) file offsets of the kernel's own __TEXT_EXEC.__text.

        Parses fileset entries (LC_FILESET_ENTRY) to find the kernel component,
        then reads its Mach-O header to get the __TEXT_EXEC.__text section.
        Falls back to the full __TEXT_EXEC segment.
        """
        # Try fileset entries
        ncmds = struct.unpack_from("<I", self.raw, 16)[0]
        off = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", self.raw, off)
            if cmd == 0x80000035:  # LC_FILESET_ENTRY
                vmaddr = struct.unpack_from("<Q", self.raw, off + 8)[0]
                str_off_in_cmd = struct.unpack_from("<I", self.raw, off + 24)[0]
                entry_id = self.raw[off + str_off_in_cmd :].split(b"\x00")[0].decode()
                if entry_id == "com.apple.kernel":
                    kext_foff = vmaddr - self.base_va
                    text_range = self._parse_kext_text_exec(kext_foff)
                    if text_range:
                        return text_range
            off += cmdsize
        return self.kern_text

    @staticmethod
    def _is_func_boundary(insn):
        """Return True if *insn* typically ends/starts a function."""
        return insn in _FUNC_BOUNDARY_U32S

    def _find_sandbox_ops_table_via_conf(self):
        """Find Sandbox mac_policy_ops table via mac_policy_conf struct."""
        self._log("\n[*] Finding Sandbox mac_policy_ops via mac_policy_conf...")

        seatbelt_off = self.find_string(b"Seatbelt sandbox policy")
        sandbox_raw = self.raw.find(b"\x00Sandbox\x00")
        sandbox_off = sandbox_raw + 1 if sandbox_raw >= 0 else -1
        if seatbelt_off < 0 or sandbox_off < 0:
            self._log("  [-] Sandbox/Seatbelt strings not found")
            return None
        self._log(
            f"  [*] Sandbox string at foff 0x{sandbox_off:X}, "
            f"Seatbelt at 0x{seatbelt_off:X}"
        )

        data_ranges = []
        for name, vmaddr, fileoff, filesize, prot in self.all_segments:
            if name in ("__DATA_CONST", "__DATA") and filesize > 0:
                data_ranges.append((fileoff, fileoff + filesize))

        for d_start, d_end in data_ranges:
            for i in range(d_start, d_end - 40, 8):
                val = _rd64(self.raw, i)
                if val == 0 or (val & (1 << 63)):
                    continue
                if (val & 0x7FFFFFFFFFF) != sandbox_off:
                    continue
                val2 = _rd64(self.raw, i + 8)
                if (val2 & (1 << 63)) or (val2 & 0x7FFFFFFFFFF) != seatbelt_off:
                    continue
                val_ops = _rd64(self.raw, i + 32)
                if not (val_ops & (1 << 63)):
                    ops_off = val_ops & 0x7FFFFFFFFFF
                    self._log(
                        f"  [+] mac_policy_conf at foff 0x{i:X}, "
                        f"mpc_ops -> 0x{ops_off:X}"
                    )
                    return ops_off

        self._log("  [-] mac_policy_conf not found")
        return None

    def _read_ops_entry(self, table_off, index):
        """Read a function pointer from the ops table, handling chained fixups."""
        off = table_off + index * 8
        if off + 8 > self.size:
            return -1
        val = _rd64(self.raw, off)
        if val == 0:
            return 0
        return self._decode_chained_ptr(val)
