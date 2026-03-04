"""kernel_jb.py — Jailbreak extension patcher for iOS kernelcache."""

import time

from .kernel_jb_base import KernelJBPatcherBase
from .kernel_jb_patch_amfi_trustcache import KernelJBPatchAmfiTrustcacheMixin
from .kernel_jb_patch_amfi_execve import KernelJBPatchAmfiExecveMixin
from .kernel_jb_patch_task_conversion import KernelJBPatchTaskConversionMixin
from .kernel_jb_patch_sandbox_extended import KernelJBPatchSandboxExtendedMixin
from .kernel_jb_patch_post_validation import KernelJBPatchPostValidationMixin
from .kernel_jb_patch_proc_security import KernelJBPatchProcSecurityMixin
from .kernel_jb_patch_proc_pidinfo import KernelJBPatchProcPidinfoMixin
from .kernel_jb_patch_port_to_map import KernelJBPatchPortToMapMixin
from .kernel_jb_patch_vm_fault import KernelJBPatchVmFaultMixin
from .kernel_jb_patch_vm_protect import KernelJBPatchVmProtectMixin
from .kernel_jb_patch_mac_mount import KernelJBPatchMacMountMixin
from .kernel_jb_patch_dounmount import KernelJBPatchDounmountMixin
from .kernel_jb_patch_bsd_init_auth import KernelJBPatchBsdInitAuthMixin
from .kernel_jb_patch_spawn_persona import KernelJBPatchSpawnPersonaMixin
from .kernel_jb_patch_task_for_pid import KernelJBPatchTaskForPidMixin
from .kernel_jb_patch_load_dylinker import KernelJBPatchLoadDylinkerMixin
from .kernel_jb_patch_shared_region import KernelJBPatchSharedRegionMixin
from .kernel_jb_patch_nvram import KernelJBPatchNvramMixin
from .kernel_jb_patch_secure_root import KernelJBPatchSecureRootMixin
from .kernel_jb_patch_thid_crash import KernelJBPatchThidCrashMixin
from .kernel_jb_patch_cred_label import KernelJBPatchCredLabelMixin
from .kernel_jb_patch_syscallmask import KernelJBPatchSyscallmaskMixin
from .kernel_jb_patch_hook_cred_label import KernelJBPatchHookCredLabelMixin
from .kernel_jb_patch_kcall10 import KernelJBPatchKcall10Mixin


class KernelJBPatcher(
    KernelJBPatchKcall10Mixin,
    KernelJBPatchHookCredLabelMixin,
    KernelJBPatchSyscallmaskMixin,
    KernelJBPatchCredLabelMixin,
    KernelJBPatchThidCrashMixin,
    KernelJBPatchSecureRootMixin,
    KernelJBPatchNvramMixin,
    KernelJBPatchSharedRegionMixin,
    KernelJBPatchLoadDylinkerMixin,
    KernelJBPatchTaskForPidMixin,
    KernelJBPatchSpawnPersonaMixin,
    KernelJBPatchBsdInitAuthMixin,
    KernelJBPatchDounmountMixin,
    KernelJBPatchMacMountMixin,
    KernelJBPatchVmProtectMixin,
    KernelJBPatchVmFaultMixin,
    KernelJBPatchPortToMapMixin,
    KernelJBPatchProcPidinfoMixin,
    KernelJBPatchProcSecurityMixin,
    KernelJBPatchPostValidationMixin,
    KernelJBPatchSandboxExtendedMixin,
    KernelJBPatchTaskConversionMixin,
    KernelJBPatchAmfiExecveMixin,
    KernelJBPatchAmfiTrustcacheMixin,
    KernelJBPatcherBase,
):
    _TIMING_LOG_MIN_SECONDS = 10.0

    _GROUP_AB_METHODS = (
        "patch_amfi_cdhash_in_trustcache",      # A1
        "patch_amfi_execve_kill_path",          # A2
        "patch_task_conversion_eval_internal",  # A3
        "patch_sandbox_hooks_extended",         # A4
        "patch_post_validation_additional",     # B5
        "patch_proc_security_policy",           # B6
        "patch_proc_pidinfo",                   # B7
        "patch_convert_port_to_map",            # B8
        "patch_vm_fault_enter_prepare",         # B9
        "patch_vm_map_protect",                 # B10
        "patch_mac_mount",                      # B11
        "patch_dounmount",                      # B12
        "patch_bsd_init_auth",                  # B13
        "patch_spawn_validate_persona",         # B14
        "patch_task_for_pid",                   # B15
        "patch_load_dylinker",                  # B16
        "patch_shared_region_map",              # B17
        "patch_nvram_verify_permission",        # B18
        "patch_io_secure_bsd_root",             # B19
        "patch_thid_should_crash",              # B20
    )
    _GROUP_C_METHODS = (
        "patch_cred_label_update_execve",       # C21
        "patch_syscallmask_apply_to_proc",      # C22
        "patch_hook_cred_label_update_execve",  # C23
        "patch_kcall10",                        # C24
    )

    def __init__(self, data, verbose=False):
        super().__init__(data, verbose)
        self.patch_timings = []

    def _run_patch_method_timed(self, method_name):
        before = len(self.patches)
        t0 = time.perf_counter()
        getattr(self, method_name)()
        dt = time.perf_counter() - t0
        added = len(self.patches) - before
        self.patch_timings.append((method_name, dt, added))
        if dt >= self._TIMING_LOG_MIN_SECONDS:
            print(f"  [T] {method_name:36s} {dt:7.3f}s  (+{added})")

    def _run_methods(self, methods):
        for method_name in methods:
            self._run_patch_method_timed(method_name)

    def _print_timing_summary(self):
        if not self.patch_timings:
            return
        slow_items = [
            item
            for item in sorted(self.patch_timings, key=lambda item: item[1], reverse=True)
            if item[1] >= self._TIMING_LOG_MIN_SECONDS
        ]
        if not slow_items:
            return

        print(
            "\n  [Timing Summary] JB patch method cost (desc, >= "
            f"{self._TIMING_LOG_MIN_SECONDS:.0f}s):"
        )
        for method_name, dt, added in slow_items:
            print(f"    {dt:7.3f}s  (+{added:3d})  {method_name}")

    def find_all(self):
        self._reset_patch_state()
        self.patch_timings = []

        self._run_methods(self._GROUP_AB_METHODS)
        self._run_methods(self._GROUP_C_METHODS)
        self._print_timing_summary()

        return self.patches

    def apply(self):
        patches = self.find_all()
        for off, patch_bytes, _ in patches:
            self.data[off : off + len(patch_bytes)] = patch_bytes
        return len(patches)

    # ══════════════════════════════════════════════════════════════
    # Group A: Existing patches (unchanged)
    # ══════════════════════════════════════════════════════════════
