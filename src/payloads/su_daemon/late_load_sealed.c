#define _GNU_SOURCE

#include "su_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/*
 * Loading KernelSU into a running kernel, and nothing else.
 *
 * This is the whole of what the helper knows about KernelSU. It was in
 * su_daemon.c, where it carried two values that belong to a target rather than
 * to a helper shipped once for all of them:
 *
 *     execl(..., "late-load", "--kmi", "android15-6.6",
 *                "--package-name", "me.weishu.kernelsu", NULL);
 *
 * ksud embeds one module per KMI and picks by the name it is given, so that
 * literal silently loaded nothing on any kernel that was not android15-6.6 --
 * a device failure, in a value that could not be seen from the device. They
 * are now required arguments. src/targets.json carries both per target, the
 * feed passes them to the application, and the application passes them here;
 * no default is kept, because a default is what the mistake was.
 */

/* The shell-owned input is only a transport. It is opened without following a
 * link, claimed by root, optionally checked against a compile-time digest, and
 * copied below PRIVATE_STAGE_ROOT.  When no compile-time pin is supplied, the
 * securely claimed inode's digest becomes the run pin.  Only that private copy
 * is ever bind-mounted over the otherwise-idle executable cover. */
#define KSUD_PATH "/data/local/tmp/ksud"
#define LOGCAT_PATH "/system/bin/logcat"
#define ADB_DIR "/data/adb"
/* Stable pathname shared with the sealed KernelSU patch protocol.  The legacy
 * name is retained as an on-disk ABI; it is not used to select a device. */
#define PRIVATE_STAGE_ROOT "/data/adb/.rmd-late-load"
#define PRIVATE_EXEC_NAME "ksud-exec"
#define PRIVATE_STAGE_NAME "ksud-stage"
#define PRIVATE_LOCK_NAME "late-load.lock"
#define PRIVATE_MODULE_STATUS_NAME "modules-loaded"
#define PUBLIC_MODULE_STATUS_DIR "/data/local/tmp"
#define PUBLIC_MODULE_STATUS_NAME ".ksu-late-load-modules-ok"
#define INSTALLED_KSUD_NAME "ksud"
#define KSU_STAGE_PATH_ENV "KSU_LATE_LOAD_STAGED_DAEMON"
#define KSU_STAGE_SHA256_ENV "KSU_LATE_LOAD_STAGED_SHA256"
#define KSU_LATE_LOAD_RUN_ID_ENV "KSU_LATE_LOAD_RUN_ID"
#define KSU_LATE_LOAD_CLEANUP_KPTR_ENV "KSU_LATE_LOAD_CLEANUP_KPTR"
#define KSU_LATE_LOAD_CLEANUP_MODULES_ENV "KSU_LATE_LOAD_CLEANUP_MODULES"
#define KSUD_MAX_SIZE (64U * 1024U * 1024U)

/*
 * ksud does not install itself from where it runs; it *renames* a file the
 * helper gives it through KSU_LATE_LOAD_STAGED_DAEMON:
 *
 *     /data/adb/.rmd-late-load/<pid>/ksud-stage
 *         -> std::fs::rename(staged, "/data/adb/ksud")
 *
 * (Root-My-Device-KSU, patches/<version>/common/0001-ksud-staged-late-load.patch.
 * It is a rename rather than a copy on purpose: the copy has to happen before
 * loading the module changes this process's security context, and by the time
 * ksud runs it is already too late to read its own image.)
 *
 * Both the executable copy and the rename source are hard links in a root:root
 * 0700 directory. ksud checks the expected SHA-256 before and after the rename,
 * and this helper checks /data/adb/ksud again after ksud exits. No pathname in
 * the shell-writable public directory participates in the privileged rename.
 */
#define MODULE_STATUS_PATH PRIVATE_STAGE_ROOT "/" PRIVATE_MODULE_STATUS_NAME

/*
 * What this returns, and why the number is the part that matters.
 *
 * Everything below reports with dprintf to the caller's stdout and stderr,
 * which arrive here as descriptors passed over the socket and which belong to
 * adbd. Writing to them from the daemon's own domain is already a denial --
 * `scontext=u:r:kernel:s0 tcontext=u:r:adbd:s0 tclass=fd { use }`, recorded
 * while the exploit still had SELinux permissive. ksud then reloads the policy
 * as part of loading the module, enforcing comes back, and from that moment
 * every dprintf in this file is dropped. The operation silences its own
 * reporting halfway through, and it does it just before the part worth
 * reporting.
 *
 * The status goes the other way: su_daemon.c hands it to send_response on the
 * daemon's own socket, and the client returns it as its exit code. That is the
 * one channel the reload cannot touch, so the status is the report, and
 * su_late_load_report_sealed() below is what turns it back into a line -- printed by
 * the client, in the caller's own domain, where writing to the caller's stderr
 * is never in question.
 *
 * KSUD is a band rather than one code because ksud's own exit status used to
 * be returned raw, where it collided with every code here: an exit code of 13
 * could be this file's "driver fd unavailable" or ksud exiting 13, and nothing
 * distinguished them.
 */
#define LATE_LOAD_STATUS_OK 0
#define LATE_LOAD_STATUS_NAMESPACE 10
#define LATE_LOAD_STATUS_BIND 11
#define LATE_LOAD_STATUS_EXEC 12
#define LATE_LOAD_STATUS_NO_DRIVER 13
#define LATE_LOAD_STATUS_CONTROL 14
#define LATE_LOAD_STATUS_STAGE 15
#define LATE_LOAD_STATUS_SELINUX 16
#define LATE_LOAD_STATUS_KPTR 17
#define LATE_LOAD_STATUS_KPTR_RESTORE 18
#define LATE_LOAD_STATUS_INTEGRITY 19
#define LATE_LOAD_STATUS_BUSY 20
#define LATE_LOAD_STATUS_CHILD_SETUP 21
#define LATE_LOAD_STATUS_USAGE 22
#define LATE_LOAD_STATUS_KSU_CLEAN_ABORT 23
#define LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS 24
#define LATE_LOAD_STATUS_KSUD 64
#define LATE_LOAD_STATUS_KSUD_SPAN 64
#define LATE_LOAD_STATUS_KSUD_SIGNAL 128
#define LATE_LOAD_STATUS_KSUD_SIGNAL_SPAN 64
#define KSU_LATE_LOAD_CLEAN_ABORT_EXIT 200
#define KSU_LATE_LOAD_CLEAN_SUCCESS_EXIT 201
#define LATE_LOAD_WORKER_TIMEOUT_SECONDS 180
#define LATE_LOAD_WATCHER_TIMEOUT_SECONDS 210
#define LATE_LOAD_WATCHER_HANDSHAKE_MS 5000
#define LATE_LOAD_WATCHER_REAP_MS 5000

enum late_load_watch_decision {
  LATE_LOAD_WATCH_PENDING = 0,
  LATE_LOAD_WATCH_PREPARE = 1,
  LATE_LOAD_WATCH_FINAL = 2,
  LATE_LOAD_WATCH_ABORT = 3,
};

enum late_load_watch_ack {
  LATE_LOAD_WATCH_ACK_NONE = 0,
  LATE_LOAD_WATCH_ACK_PREPARE = 1,
  LATE_LOAD_WATCH_ACK_FINAL = 2,
  LATE_LOAD_WATCH_ACK_ABORT_CLEAN = 3,
  LATE_LOAD_WATCH_ACK_FAILED = -1,
};

enum late_load_watch_state {
  LATE_LOAD_WATCH_INIT = 0,
  LATE_LOAD_WATCH_ARMED = 1,
  LATE_LOAD_WATCH_CLEANING = 2,
  LATE_LOAD_WATCH_FAILED = 99,
};

enum late_load_worker_state {
  LATE_LOAD_WORKER_NONE = 0,
  LATE_LOAD_WORKER_READY = 1,
  LATE_LOAD_WORKER_PINNED = 2,
  LATE_LOAD_WORKER_RUNNING = 3,
  LATE_LOAD_WORKER_DONE = 4,
  LATE_LOAD_WORKER_FAILED = 99,
};

/* Anonymous MAP_SHARED state is the only control surface between the request
 * handler and its root watcher.  The parent pidfd is inherited across fork,
 * so parent-death detection cannot be fooled by PID reuse.  A worker is held
 * at a private bootstrap barrier until the watcher has pinned that worker with
 * a second pidfd; only then may it fork/exec the loader. */
struct late_load_watch_mailbox {
  atomic_int watcher_state;
  atomic_int watcher_pid;
  atomic_int decision;
  atomic_int ack;
  atomic_int parent_cleanup_ready;
  atomic_int parent_status;
  atomic_int worker_state;
  atomic_int worker_pid;
  atomic_int worker_release;
  atomic_int ksu_cleanup_proven;
  atomic_int ksu_success_proven;
  int original_kptr;
  int enable_modules;
  pid_t parent_pid;
};

_Static_assert(ATOMIC_INT_LOCK_FREE == 2,
               "late-load process-shared atomics must be lock-free");
_Static_assert(sizeof(atomic_int) == sizeof(int),
               "late-load mailbox assumes native int atomics");

/* A small self-contained SHA-256 keeps the trust check inside the already-root
 * helper. Android's NDK does not expose a stable libcrypto ABI, and invoking a
 * pathname-based sha256sum would put the path race back into the check. */
struct sha256_ctx {
  uint32_t state[8];
  uint64_t bytes;
  unsigned char block[64];
  size_t used;
};

static uint32_t sha256_rotr(uint32_t value, unsigned int shift) {
  return (value >> shift) | (value << (32U - shift));
}

static void sha256_transform(struct sha256_ctx *ctx,
                             const unsigned char block[64]) {
  static const uint32_t k[64] = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
      0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
      0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
      0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
      0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
      0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
      0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
  };
  uint32_t words[64];
  for (size_t i = 0; i < 16; i++) {
    words[i] = ((uint32_t)block[i * 4] << 24) |
               ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) |
               (uint32_t)block[i * 4 + 3];
  }
  for (size_t i = 16; i < 64; i++) {
    uint32_t s0 = sha256_rotr(words[i - 15], 7) ^
                  sha256_rotr(words[i - 15], 18) ^ (words[i - 15] >> 3);
    uint32_t s1 = sha256_rotr(words[i - 2], 17) ^
                  sha256_rotr(words[i - 2], 19) ^ (words[i - 2] >> 10);
    words[i] = words[i - 16] + s0 + words[i - 7] + s1;
  }

  uint32_t a = ctx->state[0];
  uint32_t b = ctx->state[1];
  uint32_t c = ctx->state[2];
  uint32_t d = ctx->state[3];
  uint32_t e = ctx->state[4];
  uint32_t f = ctx->state[5];
  uint32_t g = ctx->state[6];
  uint32_t h = ctx->state[7];
  for (size_t i = 0; i < 64; i++) {
    uint32_t upper = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^
                     sha256_rotr(e, 25);
    uint32_t choose = (e & f) ^ ((~e) & g);
    uint32_t t1 = h + upper + choose + k[i] + words[i];
    uint32_t lower = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^
                     sha256_rotr(a, 22);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t t2 = lower + majority;
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  ctx->state[0] += a;
  ctx->state[1] += b;
  ctx->state[2] += c;
  ctx->state[3] += d;
  ctx->state[4] += e;
  ctx->state[5] += f;
  ctx->state[6] += g;
  ctx->state[7] += h;
}

static void sha256_init(struct sha256_ctx *ctx) {
  static const uint32_t initial[8] = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  memcpy(ctx->state, initial, sizeof(initial));
  ctx->bytes = 0;
  ctx->used = 0;
}

static void sha256_update(struct sha256_ctx *ctx, const void *data, size_t len) {
  const unsigned char *at = data;
  ctx->bytes += len;
  while (len) {
    size_t room = sizeof(ctx->block) - ctx->used;
    size_t take = len < room ? len : room;
    memcpy(ctx->block + ctx->used, at, take);
    ctx->used += take;
    at += take;
    len -= take;
    if (ctx->used == sizeof(ctx->block)) {
      sha256_transform(ctx, ctx->block);
      ctx->used = 0;
    }
  }
}

static void sha256_final(struct sha256_ctx *ctx, unsigned char digest[32]) {
  uint64_t bits = ctx->bytes * 8U;
  ctx->block[ctx->used++] = 0x80;
  if (ctx->used > 56) {
    memset(ctx->block + ctx->used, 0, sizeof(ctx->block) - ctx->used);
    sha256_transform(ctx, ctx->block);
    ctx->used = 0;
  }
  memset(ctx->block + ctx->used, 0, 56 - ctx->used);
  for (size_t i = 0; i < 8; i++) {
    ctx->block[63 - i] = (unsigned char)(bits >> (i * 8));
  }
  sha256_transform(ctx, ctx->block);
  for (size_t i = 0; i < 8; i++) {
    digest[i * 4] = (unsigned char)(ctx->state[i] >> 24);
    digest[i * 4 + 1] = (unsigned char)(ctx->state[i] >> 16);
    digest[i * 4 + 2] = (unsigned char)(ctx->state[i] >> 8);
    digest[i * 4 + 3] = (unsigned char)ctx->state[i];
  }
}

static int sha256_fd(int fd, unsigned char digest[32]) {
  if (lseek(fd, 0, SEEK_SET) < 0) {
    return 0;
  }
  struct sha256_ctx ctx;
  sha256_init(&ctx);
  unsigned char buffer[65536];
  for (;;) {
    ssize_t got = read(fd, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got < 0) {
      return 0;
    }
    if (got == 0) {
      break;
    }
    sha256_update(&ctx, buffer, (size_t)got);
  }
  sha256_final(&ctx, digest);
  return lseek(fd, 0, SEEK_SET) >= 0;
}

static void sha256_hex(const unsigned char digest[32], char output[65]) {
  static const char digits[] = "0123456789abcdef";
  for (size_t i = 0; i < 32; i++) {
    output[i * 2] = digits[digest[i] >> 4];
    output[i * 2 + 1] = digits[digest[i] & 0x0f];
  }
  output[64] = '\0';
}

/*
 * argv is `su --late-load <kmi> <package> [allow-shell] [modules]`.
 *
 * The optional fourth word is for bring-up. KernelSU decides who may become
 * root from its own allowlist, which on a fresh late-load holds only the
 * manager; `allow-shell` passes ksud's --allow-shell so `su` answers the adb
 * shell too, which is the only way to demonstrate KernelSU's own root without
 * a working manager app. The application does not pass it and should not: it
 * hands root to anyone with adb for as long as the module is loaded.
 */
#define LATE_LOAD_ARGC 4U
#define LATE_LOAD_ARGC_MAX 7U
#define LATE_LOAD_KMI_ARG 2U
#define LATE_LOAD_PACKAGE_ARG 3U
#define LATE_LOAD_OPTIONS_ARG 4U
#define LATE_LOAD_ALLOW_SHELL_WORD "allow-shell"
#define LATE_LOAD_MODULES_WORD "modules"
#define LATE_LOAD_RUN_ID_PREFIX "run-id="
#define LATE_LOAD_RUN_ID_HEX_LEN 32U

#define SELINUX_POLICY_PATH "/sys/fs/selinux/policy"
#define SELINUX_LOAD_PATH "/sys/fs/selinux/load"
#define SELINUX_POLICY_MAX (32U * 1024U * 1024U)

#ifndef SELINUX_MAGIC
#define SELINUX_MAGIC 0xf97cff8cUL
#endif

static int trusted_selinux_enforce_fd(int fd, struct stat *identity) {
  struct stat st;
  struct statfs fs;
  if (fstat(fd, &st) != 0 || fstatfs(fd, &fs) != 0 ||
      !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
      st.st_nlink != 1 || (st.st_mode & 07777) != 0644 ||
      (unsigned long)fs.f_type != SELINUX_MAGIC) {
    return 0;
  }
  if (identity) {
    *identity = st;
  }
  return 1;
}

/*
 * /sys/fs/selinux/enforce has to read back as exactly "0" here: the exploit
 * cleared it and nothing since is supposed to have touched it. A run has been
 * seen where it read "166" -- a byte of a kernel pointer, not a boolean --
 * which is the residual writer described in su_daemon.c landing on this word
 * instead of the boot_id one. Nothing here can repair that byte, so this only
 * reports it; but it is the difference between "ksud turned enforcing back on"
 * and "the SELinux state was already garbage", and that belongs in the log
 * rather than in what the device does afterwards.
 */
static int enforcing_is_exactly_zero(int report_fd) {
  char value[16];
  int fd = open("/sys/fs/selinux/enforce",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: selinux enforce unreadable: %s\n",
            strerror(errno));
    return 0;
  }
  if (!trusted_selinux_enforce_fd(fd, NULL)) {
    dprintf(report_fd, "late-load: selinux enforce inode/filesystem refused\n");
    close(fd);
    return 0;
  }
  ssize_t got = read(fd, value, sizeof(value) - 1);
  int saved_errno = errno;
  close(fd);
  if (got <= 0) {
    dprintf(report_fd, "late-load: selinux enforce read failed: %s\n",
            strerror(saved_errno));
    return 0;
  }
  value[got] = '\0';
  if (got != 1 || value[0] != '0') {
    dprintf(report_fd,
            "late-load: selinux enforce reads '%s', expected '0' -- the state "
            "word has been written again since the exploit cleared it\n",
            value);
    return 0;
  }
  return 1;
}

static int enforcing_is_exactly_one(int report_fd) {
  char value[4] = {0};
  int fd = open("/sys/fs/selinux/enforce",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: final selinux enforce unreadable: %s\n",
            strerror(errno));
    return 0;
  }
  if (!trusted_selinux_enforce_fd(fd, NULL)) {
    dprintf(report_fd,
            "late-load: final selinux enforce inode/filesystem refused\n");
    close(fd);
    return 0;
  }
  ssize_t got = read(fd, value, sizeof(value));
  int saved_errno = errno;
  close(fd);
  if (got < 0) {
    dprintf(report_fd, "late-load: final selinux enforce read failed: %s\n",
            strerror(saved_errno));
    return 0;
  }
  if (!((got == 1 && value[0] == '1') ||
        (got == 2 && value[0] == '1' && value[1] == '\n'))) {
    dprintf(report_fd,
            "late-load: KernelSU returned without exact enforcing=1 readback\n");
    return 0;
  }
  return 1;
}

/*
 * The worker normally leaves this transition to ksud, after the replacement
 * policy and KernelSU control path have both been verified.  Its waiting
 * parent is nevertheless the last-resort owner of the global state: a killed
 * or wedged worker must not leave SELinux permissive indefinitely.  The
 * parent still has the root/kernel credential used to start the daemon, and
 * this write is made while the old state is permissive, so the setenforce
 * permission check cannot prevent the recovery transition.
 *
 * Return 1 when enforcing was already exact, 2 when this function restored
 * it, and 0 when neither state nor recovery could be verified.  A successful
 * worker is accepted only with return 1; needing the watchdog after a nominal
 * success is itself a failed late-load completion.
 */
static int ensure_enforcing_one_after_worker(int report_fd) {
  char value[4] = {0};
  struct stat read_identity;
  int fd = open("/sys/fs/selinux/enforce",
                O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: watchdog cannot read selinux enforce: %s\n",
            strerror(errno));
    return 0;
  }
  if (!trusted_selinux_enforce_fd(fd, &read_identity)) {
    dprintf(report_fd,
            "late-load: watchdog refused selinux enforce inode/filesystem\n");
    close(fd);
    return 0;
  }
  ssize_t got = read(fd, value, sizeof(value));
  int saved_errno = errno;
  close(fd);
  if (got < 0) {
    dprintf(report_fd, "late-load: watchdog selinux read failed: %s\n",
            strerror(saved_errno));
    return 0;
  }
  if ((got == 1 && value[0] == '1') ||
      (got == 2 && value[0] == '1' && value[1] == '\n')) {
    return 1;
  }
  if (!((got == 1 && value[0] == '0') ||
        (got == 2 && value[0] == '0' && value[1] == '\n'))) {
    dprintf(report_fd,
            "late-load: watchdog refused malformed selinux enforce state\n");
    return 0;
  }

  fd = open("/sys/fs/selinux/enforce",
            O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: watchdog cannot restore enforcing: %s\n",
            strerror(errno));
    return 0;
  }
  struct stat write_identity;
  if (!trusted_selinux_enforce_fd(fd, &write_identity) ||
      write_identity.st_dev != read_identity.st_dev ||
      write_identity.st_ino != read_identity.st_ino) {
    dprintf(report_fd,
            "late-load: watchdog selinux enforce identity changed\n");
    close(fd);
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(fd, "1", 1);
  } while (wrote < 0 && errno == EINTR);
  int write_errno = errno;
  errno = 0;
  int sync_result = wrote == 1 ? fsync(fd) : -1;
  int sync_errno = errno;
  int close_result = close(fd);
  /* Some Android selinuxfs implementations have no ->fsync operation, so the
   * syscall returns EINVAL even though sel_write_enforce completed
   * synchronously.  Still issue it, but accept that one explicit
   * "unsupported" result only when the exact enforcing=1 readback below also
   * succeeds.  Every other fsync failure remains a failed recovery. */
  int sync_ok = sync_result == 0 ||
                (sync_result < 0 && sync_errno == EINVAL);
  if (wrote != 1 || !sync_ok || close_result != 0 ||
      !enforcing_is_exactly_one(report_fd)) {
    saved_errno = wrote != 1 ? write_errno
                  : !sync_ok ? sync_errno
                             : errno;
    dprintf(report_fd,
            "late-load: watchdog enforcing=1 restore/readback failed: %s\n",
            strerror(saved_errno));
    return 0;
  }
  if (sync_result < 0) {
    dprintf(report_fd,
            "late-load: selinuxfs fsync unsupported (EINVAL); exact enforcing=1 readback verified\n");
  }
  dprintf(report_fd,
          "late-load: watchdog restored SELinux enforcing after worker failure\n");
  return 2;
}

/*
 * Put the kernel's cached policy capabilities back, immediately before ksud
 * turns enforcing back on.
 *
 * The exploit goes permissive with one 64-bit write over the head of
 * `selinux_state`, and the value it places has to be a real kernel pointer --
 * the primitive dereferences it -- so only the low byte, `enforcing`, can be
 * chosen. The other seven land on the fields behind it, `policycap[]` among
 * them, and switch on capabilities the policy does not have. The one that
 * matters is always_check_network: with it set the kernel starts checking
 * netif/node/peer on every packet, and this policy grants none of those,
 * because it never asked for the capability.
 *
 * While SELinux is permissive that is only noise in the log. It would stop
 * being noise at the moment enforcing comes back, which is something ksud does
 * a few seconds from here -- every socket in the system would be denied.
 *
 * This is a latent defect and nothing more: it is not what used to stop
 * applications launching after a run. That was the boot_id scratch, and it is
 * repaired in su_daemon.c.
 *
 * The payload repairs this once already, right after the write: a policy
 * reload runs security_load_policycaps(), which rewrites the whole array from
 * the policy. Measured on warhol, that reload is faithful and idempotent --
 * three round trips leave the policy byte-identical in size and every
 * capability unchanged -- but it happens while the exploit is still running,
 * and a run has been seen where the array was corrupt again by the time
 * anything looked. So it is done again here, where "again" costs a 1.6 MB
 * read and write and where nothing can land after it: this is the last root,
 * permissive moment before ksud.
 */
static int reload_selinux_policy(int report_fd) {
  if (!enforcing_is_exactly_zero(report_fd)) {
    return 0;
  }

  int policy_fd = open(SELINUX_POLICY_PATH, O_RDONLY | O_CLOEXEC);
  if (policy_fd < 0) {
    dprintf(report_fd, "late-load: selinux policy unreadable: %s\n",
            strerror(errno));
    return 0;
  }
  struct stat st;
  if (fstat(policy_fd, &st) != 0 || st.st_size <= 0 ||
      (size_t)st.st_size > SELINUX_POLICY_MAX) {
    close(policy_fd);
    dprintf(report_fd, "late-load: selinux policy size refused\n");
    return 0;
  }

  size_t len = (size_t)st.st_size;
  char *policy = malloc(len);
  if (!policy) {
    close(policy_fd);
    dprintf(report_fd, "late-load: selinux policy allocation failed\n");
    return 0;
  }
  size_t done = 0;
  while (done < len) {
    ssize_t got = read(policy_fd, policy + done, len - done);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      break;
    }
    done += (size_t)got;
  }
  close(policy_fd);
  if (done != len) {
    free(policy);
    dprintf(report_fd, "late-load: selinux policy short read %zu/%zu\n", done,
            len);
    return 0;
  }

  /* One write: the kernel takes the policy as a single image. */
  int load_fd = open(SELINUX_LOAD_PATH, O_WRONLY | O_CLOEXEC);
  if (load_fd < 0) {
    free(policy);
    dprintf(report_fd, "late-load: selinux load unwritable: %s\n",
            strerror(errno));
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(load_fd, policy, len);
  } while (wrote < 0 && errno == EINTR);
  int saved_errno = errno;
  close(load_fd);
  free(policy);

  if (wrote != (ssize_t)len) {
    dprintf(report_fd, "late-load: selinux policy reload failed: %s\n",
            strerror(saved_errno));
    return 0;
  }
  if (!enforcing_is_exactly_zero(report_fd)) {
    dprintf(report_fd,
            "late-load: selinux state changed during policy capability restore\n");
    return 0;
  }
  dprintf(report_fd, "late-load: policy capabilities restored (%zu bytes)\n",
          len);
  return 1;
}

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};

/* Optional compatibility pin.  Shared builds normally authenticate the
 * securely claimed inode at run time; a consuming build may additionally pin
 * a known daemon digest without making that definition mandatory. */
#ifndef RMD_EXPECTED_KSUD_SHA256
#define RMD_EXPECTED_KSUD_SHA256 ""
#endif

struct staged_ksud {
  char directory[PATH_MAX];
  char exec_path[PATH_MAX];
  char stage_path[PATH_MAX];
  unsigned char digest[32];
  char digest_hex[65];
  dev_t device;
  ino_t inode;
  off_t size;
  int ready;
};

static int decode_expected_ksud_digest(unsigned char digest[32]) {
  const char *text = RMD_EXPECTED_KSUD_SHA256;
  if (strlen(text) != 64) {
    return 0;
  }
  for (size_t i = 0; i < 32; i++) {
    int high = text[i * 2];
    int low = text[i * 2 + 1];
    high = high >= '0' && high <= '9' ? high - '0'
           : high >= 'a' && high <= 'f' ? high - 'a' + 10
           : high >= 'A' && high <= 'F' ? high - 'A' + 10
                                         : -1;
    low = low >= '0' && low <= '9' ? low - '0'
          : low >= 'a' && low <= 'f' ? low - 'a' + 10
          : low >= 'A' && low <= 'F' ? low - 'A' + 10
                                      : -1;
    if (high < 0 || low < 0) {
      return 0;
    }
    digest[i] = (unsigned char)((high << 4) | low);
  }
  return 1;
}

static int root_directory_ok(int fd, mode_t required_mode) {
  struct stat st;
  return fstat(fd, &st) == 0 && S_ISDIR(st.st_mode) && st.st_uid == 0 &&
         st.st_gid == 0 && (st.st_mode & 0777) == required_mode;
}

static int open_private_stage_root(int report_fd) {
  if (mkdir(ADB_DIR, 0700) != 0 && errno != EEXIST) {
    dprintf(report_fd, "late-load: mkdir %s: %s\n", ADB_DIR, strerror(errno));
    return -1;
  }
  int adb_fd = open(ADB_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (adb_fd < 0) {
    dprintf(report_fd, "late-load: secure open %s: %s\n", ADB_DIR,
            strerror(errno));
    return -1;
  }
  struct stat adb_stat;
  if (fstat(adb_fd, &adb_stat) != 0 || !S_ISDIR(adb_stat.st_mode) ||
      adb_stat.st_uid != 0 || adb_stat.st_gid != 0 ||
      (adb_stat.st_mode & 0022) != 0) {
    dprintf(report_fd, "late-load: %s is not a protected root directory\n",
            ADB_DIR);
    close(adb_fd);
    errno = EPERM;
    return -1;
  }

  const char *base_name = ".rmd-late-load";
  if (mkdirat(adb_fd, base_name, 0700) != 0 && errno != EEXIST) {
    dprintf(report_fd, "late-load: mkdir %s: %s\n", PRIVATE_STAGE_ROOT,
            strerror(errno));
    close(adb_fd);
    return -1;
  }
  int base_fd = openat(adb_fd, base_name,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  close(adb_fd);
  if (base_fd >= 0 && !root_directory_ok(base_fd, 0700) &&
      (fchown(base_fd, 0, 0) != 0 || fchmod(base_fd, 0700) != 0)) {
    int saved_errno = errno;
    close(base_fd);
    errno = saved_errno;
    base_fd = -1;
  }
  if (base_fd < 0 || !root_directory_ok(base_fd, 0700)) {
    dprintf(report_fd, "late-load: %s is not root:root mode 0700: %s\n",
            PRIVATE_STAGE_ROOT, strerror(errno));
    if (base_fd >= 0) {
      close(base_fd);
    }
    errno = EPERM;
    return -1;
  }
  return base_fd;
}

static int acquire_late_load_lock(int report_fd) {
  int base_fd = open_private_stage_root(report_fd);
  if (base_fd < 0) {
    return -1;
  }
  int lock_fd = openat(base_fd, PRIVATE_LOCK_NAME,
                       O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
  int saved_errno = errno;
  close(base_fd);
  if (lock_fd < 0) {
    errno = saved_errno;
    dprintf(report_fd, "late-load: open private operation lock: %s\n",
            strerror(errno));
    return -1;
  }

  struct stat st;
  if (fchown(lock_fd, 0, 0) != 0 || fchmod(lock_fd, 0600) != 0 ||
      fstat(lock_fd, &st) != 0) {
    saved_errno = errno;
    dprintf(report_fd, "late-load: private operation lock metadata refused\n");
    close(lock_fd);
    errno = saved_errno;
    return -1;
  }
  if (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
      st.st_nlink != 1 || (st.st_mode & 0777) != 0600) {
    saved_errno = EPERM;
    dprintf(report_fd, "late-load: private operation lock metadata refused\n");
    close(lock_fd);
    errno = saved_errno;
    return -1;
  }
  if (flock(lock_fd, LOCK_EX | LOCK_NB) != 0) {
    saved_errno = errno;
    if (saved_errno == EWOULDBLOCK || saved_errno == EAGAIN) {
      dprintf(report_fd, "late-load: another late-load operation is active\n");
    } else {
      dprintf(report_fd, "late-load: acquire private operation lock: %s\n",
              strerror(saved_errno));
    }
    close(lock_fd);
    errno = saved_errno;
    return -1;
  }
  return lock_fd;
}

static int remove_stale_run_directory(int base_fd, const char *run_name,
                                      int report_fd) {
  int run_fd = openat(base_fd, run_name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (run_fd < 0 || !root_directory_ok(run_fd, 0700)) {
    dprintf(report_fd,
            "late-load: stale private run directory is not trusted: %s\n",
            strerror(errno));
    if (run_fd >= 0) {
      close(run_fd);
    }
    return 0;
  }
  int ok = 1;
  if (unlinkat(run_fd, PRIVATE_STAGE_NAME, 0) != 0 && errno != ENOENT) {
    ok = 0;
  }
  if (unlinkat(run_fd, PRIVATE_EXEC_NAME, 0) != 0 && errno != ENOENT) {
    ok = 0;
  }
  close(run_fd);
  if (!ok || unlinkat(base_fd, run_name, AT_REMOVEDIR) != 0) {
    dprintf(report_fd, "late-load: stale private run cleanup failed: %s\n",
            strerror(errno));
    return 0;
  }
  return 1;
}

static int ensure_private_stage_directory(struct staged_ksud *staged,
                                          int report_fd, int *run_fd_out) {
  int base_fd = open_private_stage_root(report_fd);
  if (base_fd < 0) {
    return 0;
  }

  char run_name[64];
  int run_len = snprintf(run_name, sizeof(run_name), "%ld", (long)getpid());
  if (run_len <= 0 || (size_t)run_len >= sizeof(run_name)) {
    dprintf(report_fd, "late-load: invalid private run directory name\n");
    close(base_fd);
    return 0;
  }
  if (mkdirat(base_fd, run_name, 0700) != 0 &&
      !(errno == EEXIST &&
        remove_stale_run_directory(base_fd, run_name, report_fd) &&
        mkdirat(base_fd, run_name, 0700) == 0)) {
    dprintf(report_fd, "late-load: create private run directory: %s\n",
            strerror(errno));
    close(base_fd);
    return 0;
  }
  int run_fd = openat(base_fd, run_name,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (run_fd < 0 || fchown(run_fd, 0, 0) != 0 || fchmod(run_fd, 0700) != 0 ||
      !root_directory_ok(run_fd, 0700)) {
    dprintf(report_fd, "late-load: private run directory validation failed: %s\n",
            strerror(errno));
    if (run_fd >= 0) {
      close(run_fd);
    }
    unlinkat(base_fd, run_name, AT_REMOVEDIR);
    close(base_fd);
    return 0;
  }
  close(base_fd);

  if (snprintf(staged->directory, sizeof(staged->directory), "%s/%s",
               PRIVATE_STAGE_ROOT, run_name) >= (int)sizeof(staged->directory) ||
      snprintf(staged->exec_path, sizeof(staged->exec_path), "%s/%s",
               staged->directory, PRIVATE_EXEC_NAME) >=
          (int)sizeof(staged->exec_path) ||
      snprintf(staged->stage_path, sizeof(staged->stage_path), "%s/%s",
               staged->directory, PRIVATE_STAGE_NAME) >=
          (int)sizeof(staged->stage_path)) {
    dprintf(report_fd, "late-load: private staging path is too long\n");
    close(run_fd);
    rmdir(staged->directory);
    return 0;
  }
  *run_fd_out = run_fd;
  return 1;
}

static int copy_fd(int source, int destination) {
  if (lseek(source, 0, SEEK_SET) < 0) {
    return 0;
  }
  unsigned char buffer[65536];
  for (;;) {
    ssize_t got = read(source, buffer, sizeof(buffer));
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got < 0) {
      return 0;
    }
    if (got == 0) {
      return 1;
    }
    ssize_t done = 0;
    while (done < got) {
      ssize_t wrote = write(destination, buffer + done, (size_t)(got - done));
      if (wrote < 0 && errno == EINTR) {
        continue;
      }
      if (wrote <= 0) {
        return 0;
      }
      done += wrote;
    }
  }
}

static int unlink_public_source_if_same(int directory_fd,
                                        const struct stat *source_stat) {
  struct stat path_stat;
  if (fstatat(directory_fd, INSTALLED_KSUD_NAME, &path_stat,
              AT_SYMLINK_NOFOLLOW) != 0) {
    return errno == ENOENT;
  }
  if (path_stat.st_dev != source_stat->st_dev ||
      path_stat.st_ino != source_stat->st_ino) {
    return 1;
  }
  return unlinkat(directory_fd, INSTALLED_KSUD_NAME, 0) == 0;
}

static void cleanup_private_stage(struct staged_ksud *staged) {
  if (!staged->directory[0]) {
    return;
  }
  unlink(staged->stage_path);
  unlink(staged->exec_path);
  rmdir(staged->directory);
  staged->ready = 0;
}

static int clear_trusted_module_receipt(int report_fd) {
  int base_fd = open_private_stage_root(report_fd);
  if (base_fd < 0) {
    return 0;
  }
  if (unlinkat(base_fd, PRIVATE_MODULE_STATUS_NAME, 0) != 0 &&
      errno != ENOENT) {
    dprintf(report_fd, "late-load: invalidate trusted module receipt %s: %s\n",
            MODULE_STATUS_PATH, strerror(errno));
    close(base_fd);
    return 0;
  }
  /* Even an already-absent name needs a successful directory fsync.  A prior
   * attempt may have completed unlinkat() and then failed fsync(); treating
   * ENOENT as immediately durable would let that uncertainty escape the
   * fail-stop retry loop. */
  if (fsync(base_fd) != 0) {
    dprintf(report_fd, "late-load: sync trusted receipt invalidation: %s\n",
            strerror(errno));
    close(base_fd);
    return 0;
  }
  close(base_fd);
  return 1;
}

static int read_current_boot_id(char output[37], int report_fd) {
  char buffer[64];
  int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(report_fd, "late-load: read current boot_id: %s\n", strerror(errno));
    return 0;
  }
  ssize_t got = read(fd, buffer, sizeof(buffer));
  int saved_errno = errno;
  close(fd);
  if (!((got == 36) || (got == 37 && buffer[36] == '\n'))) {
    dprintf(report_fd, "late-load: invalid current boot_id read: %s\n",
            got < 0 ? strerror(saved_errno) : "unexpected length");
    return 0;
  }
  for (size_t i = 0; i < 36; i++) {
    int hyphen = i == 8 || i == 13 || i == 18 || i == 23;
    int hex = (buffer[i] >= '0' && buffer[i] <= '9') ||
              (buffer[i] >= 'a' && buffer[i] <= 'f') ||
              (buffer[i] >= 'A' && buffer[i] <= 'F');
    if ((hyphen && buffer[i] != '-') || (!hyphen && !hex)) {
      dprintf(report_fd, "late-load: malformed current boot_id\n");
      return 0;
    }
  }
  memcpy(output, buffer, 36);
  output[36] = '\0';
  return 1;
}

static int build_module_receipt(const struct staged_ksud *staged,
                                const char *run_id, char output[256],
                                int report_fd) {
  char boot_id[37];
  if (!read_current_boot_id(boot_id, report_fd)) {
    return -1;
  }
  int len = snprintf(
      output, 256,
      "version=1\nboot_id=%s\nrun_id=%s\nksud_sha256=%s\n", boot_id,
      run_id, staged->digest_hex);
  if (len <= 0 || len >= 256) {
    dprintf(report_fd, "late-load: module receipt expectation overflow\n");
    return -1;
  }
  return len;
}

static int read_exact_content(int fd, const char *expected, size_t expected_len) {
  char actual[256];
  if (expected_len > sizeof(actual)) {
    return 0;
  }
  size_t done = 0;
  while (done < expected_len) {
    ssize_t got = read(fd, actual + done, expected_len - done);
    if (got < 0 && errno == EINTR) {
      continue;
    }
    if (got <= 0) {
      return 0;
    }
    done += (size_t)got;
  }
  char extra;
  ssize_t got;
  do {
    got = read(fd, &extra, sizeof(extra));
  } while (got < 0 && errno == EINTR);
  return got == 0 && memcmp(actual, expected, expected_len) == 0;
}

static __attribute__((unused)) int verify_trusted_module_receipt(
    const struct staged_ksud *staged, const char *expected_run_id,
    int report_fd) {
  char expected[256];
  int expected_len =
      build_module_receipt(staged, expected_run_id, expected, report_fd);
  if (expected_len < 0) {
    return 0;
  }

  int base_fd = open_private_stage_root(report_fd);
  if (base_fd < 0) {
    return 0;
  }
  int fd = openat(base_fd, PRIVATE_MODULE_STATUS_NAME,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: trusted module receipt missing: %s\n",
            strerror(errno));
    close(base_fd);
    return 0;
  }

  struct stat st;
  struct stat after;
  struct stat path_st;
  int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
           st.st_gid == 0 && st.st_nlink == 1 &&
           (st.st_mode & 0777) == 0600 && st.st_size == expected_len;
  if (ok) {
    ok = read_exact_content(fd, expected, (size_t)expected_len);
  }
  if (ok) {
    ok = fstat(fd, &after) == 0 && after.st_dev == st.st_dev &&
         after.st_ino == st.st_ino && after.st_size == st.st_size &&
         after.st_uid == 0 && after.st_gid == 0 && after.st_nlink == 1 &&
         (after.st_mode & 0777) == 0600 &&
         fstatat(base_fd, PRIVATE_MODULE_STATUS_NAME, &path_st,
                 AT_SYMLINK_NOFOLLOW) == 0 &&
         S_ISREG(path_st.st_mode) && path_st.st_dev == st.st_dev &&
         path_st.st_ino == st.st_ino && path_st.st_size == st.st_size &&
         path_st.st_uid == 0 && path_st.st_gid == 0 && path_st.st_nlink == 1 &&
         (path_st.st_mode & 0777) == 0600;
  }
  close(fd);
  close(base_fd);
  if (!ok) {
    dprintf(report_fd,
            "late-load: trusted module receipt metadata/content mismatch\n");
    return 0;
  }
  dprintf(report_fd,
          "late-load: trusted current-boot module receipt verified run=%s\n",
          expected_run_id);
  return 1;
}

static int clear_public_module_receipt(int report_fd) {
  int dir_fd = open(PUBLIC_MODULE_STATUS_DIR,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) {
    dprintf(report_fd, "late-load: open public receipt directory: %s\n",
            strerror(errno));
    return 0;
  }
  if (unlinkat(dir_fd, PUBLIC_MODULE_STATUS_NAME, 0) != 0 && errno != ENOENT) {
    dprintf(report_fd, "late-load: invalidate public module receipt: %s\n",
            strerror(errno));
    close(dir_fd);
    return 0;
  }
  struct stat st;
  if (fstatat(dir_fd, PUBLIC_MODULE_STATUS_NAME, &st,
              AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT) {
    dprintf(report_fd, "late-load: public module receipt survived invalidation\n");
    close(dir_fd);
    return 0;
  }
  if (fsync(dir_fd) != 0) {
    dprintf(report_fd, "late-load: sync public receipt invalidation: %s\n",
            strerror(errno));
    close(dir_fd);
    return 0;
  }
  close(dir_fd);
  return 1;
}

static int trusted_module_receipt_absent_exact(int report_fd) {
  int base_fd = open_private_stage_root(report_fd);
  if (base_fd < 0) {
    return 0;
  }
  struct stat st;
  errno = 0;
  int absent = fstatat(base_fd, PRIVATE_MODULE_STATUS_NAME, &st,
                       AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
  if (!absent) {
    dprintf(report_fd,
            "late-load: trusted module receipt survived final invalidation\n");
  }
  close(base_fd);
  return absent;
}

static int public_module_receipt_absent_exact(int report_fd) {
  int dir_fd = open(PUBLIC_MODULE_STATUS_DIR,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) {
    dprintf(report_fd,
            "late-load: open public receipt directory for absence check: %s\n",
            strerror(errno));
    return 0;
  }
  struct stat st;
  errno = 0;
  int absent = fstatat(dir_fd, PUBLIC_MODULE_STATUS_NAME, &st,
                       AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
  if (!absent) {
    dprintf(report_fd,
            "late-load: public module receipt survived final invalidation\n");
  }
  close(dir_fd);
  return absent;
}

static int invalidate_module_receipts_exact(int report_fd) {
  /* Do not short-circuit: each authority and each post-unlink absence check is
   * independently required, even when an earlier cleanup already failed. */
  int trusted_cleared = clear_trusted_module_receipt(report_fd);
  int public_cleared = clear_public_module_receipt(report_fd);
  int trusted_absent = trusted_module_receipt_absent_exact(report_fd);
  int public_absent = public_module_receipt_absent_exact(report_fd);
  return trusted_cleared && public_cleared && trusted_absent && public_absent;
}

static int write_full_fd(int fd, const void *data, size_t len) {
  const unsigned char *at = data;
  while (len) {
    ssize_t wrote = write(fd, at, len);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      return 0;
    }
    at += wrote;
    len -= (size_t)wrote;
  }
  return 1;
}

static __attribute__((unused)) int publish_public_module_receipt(
    const struct staged_ksud *staged, const char *run_id, int report_fd) {
  char content[256];
  int content_len = build_module_receipt(staged, run_id, content, report_fd);
  if (content_len < 0) {
    return 0;
  }
  int dir_fd = open(PUBLIC_MODULE_STATUS_DIR,
                    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (dir_fd < 0) {
    dprintf(report_fd, "late-load: open public receipt directory: %s\n",
            strerror(errno));
    return 0;
  }
  char temp_name[96];
  int temp_len = snprintf(temp_name, sizeof(temp_name), "%s.tmp.%ld.%s",
                          PUBLIC_MODULE_STATUS_NAME, (long)getpid(), run_id);
  if (temp_len <= 0 || temp_len >= (int)sizeof(temp_name)) {
    close(dir_fd);
    return 0;
  }
  int fd = openat(dir_fd, temp_name,
                  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (fd < 0) {
    dprintf(report_fd, "late-load: create public receipt temp: %s\n",
            strerror(errno));
    close(dir_fd);
    return 0;
  }
  struct stat temp_st;
  memset(&temp_st, 0, sizeof(temp_st));
  int ok = fchown(fd, 0, 0) == 0 && fchmod(fd, 0644) == 0 &&
           write_full_fd(fd, content, (size_t)content_len) && fsync(fd) == 0 &&
           fstat(fd, &temp_st) == 0 && S_ISREG(temp_st.st_mode) &&
           temp_st.st_uid == 0 && temp_st.st_gid == 0 && temp_st.st_nlink == 1 &&
           (temp_st.st_mode & 0777) == 0644 && temp_st.st_size == content_len;
  if (ok) {
    ok = renameat(dir_fd, temp_name, dir_fd, PUBLIC_MODULE_STATUS_NAME) == 0 &&
         fsync(dir_fd) == 0;
  }
  close(fd);
  if (!ok) {
    struct stat current;
    if (fstatat(dir_fd, temp_name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        current.st_dev == temp_st.st_dev && current.st_ino == temp_st.st_ino) {
      (void)unlinkat(dir_fd, temp_name, 0);
    }
    dprintf(report_fd, "late-load: publish public module receipt failed: %s\n",
            strerror(errno));
    close(dir_fd);
    return 0;
  }

  int verify_fd = openat(dir_fd, PUBLIC_MODULE_STATUS_NAME,
                         O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  struct stat verify_st;
  struct stat path_st;
  ok = verify_fd >= 0 && fstat(verify_fd, &verify_st) == 0 &&
       S_ISREG(verify_st.st_mode) && verify_st.st_uid == 0 &&
       verify_st.st_gid == 0 && verify_st.st_nlink == 1 &&
       (verify_st.st_mode & 0777) == 0644 && verify_st.st_size == content_len &&
       verify_st.st_dev == temp_st.st_dev && verify_st.st_ino == temp_st.st_ino &&
       read_exact_content(verify_fd, content, (size_t)content_len) &&
       fstatat(dir_fd, PUBLIC_MODULE_STATUS_NAME, &path_st,
               AT_SYMLINK_NOFOLLOW) == 0 &&
       path_st.st_dev == verify_st.st_dev && path_st.st_ino == verify_st.st_ino &&
       S_ISREG(path_st.st_mode) && path_st.st_uid == 0 && path_st.st_gid == 0 &&
       path_st.st_nlink == 1 && (path_st.st_mode & 0777) == 0644 &&
       path_st.st_size == content_len;
  if (verify_fd >= 0) {
    close(verify_fd);
  }
  close(dir_fd);
  if (!ok) {
    dprintf(report_fd,
            "late-load: public module receipt post-publish verification failed\n");
    return 0;
  }
  dprintf(report_fd, "late-load: public nonce-bound module receipt published\n");
  return 1;
}

/* Claim the caller-owned inode, remove its public name, copy it into a
 * root-only directory, and hash every boundary.  A build may still provide a
 * compile-time digest pin, but the shared helper does not require one: the
 * securely claimed inode's digest becomes the run pin and is carried through
 * the ksud handoff.  That keeps this binary target-independent while retaining
 * the no-path-replacement/no-TOCTOU contract. */
static int stage_ksud(int report_fd, uid_t source_uid,
                      struct staged_ksud *staged) {
  memset(staged, 0, sizeof(*staged));
  unsigned char expected[32];
  int has_build_pin = decode_expected_ksud_digest(expected);

  int public_fd = open("/data/local/tmp",
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (public_fd < 0) {
    dprintf(report_fd, "late-load: secure open /data/local/tmp: %s\n",
            strerror(errno));
    return LATE_LOAD_STATUS_STAGE;
  }
  int source = openat(public_fd, INSTALLED_KSUD_NAME,
                      O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (source < 0) {
    dprintf(report_fd, "late-load: secure open %s: %s\n", KSUD_PATH,
            strerror(errno));
    close(public_fd);
    return LATE_LOAD_STATUS_STAGE;
  }

  struct stat source_stat;
  memset(&source_stat, 0, sizeof(source_stat));
  if (fstat(source, &source_stat) != 0 || !S_ISREG(source_stat.st_mode) ||
      source_stat.st_uid != source_uid || source_stat.st_nlink != 1 ||
      source_stat.st_size <= 0 || (uint64_t)source_stat.st_size > KSUD_MAX_SIZE ||
      (source_stat.st_mode & 0022) != 0 ||
      (source_stat.st_mode & S_IXUSR) == 0) {
    dprintf(report_fd,
            "late-load: refused untrusted ksud metadata uid=%u mode=%o "
            "links=%lu size=%lld\n",
            (unsigned)source_stat.st_uid, (unsigned)(source_stat.st_mode & 07777),
            (unsigned long)source_stat.st_nlink, (long long)source_stat.st_size);
    close(source);
    close(public_fd);
    return LATE_LOAD_STATUS_INTEGRITY;
  }

  /* Once opened and validated, take ownership of this inode. Other shell-uid
   * processes may replace the directory entry, but they can no longer change
   * the bytes read through this descriptor. */
  if (fchown(source, 0, 0) != 0 || fchmod(source, 0500) != 0 ||
      fstat(source, &source_stat) != 0 || source_stat.st_uid != 0 ||
      source_stat.st_gid != 0 || !S_ISREG(source_stat.st_mode) ||
      (source_stat.st_mode & 0777) != 0500) {
    dprintf(report_fd, "late-load: could not claim staged ksud inode: %s\n",
            strerror(errno));
    (void)unlink_public_source_if_same(public_fd, &source_stat);
    close(source);
    close(public_fd);
    return LATE_LOAD_STATUS_INTEGRITY;
  }
  /* Drop the public name immediately after claiming the inode. The open
   * descriptor remains the transport source; a crash can no longer strand a
   * root-owned 0500 file where the shell must stage the next attempt. */
  if (!unlink_public_source_if_same(public_fd, &source_stat)) {
    dprintf(report_fd, "late-load: could not remove claimed public ksud name: %s\n",
            strerror(errno));
    close(source);
    close(public_fd);
    return LATE_LOAD_STATUS_INTEGRITY;
  }

  int status = LATE_LOAD_STATUS_STAGE;
  int run_fd = -1;
  int private_exec = -1;
  unsigned char source_before[32];
  unsigned char source_after[32];
  unsigned char private_digest[32];
  if (!sha256_fd(source, source_before) ||
      (has_build_pin &&
       memcmp(source_before, expected, sizeof(expected)) != 0)) {
    dprintf(report_fd,
            "late-load: claimed ksud hash could not be established%s\n",
            has_build_pin ? " or did not match the optional build pin" : "");
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto out;
  }
  if (!ensure_private_stage_directory(staged, report_fd, &run_fd)) {
    goto out;
  }
  private_exec = openat(run_fd, PRIVATE_EXEC_NAME,
                        O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                        0500);
  if (private_exec < 0 || !copy_fd(source, private_exec) ||
      fsync(private_exec) != 0 || fchown(private_exec, 0, 0) != 0 ||
      fchmod(private_exec, 0500) != 0 ||
      !sha256_fd(private_exec, private_digest) ||
      !sha256_fd(source, source_after) ||
      memcmp(source_before, source_after, sizeof(source_before)) != 0 ||
      memcmp(source_before, private_digest, sizeof(source_before)) != 0 ||
      (has_build_pin &&
       memcmp(source_before, expected, sizeof(expected)) != 0)) {
    dprintf(report_fd, "late-load: root-private ksud copy/hash verification failed: %s\n",
            strerror(errno));
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto out;
  }

  struct stat private_stat;
  if (fstat(private_exec, &private_stat) != 0 ||
      !S_ISREG(private_stat.st_mode) || private_stat.st_uid != 0 ||
      private_stat.st_gid != 0 || (private_stat.st_mode & 0777) != 0500 ||
      private_stat.st_size != source_stat.st_size ||
      linkat(run_fd, PRIVATE_EXEC_NAME, run_fd, PRIVATE_STAGE_NAME, 0) != 0) {
    dprintf(report_fd, "late-load: private ksud metadata/handoff failed: %s\n",
            strerror(errno));
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto out;
  }

  memcpy(staged->digest, source_before, sizeof(staged->digest));
  sha256_hex(staged->digest, staged->digest_hex);
  staged->device = private_stat.st_dev;
  staged->inode = private_stat.st_ino;
  staged->size = private_stat.st_size;
  staged->ready = 1;
  dprintf(report_fd,
          "late-load: root-private ksud verified size=%lld sha256=%s\n",
          (long long)staged->size, staged->digest_hex);
  status = LATE_LOAD_STATUS_OK;

out:
  if (private_exec >= 0) {
    close(private_exec);
  }
  if (run_fd >= 0) {
    close(run_fd);
  }
  close(source);
  close(public_fd);
  if (status != LATE_LOAD_STATUS_OK) {
    cleanup_private_stage(staged);
  }
  return status;
}

static __attribute__((unused)) int verify_installed_ksud(
    const struct staged_ksud *staged, int report_fd) {
  int adb_fd = open(ADB_DIR, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (adb_fd < 0) {
    dprintf(report_fd, "late-load: verify installed ksud directory: %s\n",
            strerror(errno));
    return 0;
  }
  int fd = openat(adb_fd, INSTALLED_KSUD_NAME,
                  O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) {
    dprintf(report_fd, "late-load: installed ksud is missing: %s\n",
            strerror(errno));
    close(adb_fd);
    return 0;
  }
  struct stat st;
  struct stat after;
  struct stat path_st;
  unsigned char digest[32];
  unsigned char digest_after[32];
  memset(&st, 0, sizeof(st));
  memset(&after, 0, sizeof(after));
  memset(&path_st, 0, sizeof(path_st));
  int ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_uid == 0 &&
           st.st_gid == 0 && (st.st_mode & 0777) == 0755 &&
           st.st_size == staged->size && st.st_dev == staged->device &&
           st.st_ino == staged->inode && sha256_fd(fd, digest) &&
           memcmp(digest, staged->digest, sizeof(digest)) == 0 &&
           fstat(fd, &after) == 0 && after.st_dev == st.st_dev &&
           after.st_ino == st.st_ino && after.st_size == st.st_size &&
           after.st_uid == st.st_uid && after.st_gid == st.st_gid &&
           (after.st_mode & 0777) == 0755 && sha256_fd(fd, digest_after) &&
           memcmp(digest_after, staged->digest, sizeof(digest_after)) == 0 &&
           fstatat(adb_fd, INSTALLED_KSUD_NAME, &path_st,
                   AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(path_st.st_mode) && path_st.st_dev == st.st_dev &&
           path_st.st_ino == st.st_ino && path_st.st_size == st.st_size &&
           path_st.st_uid == 0 && path_st.st_gid == 0 &&
           (path_st.st_mode & 0777) == 0755;
  if (!ok) {
    dprintf(report_fd,
            "late-load: installed /data/adb/ksud failed metadata/hash identity\n");
    /* Never unlink a replacement that appeared after the verified open. */
    struct stat current;
    if (st.st_ino != 0 &&
        fstatat(adb_fd, INSTALLED_KSUD_NAME, &current,
                AT_SYMLINK_NOFOLLOW) == 0 &&
        current.st_dev == st.st_dev && current.st_ino == st.st_ino) {
      (void)unlinkat(adb_fd, INSTALLED_KSUD_NAME, 0);
    }
  }
  close(fd);
  close(adb_fd);
  return ok;
}

/*
 * Make /proc/kallsyms answer, and put it back afterwards.
 *
 * ksud's late-load resolves the module's undefined symbols from
 * /proc/kallsyms before init_module -- that is the whole reason the module is
 * built with an empty Module.symvers and a zero-length __versions section.
 * Under kernel.kptr_restrict = 2 every address in that file reads as
 * 0000000000000000 *for root as well*: the 2 setting hides pointers from
 * everyone, not just unprivileged readers. Measured on Quest 3, which ships
 * that setting -- `head -2 /proc/kallsyms` as uid 0 in u:r:kernel:s0 returns
 * zeros, and the same read with kptr_restrict set to 0 returns real addresses
 * for the symbols the module needs (avc_has_perm, __set_fixmap, change_pid).
 *
 * A resolver that reads zeros does not fail loudly; it relocates to zero. So
 * this is a precondition rather than a diagnostic, and it is restored once
 * the loader has exited, because leaving kernel pointers readable is not this
 * operation's to decide.
 */
#define KPTR_RESTRICT_PATH "/proc/sys/kernel/kptr_restrict"

static int read_kptr_restrict(void) {
  char value[16];
  int fd = open(KPTR_RESTRICT_PATH, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return -1;
  }
  ssize_t got = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (got <= 0) {
    return -1;
  }
  value[got] = '\0';
  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 10);
  while (end && (*end == '\n' || *end == '\r' || *end == ' ' || *end == '\t')) {
    end++;
  }
  if (errno || end == value || !end || *end != '\0' || parsed < 0 ||
      parsed > 2) {
    return -1;
  }
  return (int)parsed;
}

static int set_kptr_restrict_checked(int value, int report_fd) {
  char text[16];
  int len = snprintf(text, sizeof(text), "%d\n", value);
  int fd = open(KPTR_RESTRICT_PATH, O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(report_fd, "late-load: open kptr_restrict for %d: %s\n", value,
            strerror(errno));
    return 0;
  }
  ssize_t wrote;
  do {
    wrote = write(fd, text, (size_t)len);
  } while (wrote < 0 && errno == EINTR);
  int saved_errno = errno;
  close(fd);
  if (wrote != len) {
    dprintf(report_fd, "late-load: write kptr_restrict=%d failed: %s\n", value,
            strerror(saved_errno));
    return 0;
  }
  int after = read_kptr_restrict();
  if (after != value) {
    dprintf(report_fd,
            "late-load: kptr_restrict readback mismatch wrote=%d read=%d\n",
            value, after);
    return 0;
  }
  return 1;
}

static int verify_required_kallsyms_visible(int report_fd) {
  static const char *const required[] = {
      "__set_fixmap",
      "change_pid",
      "avc_has_perm",
  };
  int found[sizeof(required) / sizeof(required[0])];
  memset(found, 0, sizeof(found));

  int fd = open("/proc/kallsyms", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    dprintf(report_fd, "late-load: open /proc/kallsyms: %s\n",
            strerror(errno));
    return 0;
  }
  FILE *stream = fdopen(fd, "r");
  if (!stream) {
    dprintf(report_fd, "late-load: fdopen /proc/kallsyms: %s\n",
            strerror(errno));
    close(fd);
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), stream)) {
    unsigned long long address = 0;
    char type = 0;
    char name[256];
    if (sscanf(line, "%llx %c %255s", &address, &type, name) != 3) {
      continue;
    }
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
      if (!found[i] && strcmp(name, required[i]) == 0) {
        if (address == 0) {
          dprintf(report_fd,
                  "late-load: kallsyms address is still hidden for %s\n",
                  required[i]);
          fclose(stream);
          return 0;
        }
        found[i] = 1;
      }
    }
  }
  int read_error = ferror(stream);
  fclose(stream);
  if (read_error) {
    dprintf(report_fd, "late-load: /proc/kallsyms read failed\n");
    return 0;
  }
  for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
    if (!found[i]) {
      dprintf(report_fd, "late-load: required kallsyms symbol missing: %s\n",
              required[i]);
      return 0;
    }
  }
  dprintf(report_fd,
          "late-load: required kallsyms addresses verified nonzero\n");
  return 1;
}

static __attribute__((unused)) int verify_kernelsu_control(void) {
  int fd = -1;
  syscall(SYS_reboot, 0xDEADBEEF, 0xCAFEBABE, 0, &fd);
  if (fd < 0) {
    dprintf(STDERR_FILENO, "late-load: KernelSU driver fd unavailable\n");
    return LATE_LOAD_STATUS_NO_DRIVER;
  }

  struct ksu_get_info_cmd info;
  memset(&info, 0, sizeof(info));
  int ret = ioctl(fd, _IOR('K', 2, struct ksu_get_info_cmd), &info);
  int saved_errno = errno;
  close(fd);
  if (ret != 0 || info.version == 0 || (info.flags & 1U) == 0 ||
      (info.flags & 4U) == 0) {
    dprintf(STDERR_FILENO,
            "late-load: KernelSU control check failed ret=%d errno=%d "
            "version=%u flags=0x%x\n",
            ret, saved_errno, info.version, info.flags);
    return LATE_LOAD_STATUS_CONTROL;
  }

  dprintf(STDOUT_FILENO,
          "KernelSU control verified version=%u flags=0x%x "
          "uapi=%u features=0x%x\n",
          info.version, info.flags, info.uapi_version, info.features);
  return LATE_LOAD_STATUS_OK;
}

static int late_load_open_trusted_pidfd(pid_t pid) {
#ifdef SYS_pidfd_open
  int fd = (int)syscall(SYS_pidfd_open, pid, 0);
#else
  int fd = -1;
  errno = ENOSYS;
#endif
  if (fd < 0) {
    return -1;
  }
  int flags = fcntl(fd, F_GETFD);
  char path[64];
  char target[32] = {0};
  int path_len = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
  ssize_t target_len =
      path_len > 0 && path_len < (int)sizeof(path)
          ? readlink(path, target, sizeof(target))
          : -1;
  static const char expected[] = "anon_inode:[pidfd]";
  struct pollfd probe = {.fd = fd, .events = POLLIN};
  if (flags < 0 || (flags & FD_CLOEXEC) == 0 ||
      target_len != (ssize_t)(sizeof(expected) - 1) ||
      memcmp(target, expected, sizeof(expected) - 1) != 0 ||
      poll(&probe, 1, 0) != 0) {
    int saved_errno = errno ? errno : EPROTO;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

static int late_load_pidfd_is_dead(int pidfd) {
  struct pollfd probe = {.fd = pidfd, .events = POLLIN};
  int polled;
  do {
    polled = poll(&probe, 1, 0);
  } while (polled < 0 && errno == EINTR);
  return polled > 0;
}

static int late_load_wait_atomic(struct late_load_watch_mailbox *mailbox,
                                 atomic_int *field, int expected,
                                 int timeout_ms) {
  if (!mailbox || !field || timeout_ms <= 0) {
    return 0;
  }
  for (int i = 0; i < timeout_ms; i++) {
    if (atomic_load_explicit(field, memory_order_acquire) == expected) {
      return 1;
    }
    if (atomic_load_explicit(&mailbox->watcher_state,
                             memory_order_acquire) ==
            LATE_LOAD_WATCH_FAILED ||
        atomic_load_explicit(&mailbox->ack, memory_order_acquire) ==
            LATE_LOAD_WATCH_ACK_FAILED) {
      return 0;
    }
    usleep(1000);
  }
  return 0;
}

static int late_load_watch_pin_worker(
    struct late_load_watch_mailbox *mailbox, int *worker_pidfd) {
  if (*worker_pidfd >= 0) {
    return 1;
  }
  int state = atomic_load_explicit(&mailbox->worker_state,
                                   memory_order_acquire);
  pid_t worker = (pid_t)atomic_load_explicit(&mailbox->worker_pid,
                                             memory_order_acquire);
  if (state < LATE_LOAD_WORKER_READY || worker <= 1) {
    return 0;
  }
  int pidfd = late_load_open_trusted_pidfd(worker);
  if (pidfd < 0 || getpgid(worker) != worker ||
      atomic_load_explicit(&mailbox->worker_pid, memory_order_acquire) !=
          worker) {
    if (pidfd >= 0) {
      close(pidfd);
    }
    return 0;
  }
  *worker_pidfd = pidfd;
  atomic_store_explicit(&mailbox->worker_state, LATE_LOAD_WORKER_PINNED,
                        memory_order_release);
  return 1;
}

static int late_load_watch_kill_worker(
    struct late_load_watch_mailbox *mailbox, int worker_pidfd) {
  if (worker_pidfd < 0) {
    int state = atomic_load_explicit(&mailbox->worker_state,
                                     memory_order_acquire);
    return state == LATE_LOAD_WORKER_NONE || state == LATE_LOAD_WORKER_DONE;
  }
  pid_t worker = (pid_t)atomic_load_explicit(&mailbox->worker_pid,
                                             memory_order_acquire);
  if (!late_load_pidfd_is_dead(worker_pidfd) && worker > 1 &&
      getpgid(worker) == worker) {
    /* The loader inherits this private process group.  Signal the group while
     * its leader is still pinned and alive, then signal the pinned leader as a
     * second exact path. */
    (void)kill(-worker, SIGKILL);
#ifdef SYS_pidfd_send_signal
    (void)syscall(SYS_pidfd_send_signal, worker_pidfd, SIGKILL, NULL, 0);
#endif
  }
  for (int i = 0; i < LATE_LOAD_WATCHER_REAP_MS; i++) {
    if (late_load_pidfd_is_dead(worker_pidfd)) {
      atomic_store_explicit(&mailbox->worker_state, LATE_LOAD_WORKER_DONE,
                            memory_order_release);
      return 1;
    }
    usleep(1000);
  }
  return late_load_pidfd_is_dead(worker_pidfd);
}

static void late_load_watch_abort_cleanup(
    struct late_load_watch_mailbox *mailbox, int worker_pidfd,
    int report_fd) {
  atomic_store_explicit(&mailbox->watcher_state, LATE_LOAD_WATCH_CLEANING,
                        memory_order_release);
  for (;;) {
    if (worker_pidfd < 0) {
      (void)late_load_watch_pin_worker(mailbox, &worker_pidfd);
    }
    int worker_dead = late_load_watch_kill_worker(mailbox, worker_pidfd);
    if (!worker_dead && worker_pidfd < 0 &&
        atomic_load_explicit(&mailbox->worker_state,
                             memory_order_acquire) ==
            LATE_LOAD_WORKER_READY &&
        atomic_load_explicit(&mailbox->worker_release,
                             memory_order_acquire) == 0) {
      /* A bootstrap child cannot have touched global state before release. If
       * parent death killed it before the watcher could acquire its pidfd, no
       * loader or process group was ever created. */
      worker_dead = 1;
      atomic_store_explicit(&mailbox->worker_state, LATE_LOAD_WORKER_DONE,
                            memory_order_release);
    }

    /* The direct hash-pinned ksud child is the only process that can finish
     * after KernelSU restores enforcing.  Its two reserved exits attest either
     * a complete success finalization or a complete abort rollback.  Check
     * those mutually-exclusive proofs before any u:r:kernel:s0 pathname
     * reopen: after enforcing, the watcher has no authority for those opens. */
    int ksu_success_proven =
        atomic_load_explicit(&mailbox->ksu_success_proven,
                             memory_order_acquire) == 1;
    int ksu_cleanup_proven =
        atomic_load_explicit(&mailbox->ksu_cleanup_proven,
                             memory_order_acquire) == 1;
    if (worker_dead && ksu_success_proven != ksu_cleanup_proven) {
      atomic_store_explicit(
          &mailbox->ack,
          ksu_success_proven ? LATE_LOAD_WATCH_ACK_FINAL
                             : LATE_LOAD_WATCH_ACK_ABORT_CLEAN,
          memory_order_release);
      _exit(0);
    }

    /* Every rollback is attempted even when an earlier one failed.  The
     * watcher keeps the inherited flock for as long as any exact readback is
     * missing, so another late-load can never overlap an uncertain cleanup. */
    int kptr_ok = set_kptr_restrict_checked(mailbox->original_kptr, report_fd);
    int receipts_cleared =
        !mailbox->enable_modules || invalidate_module_receipts_exact(report_fd);
    int enforcing_ok = ensure_enforcing_one_after_worker(report_fd) != 0;
    /* Once KernelSU has returned SELinux to enforcing, u:r:kernel:s0 can no
     * longer reopen the three cleanup authorities above.  The only alternate
     * proof is the reserved exit from the exact authenticated ksud child: the
     * worker records it only after waitpid() reaps that direct child without
     * an exec-error record.  Do not turn a merely claimed mailbox bit into an
     * acknowledgement; a dead worker and the unique authenticated setter are
     * both part of the handoff. */
    if (worker_dead &&
        (ksu_cleanup_proven || (kptr_ok && receipts_cleared && enforcing_ok))) {
      atomic_store_explicit(&mailbox->ack,
                            LATE_LOAD_WATCH_ACK_ABORT_CLEAN,
                            memory_order_release);
      _exit(0);
    }
    atomic_store_explicit(&mailbox->watcher_state, LATE_LOAD_WATCH_FAILED,
                          memory_order_release);
    atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_FAILED,
                          memory_order_release);
    sleep(1);
    atomic_store_explicit(&mailbox->watcher_state,
                          LATE_LOAD_WATCH_CLEANING,
                          memory_order_release);
  }
}

static void late_load_watch_main(struct late_load_watch_mailbox *mailbox,
                                 int parent_pidfd, int lock_fd,
                                 int report_fd) {
  struct stat lock_st;
  struct timespec started;
  if (!mailbox || parent_pidfd < 0 || lock_fd < 0 ||
      prctl(PR_SET_PDEATHSIG, 0) != 0 ||
      prctl(PR_SET_NAME, "rmd-late-watch") != 0 ||
      fstat(lock_fd, &lock_st) != 0 || !S_ISREG(lock_st.st_mode) ||
      lock_st.st_uid != 0 || lock_st.st_gid != 0 || lock_st.st_nlink != 1 ||
      (lock_st.st_mode & 0777) != 0600 ||
      flock(lock_fd, LOCK_EX | LOCK_NB) != 0 ||
      clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    if (mailbox) {
      atomic_store_explicit(&mailbox->watcher_state,
                            LATE_LOAD_WATCH_FAILED,
                            memory_order_release);
      atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_FAILED,
                            memory_order_release);
    }
    _exit(140);
  }

  atomic_store_explicit(&mailbox->watcher_pid, (int)getpid(),
                        memory_order_release);
  atomic_store_explicit(&mailbox->watcher_state, LATE_LOAD_WATCH_ARMED,
                        memory_order_release);
  int worker_pidfd = -1;
  int prepared = 0;

  for (;;) {
    if (worker_pidfd < 0) {
      (void)late_load_watch_pin_worker(mailbox, &worker_pidfd);
    }
    int decision = atomic_load_explicit(&mailbox->decision,
                                        memory_order_acquire);
    struct pollfd parent = {.fd = parent_pidfd, .events = POLLIN};
    int parent_poll;
    do {
      parent_poll = poll(&parent, 1, 0);
    } while (parent_poll < 0 && errno == EINTR);
    struct timespec now;
    int clock_ok = clock_gettime(CLOCK_MONOTONIC, &now) == 0;
    int timed_out = !clock_ok || now.tv_sec < started.tv_sec ||
                    now.tv_sec - started.tv_sec >=
                        LATE_LOAD_WATCHER_TIMEOUT_SECONDS;
    if (decision == LATE_LOAD_WATCH_ABORT || parent_poll != 0 || timed_out) {
      int pending = decision;
      if (pending == LATE_LOAD_WATCH_PENDING ||
          pending == LATE_LOAD_WATCH_PREPARE) {
        (void)atomic_compare_exchange_strong_explicit(
            &mailbox->decision, &pending, LATE_LOAD_WATCH_ABORT,
            memory_order_acq_rel, memory_order_acquire);
      }
      late_load_watch_abort_cleanup(mailbox, worker_pidfd, report_fd);
    }
    if (decision == LATE_LOAD_WATCH_PREPARE) {
      int worker_state = atomic_load_explicit(&mailbox->worker_state,
                                              memory_order_acquire);
      int worker_quiescent =
          worker_state == LATE_LOAD_WORKER_NONE ||
          (worker_pidfd >= 0 && late_load_pidfd_is_dead(worker_pidfd));
      int success_proven =
          atomic_load_explicit(&mailbox->ksu_success_proven,
                               memory_order_acquire) == 1 &&
          atomic_load_explicit(&mailbox->ksu_cleanup_proven,
                               memory_order_acquire) == 0;
      int exact =
          atomic_load_explicit(&mailbox->parent_cleanup_ready,
                               memory_order_acquire) == 1 &&
          worker_quiescent &&
          (success_proven ||
           (read_kptr_restrict() == mailbox->original_kptr &&
            enforcing_is_exactly_one(report_fd)));
      if (!exact) {
        atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_FAILED,
                              memory_order_release);
        atomic_store_explicit(&mailbox->watcher_state,
                              LATE_LOAD_WATCH_FAILED,
                              memory_order_release);
        int preparing = LATE_LOAD_WATCH_PREPARE;
        (void)atomic_compare_exchange_strong_explicit(
            &mailbox->decision, &preparing, LATE_LOAD_WATCH_ABORT,
            memory_order_acq_rel, memory_order_acquire);
        late_load_watch_abort_cleanup(mailbox, worker_pidfd, report_fd);
      }
      prepared = 1;
      atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_PREPARE,
                            memory_order_release);
    } else if (decision == LATE_LOAD_WATCH_FINAL) {
      if (!prepared ||
          atomic_load_explicit(&mailbox->ack, memory_order_acquire) !=
              LATE_LOAD_WATCH_ACK_PREPARE) {
        atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_FAILED,
                              memory_order_release);
        atomic_store_explicit(&mailbox->watcher_state,
                              LATE_LOAD_WATCH_FAILED,
                              memory_order_release);
        late_load_watch_abort_cleanup(mailbox, worker_pidfd, report_fd);
      }
      atomic_store_explicit(&mailbox->ack, LATE_LOAD_WATCH_ACK_FINAL,
                            memory_order_release);
      _exit(0);
    }
    usleep(1000);
  }
}

static int late_load_reap_watcher(pid_t watcher, int *status_out) {
  if (watcher <= 0) {
    return 1;
  }
  for (int i = 0; i < LATE_LOAD_WATCHER_REAP_MS; i++) {
    int status = 0;
    pid_t waited = waitpid(watcher, &status, WNOHANG);
    if (waited == watcher) {
      if (status_out) {
        *status_out = status;
      }
      return WIFEXITED(status) && WEXITSTATUS(status) == 0;
    }
    if (waited < 0 && errno == ECHILD) {
      return 1;
    }
    if (waited < 0 && errno != EINTR) {
      return 0;
    }
    usleep(1000);
  }
  return 0;
}

static int late_load_start_watcher(
    int lock_fd, int report_fd, int original_kptr, int enable_modules,
    struct late_load_watch_mailbox **mailbox_out, pid_t *watcher_out) {
  *mailbox_out = NULL;
  *watcher_out = -1;
  struct late_load_watch_mailbox *mailbox =
      mmap(NULL, sizeof(*mailbox), PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (mailbox == MAP_FAILED) {
    dprintf(report_fd, "late-load: watcher mailbox allocation failed: %s\n",
            strerror(errno));
    return 0;
  }
  memset(mailbox, 0, sizeof(*mailbox));
  atomic_init(&mailbox->watcher_state, LATE_LOAD_WATCH_INIT);
  atomic_init(&mailbox->watcher_pid, -1);
  atomic_init(&mailbox->decision, LATE_LOAD_WATCH_PENDING);
  atomic_init(&mailbox->ack, LATE_LOAD_WATCH_ACK_NONE);
  atomic_init(&mailbox->parent_cleanup_ready, 0);
  atomic_init(&mailbox->parent_status, LATE_LOAD_STATUS_EXEC);
  atomic_init(&mailbox->worker_state, LATE_LOAD_WORKER_NONE);
  atomic_init(&mailbox->worker_pid, -1);
  atomic_init(&mailbox->worker_release, 0);
  atomic_init(&mailbox->ksu_cleanup_proven, 0);
  atomic_init(&mailbox->ksu_success_proven, 0);
  mailbox->original_kptr = original_kptr;
  mailbox->enable_modules = enable_modules;
  mailbox->parent_pid = getpid();

  int parent_pidfd = late_load_open_trusted_pidfd(mailbox->parent_pid);
  if (parent_pidfd < 0) {
    dprintf(report_fd, "late-load: parent pidfd unavailable: %s\n",
            strerror(errno));
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }
  pid_t watcher = fork();
  if (watcher == 0) {
    late_load_watch_main(mailbox, parent_pidfd, lock_fd, report_fd);
  }
  close(parent_pidfd);
  if (watcher < 0) {
    dprintf(report_fd, "late-load: fork cleanup watcher: %s\n",
            strerror(errno));
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }
  if (!late_load_wait_atomic(mailbox, &mailbox->watcher_state,
                             LATE_LOAD_WATCH_ARMED,
                             LATE_LOAD_WATCHER_HANDSHAKE_MS) ||
      (pid_t)atomic_load_explicit(&mailbox->watcher_pid,
                                  memory_order_acquire) != watcher) {
    dprintf(report_fd, "late-load: cleanup watcher did not arm exactly\n");
    int pending = LATE_LOAD_WATCH_PENDING;
    (void)atomic_compare_exchange_strong_explicit(
        &mailbox->decision, &pending, LATE_LOAD_WATCH_ABORT,
        memory_order_acq_rel, memory_order_acquire);
    (void)late_load_reap_watcher(watcher, NULL);
    munmap(mailbox, sizeof(*mailbox));
    return 0;
  }
  *mailbox_out = mailbox;
  *watcher_out = watcher;
  return 1;
}

static int late_load_request_watcher_proof(
    struct late_load_watch_mailbox *mailbox, pid_t watcher,
    int expected_ack);

static int late_load_request_watcher_abort(
    struct late_load_watch_mailbox *mailbox, pid_t watcher) {
  return late_load_request_watcher_proof(
      mailbox, watcher, LATE_LOAD_WATCH_ACK_ABORT_CLEAN);
}

static int late_load_request_watcher_proof(
    struct late_load_watch_mailbox *mailbox, pid_t watcher,
    int expected_ack) {
  if (expected_ack != LATE_LOAD_WATCH_ACK_ABORT_CLEAN &&
      expected_ack != LATE_LOAD_WATCH_ACK_FINAL) {
    return 0;
  }
  int decision = atomic_load_explicit(&mailbox->decision,
                                      memory_order_acquire);
  while (decision == LATE_LOAD_WATCH_PENDING ||
         decision == LATE_LOAD_WATCH_PREPARE) {
    if (atomic_compare_exchange_weak_explicit(
            &mailbox->decision, &decision, LATE_LOAD_WATCH_ABORT,
            memory_order_acq_rel, memory_order_acquire)) {
      decision = LATE_LOAD_WATCH_ABORT;
      break;
    }
  }
  if (decision != LATE_LOAD_WATCH_ABORT &&
      !(expected_ack == LATE_LOAD_WATCH_ACK_FINAL &&
        decision == LATE_LOAD_WATCH_FINAL)) {
    return 0;
  }
  /* A proof handoff is fail-stop rather than a bounded RPC. The watcher first
   * reaps the exact worker, then publishes the proof-specific acknowledgement
   * while still retaining its inherited operation lock. */
  for (;;) {
    int ack = atomic_load_explicit(&mailbox->ack, memory_order_acquire);
    int status = 0;
    pid_t waited = waitpid(watcher, &status, WNOHANG);
    if (waited == watcher) {
      ack = atomic_load_explicit(&mailbox->ack, memory_order_acquire);
      return WIFEXITED(status) && WEXITSTATUS(status) == 0 &&
             ack == expected_ack;
    }
    if (waited < 0 && errno == ECHILD) {
      return ack == expected_ack;
    }
    if (waited < 0 && errno != EINTR) {
      return 0;
    }
    if (ack == expected_ack) {
      do {
        waited = waitpid(watcher, &status, 0);
      } while (waited < 0 && errno == EINTR);
      if (waited < 0 && errno == ECHILD) {
        return 1;
      }
      return waited == watcher && WIFEXITED(status) &&
             WEXITSTATUS(status) == 0;
    }
    usleep(1000);
  }
}

static int late_load_wait_final_watcher(
    struct late_load_watch_mailbox *mailbox, pid_t watcher) {
  /* FINAL follows an acknowledged PREPARE and is the last normal transition.
   * Do not turn a merely slow watcher into a failure after a bounded timeout:
   * that would require invalidating success receipts after the watcher had
   * already been allowed to exit.  Retain the operation lock until an exact
   * FINAL acknowledgement and clean reap, or until an abnormal watcher exit
   * transfers rollback ownership back to the parent. */
  for (;;) {
    int ack = atomic_load_explicit(&mailbox->ack, memory_order_acquire);
    int child_status = 0;
    pid_t waited = waitpid(watcher, &child_status, WNOHANG);
    if (waited == watcher) {
      ack = atomic_load_explicit(&mailbox->ack, memory_order_acquire);
      return WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0 &&
             ack == LATE_LOAD_WATCH_ACK_FINAL;
    }
    if (waited < 0 && errno == ECHILD) {
      return ack == LATE_LOAD_WATCH_ACK_FINAL;
    }
    if (waited < 0 && errno != EINTR) {
      return 0;
    }
    if (ack == LATE_LOAD_WATCH_ACK_FINAL) {
      do {
        waited = waitpid(watcher, &child_status, 0);
      } while (waited < 0 && errno == EINTR);
      if (waited < 0 && errno == ECHILD) {
        return 1;
      }
      return waited == watcher && WIFEXITED(child_status) &&
             WEXITSTATUS(child_status) == 0;
    }
    usleep(1000);
  }
}

static int late_load_finish_watcher(
    struct late_load_watch_mailbox *mailbox, pid_t watcher, int status,
    int cleanup_ready) {
  atomic_store_explicit(&mailbox->parent_status, status,
                        memory_order_release);
  atomic_store_explicit(&mailbox->parent_cleanup_ready,
                        cleanup_ready ? 1 : 0, memory_order_release);
  if (status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS && cleanup_ready) {
    return late_load_request_watcher_proof(
               mailbox, watcher, LATE_LOAD_WATCH_ACK_FINAL)
               ? 1
               : -1;
  }
  if (status == LATE_LOAD_STATUS_KSU_CLEAN_ABORT && cleanup_ready) {
    return late_load_request_watcher_proof(
               mailbox, watcher, LATE_LOAD_WATCH_ACK_ABORT_CLEAN)
               ? 0
               : -1;
  }
  if (status != LATE_LOAD_STATUS_OK || !cleanup_ready) {
    return late_load_request_watcher_abort(mailbox, watcher) ? 0 : -1;
  }
  int pending = LATE_LOAD_WATCH_PENDING;
  if (!atomic_compare_exchange_strong_explicit(
          &mailbox->decision, &pending, LATE_LOAD_WATCH_PREPARE,
          memory_order_acq_rel, memory_order_acquire) ||
      !late_load_wait_atomic(mailbox, &mailbox->ack,
                             LATE_LOAD_WATCH_ACK_PREPARE,
                             LATE_LOAD_WATCHER_HANDSHAKE_MS)) {
    return late_load_request_watcher_abort(mailbox, watcher) ? 0 : -1;
  }
  int prepared = LATE_LOAD_WATCH_PREPARE;
  if (!atomic_compare_exchange_strong_explicit(
          &mailbox->decision, &prepared, LATE_LOAD_WATCH_FINAL,
          memory_order_acq_rel, memory_order_acquire)) {
    return -1;
  }
  return late_load_wait_final_watcher(mailbox, watcher) ? 1 : -1;
}

static void late_load_parent_fail_stop_cleanup(int original_kptr,
                                               int enable_modules,
                                               int report_fd) {
  /* This is the last owner after an abnormal watcher exit as well as an exact
   * post-watcher confirmation.  Keep the private flock held and never return a
   * failure response while either receipt can still authorize stale success,
   * or while either global rollback lacks an exact readback. */
  for (;;) {
    int kptr_ok = original_kptr < 0 ||
                  set_kptr_restrict_checked(original_kptr, report_fd);
    int receipts_ok = !enable_modules ||
                      invalidate_module_receipts_exact(report_fd);
    int enforcing_ok = ensure_enforcing_one_after_worker(report_fd) != 0;
    if (kptr_ok && receipts_ok && enforcing_ok) {
      return;
    }
    dprintf(report_fd,
            "late-load: fail-stop cleanup incomplete; retaining lock and retrying\n");
    sleep(1);
  }
}

static void late_load_proven_success_fail_stop(void) {
  /* Reserved exit 201 proves that success receipts and every global state are
   * exact. If the process-level watcher acknowledgement itself becomes
   * impossible, returning nonzero would contradict those valid receipts while
   * deleting them from u:r:kernel:s0 is impossible. Retain the flock until a
   * reboot instead of publishing either a false failure or an early success. */
  for (;;) {
    sleep(1);
  }
}

static int late_load_worker_bootstrap(
    struct late_load_watch_mailbox *mailbox, pid_t expected_parent) {
  pid_t self = getpid();
  if (!mailbox || self <= 1 || self != (pid_t)syscall(SYS_gettid) ||
      setpgid(0, 0) != 0 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
      getppid() != expected_parent) {
    return 0;
  }
  int empty = -1;
  if (!atomic_compare_exchange_strong_explicit(
          &mailbox->worker_pid, &empty, (int)self,
          memory_order_acq_rel, memory_order_acquire)) {
    return 0;
  }
  atomic_store_explicit(&mailbox->worker_state, LATE_LOAD_WORKER_READY,
                        memory_order_release);
  for (int i = 0; i < LATE_LOAD_WATCHER_HANDSHAKE_MS; i++) {
    if (atomic_load_explicit(&mailbox->decision, memory_order_acquire) ==
        LATE_LOAD_WATCH_ABORT) {
      return 0;
    }
    if (atomic_load_explicit(&mailbox->worker_release,
                             memory_order_acquire) == 1 &&
        atomic_load_explicit(&mailbox->worker_state,
                             memory_order_acquire) ==
            LATE_LOAD_WORKER_PINNED) {
      atomic_store_explicit(&mailbox->worker_state,
                            LATE_LOAD_WORKER_RUNNING,
                            memory_order_release);
      return 1;
    }
    usleep(1000);
  }
  atomic_store_explicit(&mailbox->worker_state, LATE_LOAD_WORKER_FAILED,
                        memory_order_release);
  return 0;
}

struct loader_exec_error {
  int error_number;
};

static void publish_loader_exec_error(int fd, int error_number) {
  struct loader_exec_error error = {
      .error_number = error_number ? error_number : EIO,
  };
  const unsigned char *at = (const unsigned char *)&error;
  size_t remaining = sizeof(error);
  while (remaining) {
    ssize_t wrote = write(fd, at, remaining);
    if (wrote < 0 && errno == EINTR) {
      continue;
    }
    if (wrote <= 0) {
      return;
    }
    at += wrote;
    remaining -= (size_t)wrote;
  }
}

static int wait_loader_status(pid_t loader, int error_fd, int report_fd,
                              int cleanup_handoff_expected) {
  int raw_status = 0;
  pid_t waited;
  do {
    waited = waitpid(loader, &raw_status, 0);
  } while (waited < 0 && errno == EINTR);

  struct loader_exec_error setup_error;
  ssize_t got;
  do {
    got = read(error_fd, &setup_error, sizeof(setup_error));
  } while (got < 0 && errno == EINTR);
  close(error_fd);
  if (got != 0) {
    int error_number = got == (ssize_t)sizeof(setup_error)
                           ? setup_error.error_number
                           : EIO;
    dprintf(report_fd, "late-load: loader setup/exec failed: %s\n",
            strerror(error_number));
    return LATE_LOAD_STATUS_EXEC;
  }
  if (waited != loader) {
    dprintf(report_fd, "late-load: wait for ksud failed: %s\n", strerror(errno));
    return LATE_LOAD_STATUS_EXEC;
  }
  if (WIFSIGNALED(raw_status)) {
    int signal_number = WTERMSIG(raw_status);
    if (signal_number >= LATE_LOAD_STATUS_KSUD_SIGNAL_SPAN) {
      signal_number = LATE_LOAD_STATUS_KSUD_SIGNAL_SPAN - 1;
    }
    dprintf(report_fd, "late-load: ksud terminated by signal %d\n",
            WTERMSIG(raw_status));
    return LATE_LOAD_STATUS_KSUD_SIGNAL + signal_number;
  }
  if (!WIFEXITED(raw_status)) {
    dprintf(report_fd, "late-load: ksud ended without an exit status\n");
    return LATE_LOAD_STATUS_EXEC;
  }
  int exit_status = WEXITSTATUS(raw_status);
  if (exit_status == KSU_LATE_LOAD_CLEAN_SUCCESS_EXIT) {
    /* Success is not a generic process exit. The exact staged ksud must attest
     * that every post-enforce postcondition was finalized in u:r:ksu:s0. The
     * empty exec-error pipe and waitpid() of this direct child bind the proof
     * to the inode/hash-pinned executable. */
    if (cleanup_handoff_expected) {
      return LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS;
    }
    dprintf(report_fd,
            "late-load: refused unexpected ksud success-proof exit\n");
    return LATE_LOAD_STATUS_INTEGRITY;
  }
  if (exit_status == 0) {
    dprintf(report_fd,
            "late-load: refused generic ksud success without retained-fd finalization proof\n");
    return LATE_LOAD_STATUS_INTEGRITY;
  }
  if (exit_status == KSU_LATE_LOAD_CLEAN_ABORT_EXIT) {
    /* This status is reserved by a sealed-protocol ksud for one outcome only:
     * post-load failure after exact kptr/receipt/enforcing
     * rollback.  The exec-error pipe is already proven empty and waitpid()
     * reaped the direct loader pid, so callers can authenticate the result to
     * the inode/hash-pinned executable rather than to a writable pathname. */
    if (cleanup_handoff_expected) {
      return LATE_LOAD_STATUS_KSU_CLEAN_ABORT;
    }
    dprintf(report_fd,
            "late-load: refused unexpected ksud cleanup-proof exit\n");
    return LATE_LOAD_STATUS_INTEGRITY;
  }
  if (exit_status >= LATE_LOAD_STATUS_KSUD_SPAN) {
    exit_status = LATE_LOAD_STATUS_KSUD_SPAN - 1;
  }
  dprintf(report_fd, "late-load: ksud exited %d\n", WEXITSTATUS(raw_status));
  return LATE_LOAD_STATUS_KSUD + exit_status;
}

static int late_load_worker_status(int raw_status) {
  if (WIFEXITED(raw_status)) {
    return WEXITSTATUS(raw_status);
  }
  if (WIFSIGNALED(raw_status)) {
    return 128 + WTERMSIG(raw_status);
  }
  return LATE_LOAD_STATUS_EXEC;
}

/* A bounded parent wait is part of the global-state rollback contract.  The
 * loader has PR_SET_PDEATHSIG=SIGKILL, so killing a wedged worker also tears
 * down a ksud child before the parent restores kptr_restrict and SELinux. */
static void kill_late_load_worker_group(pid_t worker, int worker_pidfd) {
  if (worker <= 1 || worker_pidfd < 0 ||
      late_load_pidfd_is_dead(worker_pidfd)) {
    return;
  }
  if (getpgid(worker) == worker) {
    (void)kill(-worker, SIGKILL);
  }
#ifdef SYS_pidfd_send_signal
  (void)syscall(SYS_pidfd_send_signal, worker_pidfd, SIGKILL, NULL, 0);
#else
  (void)kill(worker, SIGKILL);
#endif
}

static int wait_late_load_worker(pid_t worker, int worker_pidfd,
                                 int report_fd) {
  struct timespec start;
  if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
    dprintf(report_fd, "late-load: watchdog clock unavailable: %s\n",
            strerror(errno));
    kill_late_load_worker_group(worker, worker_pidfd);
    while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {
    }
    return LATE_LOAD_STATUS_EXEC;
  }

  for (;;) {
    int raw_status = 0;
    pid_t waited = waitpid(worker, &raw_status, WNOHANG);
    if (waited == worker) {
      return late_load_worker_status(raw_status);
    }
    if (waited < 0 && errno != EINTR) {
      int wait_errno = errno;
      dprintf(report_fd, "late-load: watchdog wait failed: %s\n",
              strerror(wait_errno));
      if (wait_errno != ECHILD) {
        kill_late_load_worker_group(worker, worker_pidfd);
        while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {
        }
      }
      return LATE_LOAD_STATUS_EXEC;
    }

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec - start.tv_sec >= LATE_LOAD_WORKER_TIMEOUT_SECONDS) {
      dprintf(report_fd,
              "late-load: worker exceeded %d-second watchdog; terminating\n",
              LATE_LOAD_WORKER_TIMEOUT_SECONDS);
      kill_late_load_worker_group(worker, worker_pidfd);
      while (waitpid(worker, NULL, 0) < 0 && errno == EINTR) {
      }
      return LATE_LOAD_STATUS_EXEC;
    }

    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = 100000000L,
    };
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
    }
  }
}

static int run_late_load_child(const char *kmi, const char *package,
                               int allow_shell, int enable_modules,
                               const char *run_id,
                               uid_t source_uid,
                               struct late_load_watch_mailbox *mailbox) {
  int status = LATE_LOAD_STATUS_OK;
  int kptr_was = -1;
  int restore_kptr = 0;
  int ksu_success_proven = 0;
  int ksu_cleanup_proven = 0;
  int cleanup_handoff_expected = 0;
  struct staged_ksud staged;
  memset(&staged, 0, sizeof(staged));

  status = stage_ksud(STDERR_FILENO, source_uid, &staged);
  if (status != LATE_LOAD_STATUS_OK) {
    goto cleanup;
  }

  kptr_was = read_kptr_restrict();
  if (kptr_was < 0) {
    dprintf(STDERR_FILENO,
            "late-load: cannot establish original kptr_restrict value\n");
    status = LATE_LOAD_STATUS_KPTR;
    goto cleanup;
  }
  if (!mailbox || kptr_was != mailbox->original_kptr) {
    dprintf(STDERR_FILENO,
            "late-load: worker/parent original kptr_restrict snapshots disagree\n");
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto cleanup;
  }
  restore_kptr = 1;
  if (kptr_was > 0) {
    /* Set this before the write: a successful write followed by a failed
     * readback still has to take the restoration path. */
    dprintf(STDERR_FILENO,
            "late-load: kptr_restrict=%d hides every address in "
            "/proc/kallsyms; setting 0 for the load\n",
            kptr_was);
    if (!set_kptr_restrict_checked(0, STDERR_FILENO)) {
      status = LATE_LOAD_STATUS_KPTR;
      goto cleanup;
    }
  } else if (read_kptr_restrict() != 0) {
    dprintf(STDERR_FILENO,
            "late-load: kptr_restrict changed before module resolution\n");
    status = LATE_LOAD_STATUS_KPTR;
    goto cleanup;
  }
  if (!verify_required_kallsyms_visible(STDERR_FILENO)) {
    status = LATE_LOAD_STATUS_KPTR;
    goto cleanup;
  }

  if (unshare(CLONE_NEWNS) != 0 ||
      mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
    dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n",
            strerror(errno));
    status = LATE_LOAD_STATUS_NAMESPACE;
    goto cleanup;
  }
  /* Never execute the shell-owned pathname. This path is below a root:root
   * 0700 directory and its descriptor was hashed against the build pin. */
  if (mount(staged.exec_path, LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
    dprintf(STDERR_FILENO, "late-load: bind trusted ksud: %s\n",
            strerror(errno));
    status = LATE_LOAD_STATUS_BIND;
    goto cleanup;
  }

  int loader_error_pipe[2] = {-1, -1};
  if (pipe2(loader_error_pipe, O_CLOEXEC) != 0) {
    dprintf(STDERR_FILENO, "late-load: loader error pipe: %s\n",
            strerror(errno));
    status = LATE_LOAD_STATUS_EXEC;
    goto cleanup;
  }

  /* Stage, hash, namespace and kallsyms preparation are complete. Reload the
   * policy as the final permissive operation, and require the exact zero byte
   * again in the exec child immediately before it enters ksud. */
  if (!reload_selinux_policy(STDERR_FILENO)) {
    close(loader_error_pipe[0]);
    close(loader_error_pipe[1]);
    status = LATE_LOAD_STATUS_SELINUX;
    goto cleanup;
  }

  cleanup_handoff_expected =
      mailbox && staged.ready && kptr_was == mailbox->original_kptr &&
      enable_modules == mailbox->enable_modules;
  if (!cleanup_handoff_expected) {
    dprintf(STDERR_FILENO,
            "late-load: cleanup handoff expectation did not bind exactly\n");
    close(loader_error_pipe[0]);
    close(loader_error_pipe[1]);
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto cleanup;
  }

  pid_t loader_parent = getpid();
  pid_t loader = fork();
  if (loader < 0) {
    dprintf(STDERR_FILENO, "late-load: fork: %s\n", strerror(errno));
    close(loader_error_pipe[0]);
    close(loader_error_pipe[1]);
    status = LATE_LOAD_STATUS_EXEC;
    goto cleanup;
  }
  if (loader == 0) {
    close(loader_error_pipe[0]);
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != loader_parent) {
      publish_loader_exec_error(loader_error_pipe[1], errno ? errno : ECHILD);
      _exit(LATE_LOAD_STATUS_EXEC);
    }
    char *loader_argv[11];
    size_t loader_argc = 0;
    loader_argv[loader_argc++] = "logcat";
    loader_argv[loader_argc++] = "late-load";
    loader_argv[loader_argc++] = "--kmi";
    loader_argv[loader_argc++] = (char *)kmi;
    loader_argv[loader_argc++] = "--package-name";
    loader_argv[loader_argc++] = (char *)package;
    if (allow_shell) {
      loader_argv[loader_argc++] = "--allow-shell";
    }
    if (enable_modules) {
      if (setenv("KSU_LATE_LOAD_MODULES", "1", 1) != 0 ||
          setenv(KSU_LATE_LOAD_RUN_ID_ENV, run_id, 1) != 0) {
        publish_loader_exec_error(loader_error_pipe[1], errno);
        _exit(LATE_LOAD_STATUS_EXEC);
      }
      loader_argv[loader_argc++] = "--modules";
    }
    loader_argv[loader_argc] = NULL;
    if (setenv(KSU_STAGE_PATH_ENV, staged.stage_path, 1) != 0 ||
        setenv(KSU_STAGE_SHA256_ENV, staged.digest_hex, 1) != 0) {
      publish_loader_exec_error(loader_error_pipe[1], errno);
      _exit(LATE_LOAD_STATUS_EXEC);
    }
    char cleanup_kptr[4];
    int cleanup_kptr_len =
        snprintf(cleanup_kptr, sizeof(cleanup_kptr), "%d", kptr_was);
    if (cleanup_kptr_len != 1 ||
        setenv(KSU_LATE_LOAD_CLEANUP_KPTR_ENV, cleanup_kptr, 1) != 0 ||
        setenv(KSU_LATE_LOAD_CLEANUP_MODULES_ENV,
               enable_modules ? "1" : "0", 1) != 0) {
      publish_loader_exec_error(loader_error_pipe[1], errno ? errno : EINVAL);
      _exit(LATE_LOAD_STATUS_EXEC);
    }
    if (!enforcing_is_exactly_zero(STDERR_FILENO)) {
      publish_loader_exec_error(loader_error_pipe[1], EPROTO);
      _exit(LATE_LOAD_STATUS_SELINUX);
    }
    execv(LOGCAT_PATH, loader_argv);
    publish_loader_exec_error(loader_error_pipe[1], errno);
    _exit(LATE_LOAD_STATUS_EXEC);
  }
  close(loader_error_pipe[1]);
  status = wait_loader_status(loader, loader_error_pipe[0], STDERR_FILENO,
                              cleanup_handoff_expected);
  ksu_success_proven = status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS;
  ksu_cleanup_proven = status == LATE_LOAD_STATUS_KSU_CLEAN_ABORT;
  if (ksu_success_proven && mailbox) {
    /* Unique setter: reserved exit 201 follows the empty exec-error pipe and
     * waitpid() of the exact hash/inode-pinned loader. */
    atomic_store_explicit(&mailbox->ksu_success_proven, 1,
                          memory_order_release);
  }
  if (ksu_cleanup_proven && mailbox) {
    /* Unique setter: it follows an empty exec-error pipe and waitpid() of the
     * exact loader child.  Neither the request parent nor watcher may infer
     * this proof merely from a generic ksud failure. */
    atomic_store_explicit(&mailbox->ksu_cleanup_proven, 1,
                          memory_order_release);
  }

cleanup:
  /* One restoration exit for every path after the sysctl may have changed.
   * A failed readback is an overall failure even if KernelSU is now live. */
  if (restore_kptr && !ksu_success_proven && !ksu_cleanup_proven &&
      !set_kptr_restrict_checked(kptr_was, STDERR_FILENO)) {
    status = LATE_LOAD_STATUS_KPTR_RESTORE;
  }

  /* No success postcondition is reopened here. KernelSU changed only the
   * loader child to u:r:ksu:s0; this C worker remains u:r:kernel:s0 and loses
   * these pathname authorities as soon as the module restores enforcing.
   * Reserved exit 201 authenticates the loader's retained-fd finalization. */
  if (enable_modules && status != LATE_LOAD_STATUS_OK &&
      !ksu_success_proven && !ksu_cleanup_proven) {
    /* ksud may have reached its final write before a restoration or integrity
     * check failed. A current-boot marker must never survive that outcome. */
    int trusted_cleared = clear_trusted_module_receipt(STDERR_FILENO);
    int public_cleared = clear_public_module_receipt(STDERR_FILENO);
    if (!trusted_cleared || !public_cleared) {
      status = LATE_LOAD_STATUS_INTEGRITY;
    }
  }
  if (!ksu_success_proven && !ksu_cleanup_proven) {
    cleanup_private_stage(&staged);
  }
  return status;
}

int su_run_late_load_sealed(struct su_request *request, int conn) {
  if (request->header.argc < LATE_LOAD_ARGC ||
      request->header.argc > LATE_LOAD_ARGC_MAX) {
    /* Reported rather than defaulted. A caller that does not name the KMI
     * cannot be served correctly, only served wrongly and silently. Written to
     * the client's stderr, which is the one the caller is reading. */
    dprintf(request->stderr_fd,
            "late-load: usage: su --late-load <kmi> <package-name> "
            "[" LATE_LOAD_ALLOW_SHELL_WORD "] [" LATE_LOAD_MODULES_WORD
            " " LATE_LOAD_RUN_ID_PREFIX "<32-lowercase-hex>]\n");
    close_request_fds(request);
    return LATE_LOAD_STATUS_USAGE;
  }
  const char *kmi = request->argv[LATE_LOAD_KMI_ARG];
  const char *package = request->argv[LATE_LOAD_PACKAGE_ARG];
  int allow_shell = 0;
  int enable_modules = 0;
  const char *run_id = NULL;
  for (uint32_t i = LATE_LOAD_OPTIONS_ARG; i < request->header.argc; i++) {
    if (strcmp(request->argv[i], LATE_LOAD_ALLOW_SHELL_WORD) == 0 &&
        !allow_shell) {
      allow_shell = 1;
    } else if (strcmp(request->argv[i], LATE_LOAD_MODULES_WORD) == 0 &&
               !enable_modules) {
      enable_modules = 1;
    } else if (strncmp(request->argv[i], LATE_LOAD_RUN_ID_PREFIX,
                       sizeof(LATE_LOAD_RUN_ID_PREFIX) - 1) == 0 &&
               !run_id) {
      const char *candidate =
          request->argv[i] + sizeof(LATE_LOAD_RUN_ID_PREFIX) - 1;
      size_t candidate_len = strlen(candidate);
      int valid = candidate_len == LATE_LOAD_RUN_ID_HEX_LEN;
      for (size_t at = 0; valid && at < candidate_len; at++) {
        valid = (candidate[at] >= '0' && candidate[at] <= '9') ||
                (candidate[at] >= 'a' && candidate[at] <= 'f');
      }
      if (!valid) {
        dprintf(request->stderr_fd,
                "late-load: run-id must be exactly 32 lowercase hex characters\n");
        close_request_fds(request);
        return LATE_LOAD_STATUS_USAGE;
      }
      run_id = candidate;
    } else {
      dprintf(request->stderr_fd,
              "late-load: unknown or duplicate option '%s'; expected "
              LATE_LOAD_ALLOW_SHELL_WORD ", " LATE_LOAD_MODULES_WORD ", or "
              LATE_LOAD_RUN_ID_PREFIX "<32-lowercase-hex>\n",
              request->argv[i]);
      close_request_fds(request);
      return LATE_LOAD_STATUS_USAGE;
    }
  }
  if ((enable_modules && !run_id) || (!enable_modules && run_id)) {
    dprintf(request->stderr_fd,
            "late-load: modules and run-id=<32-lowercase-hex> are required together\n");
    close_request_fds(request);
    return LATE_LOAD_STATUS_USAGE;
  }

  struct ucred peer;
  socklen_t peer_length = sizeof(peer);
  if (getsockopt(conn, SOL_SOCKET, SO_PEERCRED, &peer, &peer_length) != 0 ||
      peer_length != sizeof(peer) || peer.uid == 0) {
    dprintf(request->stderr_fd,
            "late-load: cannot establish the non-root staging owner\n");
    close_request_fds(request);
    return LATE_LOAD_STATUS_INTEGRITY;
  }

  errno = 0;
  int lock_fd = acquire_late_load_lock(request->stderr_fd);
  if (lock_fd < 0) {
    int lock_errno = errno;
    int status = lock_errno == EWOULDBLOCK || lock_errno == EAGAIN
                     ? LATE_LOAD_STATUS_BUSY
                     : LATE_LOAD_STATUS_INTEGRITY;
    close_request_fds(request);
    return status;
  }
  int status = LATE_LOAD_STATUS_OK;
  int parent_kptr_was = -1;
  int parent_kptr_restored = 0;
  int parent_receipts_clean = 1;
  int verified_ksu_cleanup_handoff = 0;
  int verified_ksu_success_handoff = 0;
  struct late_load_watch_mailbox *watch_mailbox = NULL;
  pid_t watcher = -1;
  int worker_pidfd = -1;

  /* Snapshot the sysctl in the waiting parent as well as in the worker. If the
   * worker is killed after exposing kallsyms, the parent still owns a verified
   * restoration path before it releases the global operation lock. */
  parent_kptr_was = read_kptr_restrict();
  if (parent_kptr_was < 0) {
    dprintf(request->stderr_fd,
            "late-load: parent cannot establish original kptr_restrict value\n");
    status = LATE_LOAD_STATUS_KPTR;
    goto parent_cleanup;
  }
  parent_kptr_restored = 1;
  if (!late_load_start_watcher(lock_fd, request->stderr_fd, parent_kptr_was,
                               enable_modules, &watch_mailbox, &watcher)) {
    status = LATE_LOAD_STATUS_INTEGRITY;
    goto parent_cleanup;
  }
  if (atomic_load_explicit(&watch_mailbox->decision,
                           memory_order_acquire) !=
      LATE_LOAD_WATCH_PENDING) {
    status = LATE_LOAD_STATUS_EXEC;
    goto parent_cleanup;
  }
  if (enable_modules) {
    int trusted_cleared = clear_trusted_module_receipt(request->stderr_fd);
    int public_cleared = clear_public_module_receipt(request->stderr_fd);
    if (!trusted_cleared || !public_cleared) {
      parent_receipts_clean = 0;
      status = LATE_LOAD_STATUS_INTEGRITY;
      goto parent_cleanup;
    }
  }

  pid_t worker_parent = getpid();
  pid_t pid = fork();
  if (pid < 0) {
    dprintf(request->stderr_fd, "late-load: fork worker: %s\n", strerror(errno));
    status = LATE_LOAD_STATUS_EXEC;
    goto parent_cleanup;
  }
  if (pid == 0) {
    if (!late_load_worker_bootstrap(watch_mailbox, worker_parent)) {
      _exit(LATE_LOAD_STATUS_CHILD_SETUP);
    }
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        fchdir(request->cwd_fd) != 0) {
      _exit(LATE_LOAD_STATUS_CHILD_SETUP);
    }
    close(conn);
    close_request_fds(request);
    _exit(run_late_load_child(kmi, package, allow_shell, enable_modules, run_id,
                              peer.uid, watch_mailbox));
  }
  int worker_bootstrap_ok =
      setpgid(pid, pid) == 0 &&
      late_load_wait_atomic(watch_mailbox, &watch_mailbox->worker_state,
                            LATE_LOAD_WORKER_PINNED,
                            LATE_LOAD_WATCHER_HANDSHAKE_MS) &&
      atomic_load_explicit(&watch_mailbox->decision,
                           memory_order_acquire) ==
          LATE_LOAD_WATCH_PENDING;
  if (worker_bootstrap_ok) {
    worker_pidfd = late_load_open_trusted_pidfd(pid);
    worker_bootstrap_ok = worker_pidfd >= 0 && getpgid(pid) == pid;
  }
  if (!worker_bootstrap_ok) {
    dprintf(request->stderr_fd,
            "late-load: worker process-group/pidfd bootstrap failed\n");
    if (worker_pidfd >= 0) {
      kill_late_load_worker_group(pid, worker_pidfd);
    } else {
      /* The child is still behind worker_release and is our unreaped child, so
       * its numeric process group cannot have been recycled. */
      (void)kill(-pid, SIGKILL);
      (void)kill(pid, SIGKILL);
    }
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
    if (worker_pidfd >= 0) {
      close(worker_pidfd);
      worker_pidfd = -1;
    }
    atomic_store_explicit(&watch_mailbox->worker_state,
                          LATE_LOAD_WORKER_DONE, memory_order_release);
    status = LATE_LOAD_STATUS_CHILD_SETUP;
    goto parent_cleanup;
  }
  atomic_store_explicit(&watch_mailbox->worker_release, 1,
                        memory_order_release);
  status = wait_late_load_worker(pid, worker_pidfd, request->stderr_fd);
  close(worker_pidfd);
  worker_pidfd = -1;
  atomic_store_explicit(&watch_mailbox->worker_state,
                        LATE_LOAD_WORKER_DONE, memory_order_release);

parent_cleanup:
  if (worker_pidfd >= 0) {
    close(worker_pidfd);
  }
  int success_bit =
      watch_mailbox &&
      atomic_load_explicit(&watch_mailbox->ksu_success_proven,
                           memory_order_acquire) == 1;
  int cleanup_bit =
      watch_mailbox &&
      atomic_load_explicit(&watch_mailbox->ksu_cleanup_proven,
                           memory_order_acquire) == 1;
  int ksu_success_proven =
      success_bit && !cleanup_bit &&
      status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS;
  int ksu_cleanup_proven =
      cleanup_bit && !success_bit &&
      status == LATE_LOAD_STATUS_KSU_CLEAN_ABORT;
  if ((success_bit !=
       (status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS)) ||
      (cleanup_bit != (status == LATE_LOAD_STATUS_KSU_CLEAN_ABORT)) ||
      (success_bit && cleanup_bit)) {
    /* A proof/status disagreement cannot be downgraded to ordinary cleanup or
     * success. The untrusted state retains fail-stop ownership. */
    status = LATE_LOAD_STATUS_INTEGRITY;
    ksu_success_proven = 0;
    ksu_cleanup_proven = 0;
  }
  int ksu_handoff_proven = ksu_success_proven || ksu_cleanup_proven;
  if (!ksu_handoff_proven && parent_kptr_was >= 0 &&
      !set_kptr_restrict_checked(parent_kptr_was, request->stderr_fd)) {
    parent_kptr_restored = 0;
    status = LATE_LOAD_STATUS_KPTR_RESTORE;
  }
  if (!ksu_handoff_proven && enable_modules &&
      status != LATE_LOAD_STATUS_OK) {
    parent_receipts_clean =
        invalidate_module_receipts_exact(request->stderr_fd);
    if (!parent_receipts_clean) {
      parent_receipts_clean = 0;
      status = LATE_LOAD_STATUS_INTEGRITY;
    }
  }
  /* Use the still-permissive window for the first receipt rollback and kptr
   * restoration. A second receipt join below is still mandatory because this
   * enforcing check can itself turn a nominal success into failure. */
  int enforcing_result =
      ksu_handoff_proven
          ? 1
          : ensure_enforcing_one_after_worker(request->stderr_fd);
  int selinux_cleanup_failed =
      enforcing_result == 0 ||
      (status == LATE_LOAD_STATUS_OK && enforcing_result != 1);
  if (selinux_cleanup_failed) {
    /* A nominal worker success that needed the watchdog is not success, and a
     * failed recovery takes precedence over receipt-cleanup diagnostics. */
    status = LATE_LOAD_STATUS_SELINUX;
  }
  /* `ensure_enforcing_one_after_worker()` can be the operation that changes a
   * nominal worker success into a SELinux failure. Invalidate only after that
   * status is final, then prove both the root-private authority and public
   * mirror absent. This second join is intentional even when the earlier,
   * still-permissive best-effort invalidation already ran. */
  if (!ksu_handoff_proven && enable_modules &&
      status != LATE_LOAD_STATUS_OK) {
    parent_receipts_clean =
        invalidate_module_receipts_exact(request->stderr_fd);
    if (!parent_receipts_clean) {
      status = LATE_LOAD_STATUS_INTEGRITY;
    }
  }
  int parent_cleanup_ready =
      ksu_handoff_proven ||
      (parent_kptr_restored && parent_receipts_clean && enforcing_result != 0);
  if (watch_mailbox) {
    int watcher_result = late_load_finish_watcher(
        watch_mailbox, watcher, status, parent_cleanup_ready);
    verified_ksu_cleanup_handoff =
        status == LATE_LOAD_STATUS_KSU_CLEAN_ABORT &&
        ksu_cleanup_proven && watcher_result == 0;
    verified_ksu_success_handoff =
        status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS &&
        ksu_success_proven && watcher_result == 1;
    if (verified_ksu_success_handoff) {
      /* Normalize only after the watcher acknowledged the authenticated proof
       * and was reaped cleanly. */
      status = LATE_LOAD_STATUS_OK;
    } else if (ksu_success_proven) {
      late_load_proven_success_fail_stop();
    } else if (status == LATE_LOAD_STATUS_KSU_CLEAN_SUCCESS ||
               (watcher_result != 1 && status == LATE_LOAD_STATUS_OK)) {
      status = LATE_LOAD_STATUS_INTEGRITY;
    }
    munmap(watch_mailbox, sizeof(*watch_mailbox));
    watch_mailbox = NULL;
  }
  if (status != LATE_LOAD_STATUS_OK &&
      !verified_ksu_cleanup_handoff) {
    /* This join is deliberately unbounded.  It covers a watcher that exited
     * abnormally after PREPARE/FINAL as well as transient unlink/open/fsync
     * faults.  request FDs and the root-private operation flock remain live
     * until both receipt names are durably absent and global state is exact. */
    late_load_parent_fail_stop_cleanup(parent_kptr_was, enable_modules,
                                       request->stderr_fd);
  }
  close_request_fds(request);
  close(lock_fd);
  return status;
}

void su_late_load_report_sealed(int status, int fd) {
  /* The band starts one above its base: it is only entered for a loader status
   * that is already nonzero, so LATE_LOAD_STATUS_KSUD itself is never sent and
   * is not a "ksud exited 0" to be reported as one. */
  if (status > LATE_LOAD_STATUS_KSUD &&
      status < LATE_LOAD_STATUS_KSUD + LATE_LOAD_STATUS_KSUD_SPAN) {
    dprintf(fd,
            "late-load: ksud stopped, exit %d -- the module may or may not "
            "have loaded. `logcat -d | grep KernelSU` has its own account.\n",
            status - LATE_LOAD_STATUS_KSUD);
    return;
  }
  if (status > LATE_LOAD_STATUS_KSUD_SIGNAL &&
      status < LATE_LOAD_STATUS_KSUD_SIGNAL +
                   LATE_LOAD_STATUS_KSUD_SIGNAL_SPAN) {
    dprintf(fd,
            "late-load: ksud/loader worker terminated by signal %d; no success "
            "receipt is trusted\n",
            status - LATE_LOAD_STATUS_KSUD_SIGNAL);
    return;
  }

  const char *text;
  switch (status) {
    case LATE_LOAD_STATUS_OK:
      /* Said here as well as in verify_kernelsu_control, which by then is
       * writing to descriptors the policy reload has taken back. */
      text = "KernelSU loaded and answering";
      break;
    case LATE_LOAD_STATUS_NAMESPACE:
      text = "could not unshare a mount namespace";
      break;
    case LATE_LOAD_STATUS_BIND:
      text = "could not cover the loader path -- is ksud staged?";
      break;
    case LATE_LOAD_STATUS_EXEC:
      text = "could not run the staged ksud";
      break;
    case LATE_LOAD_STATUS_NO_DRIVER:
      text = "ksud finished but no KernelSU driver answered";
      break;
    case LATE_LOAD_STATUS_CONTROL:
      text = "KernelSU answered but reported itself incomplete";
      break;
    case LATE_LOAD_STATUS_STAGE:
      text = "could not stage ksud for its own install -- is " KSUD_PATH
             " there?";
      break;
    case LATE_LOAD_STATUS_SELINUX:
      text = "SELinux state/policy capability restoration was not verified";
      break;
    case LATE_LOAD_STATUS_KPTR:
      text = "could not expose and verify kallsyms for manual relocation";
      break;
    case LATE_LOAD_STATUS_KPTR_RESTORE:
      text = "could not restore kptr_restrict after module loading";
      break;
    case LATE_LOAD_STATUS_INTEGRITY:
      text = "ksud staging identity or claimed-inode SHA-256 did not verify";
      break;
    case LATE_LOAD_STATUS_BUSY:
      text = "another serialized late-load operation is still active";
      break;
    case LATE_LOAD_STATUS_CHILD_SETUP:
      text = "could not prepare the isolated late-load worker";
      break;
    case LATE_LOAD_STATUS_USAGE:
      text = "usage: su --late-load <kmi> <package-name> [allow-shell] "
             "[modules run-id=<32-lowercase-hex>]";
      break;
    case LATE_LOAD_STATUS_KSU_CLEAN_ABORT:
      text = "ksud failed after loading KernelSU; authenticated ksu-domain "
             "rollback was authenticated and verified";
      break;
    default:
      /* Not this file's: the daemon refused the request before reaching it. */
      return;
  }
  dprintf(fd, "late-load: %s (%d)\n", text, status);
}
