#define _GNU_SOURCE

#include "su_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

/* Where the caller staged ksud, and the binary it is bind-mounted over. The
 * cover has to be something the daemon may exec and that nothing else is
 * running: only this file cares which one it is. */
#define KSUD_PATH "/data/local/tmp/ksud"
#define LOGCAT_PATH "/system/bin/logcat"

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
 * su_late_load_report() below is what turns it back into a line -- printed by
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
#define LATE_LOAD_STATUS_USAGE 22
#define LATE_LOAD_STATUS_KSUD 64
#define LATE_LOAD_STATUS_KSUD_SPAN 64

/*
 * argv is `su --late-load <kmi> <package> [allow-shell]`.
 *
 * The optional fourth word is for bring-up. KernelSU decides who may become
 * root from its own allowlist, which on a fresh late-load holds only the
 * manager; `allow-shell` passes ksud's --allow-shell so `su` answers the adb
 * shell too, which is the only way to demonstrate KernelSU's own root without
 * a working manager app. The application does not pass it and should not: it
 * hands root to anyone with adb for as long as the module is loaded.
 */
#define LATE_LOAD_ARGC 4U
#define LATE_LOAD_ARGC_MAX 5U
#define LATE_LOAD_KMI_ARG 2U
#define LATE_LOAD_PACKAGE_ARG 3U
#define LATE_LOAD_ALLOW_SHELL_ARG 4U
#define LATE_LOAD_ALLOW_SHELL_WORD "allow-shell"

#define SELINUX_POLICY_PATH "/sys/fs/selinux/policy"
#define SELINUX_LOAD_PATH "/sys/fs/selinux/load"
#define SELINUX_POLICY_MAX (32U * 1024U * 1024U)

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
 * To be clear about what this is and is not: it is a latent defect, repaired
 * here because the repair is cheap and provably harmless. It is *not* the
 * cause of applications dying on launch after a run. That was measured
 * separately, against a clean-boot control, and survives this repair; see the
 * open-defect section of the port notes.
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
/*
 * `enforcing` is the one byte of that word the write does choose, and it has to
 * read back as exactly "0" here: the exploit cleared it and nothing since is
 * supposed to have touched it. A run has been seen where it read "166" -- a
 * byte of a kernel pointer, not a boolean -- which is the same word being
 * written a second time. A policy reload cannot repair that byte, so this only
 * reports it; but it is the difference between "ksud turned enforcing back on"
 * and "the SELinux state was already garbage", and that is worth knowing from
 * the log rather than from the device afterwards.
 */
static void report_enforcing_byte(int report_fd) {
  char value[16];
  int fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return;
  }
  ssize_t got = read(fd, value, sizeof(value) - 1);
  close(fd);
  if (got <= 0) {
    return;
  }
  value[got] = '\0';
  if (strcmp(value, "0") != 0) {
    dprintf(report_fd,
            "late-load: selinux enforce reads '%s', expected '0' -- the state "
            "word has been written again since the exploit cleared it\n",
            value);
  }
}

static void reload_selinux_policy(int report_fd) {
  report_enforcing_byte(report_fd);

  int policy_fd = open(SELINUX_POLICY_PATH, O_RDONLY | O_CLOEXEC);
  if (policy_fd < 0) {
    dprintf(report_fd, "late-load: selinux policy unreadable: %s\n",
            strerror(errno));
    return;
  }
  struct stat st;
  if (fstat(policy_fd, &st) != 0 || st.st_size <= 0 ||
      (size_t)st.st_size > SELINUX_POLICY_MAX) {
    close(policy_fd);
    dprintf(report_fd, "late-load: selinux policy size refused\n");
    return;
  }

  size_t len = (size_t)st.st_size;
  char *policy = malloc(len);
  if (!policy) {
    close(policy_fd);
    return;
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
    return;
  }

  /* One write: the kernel takes the policy as a single image. */
  int load_fd = open(SELINUX_LOAD_PATH, O_WRONLY | O_CLOEXEC);
  if (load_fd < 0) {
    free(policy);
    dprintf(report_fd, "late-load: selinux load unwritable: %s\n",
            strerror(errno));
    return;
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
    return;
  }
  dprintf(report_fd, "late-load: policy capabilities restored (%zu bytes)\n",
          len);
}

struct ksu_get_info_cmd {
  uint32_t version;
  uint32_t flags;
  uint32_t features;
  uint32_t uapi_version;
};

static int verify_kernelsu_control(void) {
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

int su_run_late_load(struct su_request *request, int conn) {
  if (request->header.argc < LATE_LOAD_ARGC ||
      request->header.argc > LATE_LOAD_ARGC_MAX) {
    /* Reported rather than defaulted. A caller that does not name the KMI
     * cannot be served correctly, only served wrongly and silently. Written to
     * the client's stderr, which is the one the caller is reading. */
    dprintf(request->stderr_fd,
            "late-load: usage: su --late-load <kmi> <package-name> "
            "[" LATE_LOAD_ALLOW_SHELL_WORD "]\n");
    close_request_fds(request);
    return LATE_LOAD_STATUS_USAGE;
  }
  const char *kmi = request->argv[LATE_LOAD_KMI_ARG];
  const char *package = request->argv[LATE_LOAD_PACKAGE_ARG];
  int allow_shell = request->header.argc == LATE_LOAD_ARGC_MAX;
  if (allow_shell &&
      strcmp(request->argv[LATE_LOAD_ALLOW_SHELL_ARG],
             LATE_LOAD_ALLOW_SHELL_WORD) != 0) {
    dprintf(request->stderr_fd,
            "late-load: unknown option '%s'; the only one is "
            LATE_LOAD_ALLOW_SHELL_WORD "\n",
            request->argv[LATE_LOAD_ALLOW_SHELL_ARG]);
    close_request_fds(request);
    return LATE_LOAD_STATUS_USAGE;
  }

  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        fchdir(request->cwd_fd) != 0) {
      _exit(126);
    }
    close(conn);
    close_request_fds(request);

    /* Before the namespace, because it is about the whole system rather than
     * this mount tree, and before ksud, because ksud is what makes it matter. */
    reload_selinux_policy(STDERR_FILENO);

    if (unshare(CLONE_NEWNS) != 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n",
              strerror(errno));
      _exit(LATE_LOAD_STATUS_NAMESPACE);
    }
    if (mount(KSUD_PATH, LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: bind mount: %s\n", strerror(errno));
      _exit(LATE_LOAD_STATUS_BIND);
    }

    pid_t loader = fork();
    if (loader < 0) {
      dprintf(STDERR_FILENO, "late-load: fork: %s\n", strerror(errno));
      _exit(LATE_LOAD_STATUS_EXEC);
    }
    if (loader == 0) {
      if (allow_shell) {
        execl(LOGCAT_PATH, "logcat", "late-load", "--kmi", kmi,
              "--package-name", package, "--allow-shell", (char *)NULL);
      } else {
        execl(LOGCAT_PATH, "logcat", "late-load", "--kmi", kmi,
              "--package-name", package, (char *)NULL);
      }
      dprintf(STDERR_FILENO, "late-load: exec: %s\n", strerror(errno));
      _exit(LATE_LOAD_STATUS_EXEC);
    }

    int loader_status = wait_status(loader);
    if (loader_status != 0) {
      /* Clamped, not truncated: the band has to stay a band. Which value
       * inside it is a hint only -- ksud's own reason for stopping is in the
       * Android log under the KernelSU tag, and it gets there whatever the
       * policy does to the descriptors here. */
      if (loader_status >= LATE_LOAD_STATUS_KSUD_SPAN) {
        loader_status = LATE_LOAD_STATUS_KSUD_SPAN - 1;
      }
      dprintf(STDERR_FILENO, "late-load: ksud exited %d\n", loader_status);
      _exit(LATE_LOAD_STATUS_KSUD + loader_status);
    }
    _exit(verify_kernelsu_control());
  }
  close_request_fds(request);
  return wait_status(pid);
}

void su_late_load_report(int status, int fd) {
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
    case LATE_LOAD_STATUS_USAGE:
      text = "usage: su --late-load <kmi> <package-name>";
      break;
    default:
      /* Not this file's: the daemon refused the request before reaching it. */
      return;
  }
  dprintf(fd, "late-load: %s (%d)\n", text, status);
}
