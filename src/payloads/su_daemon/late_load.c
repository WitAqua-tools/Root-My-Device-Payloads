#define _GNU_SOURCE

#include "su_daemon.h"

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
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

/* argv is `su --late-load <kmi> <package>`. */
#define LATE_LOAD_ARGC 4U
#define LATE_LOAD_KMI_ARG 2U
#define LATE_LOAD_PACKAGE_ARG 3U

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
    return 13;
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
    return 14;
  }

  dprintf(STDOUT_FILENO,
          "KernelSU control verified version=%u flags=0x%x "
          "uapi=%u features=0x%x\n",
          info.version, info.flags, info.uapi_version, info.features);
  return 0;
}

int su_run_late_load(struct su_request *request, int conn) {
  if (request->header.argc != LATE_LOAD_ARGC) {
    /* Reported rather than defaulted. A caller that does not name the KMI
     * cannot be served correctly, only served wrongly and silently. Written to
     * the client's stderr, which is the one the caller is reading. */
    dprintf(request->stderr_fd,
            "late-load: usage: su --late-load <kmi> <package-name>\n");
    close_request_fds(request);
    return 22;
  }
  const char *kmi = request->argv[LATE_LOAD_KMI_ARG];
  const char *package = request->argv[LATE_LOAD_PACKAGE_ARG];

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

    if (unshare(CLONE_NEWNS) != 0 ||
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: private mount namespace: %s\n",
              strerror(errno));
      _exit(10);
    }
    if (mount(KSUD_PATH, LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: bind mount: %s\n", strerror(errno));
      _exit(11);
    }

    pid_t loader = fork();
    if (loader < 0) {
      dprintf(STDERR_FILENO, "late-load: fork: %s\n", strerror(errno));
      _exit(12);
    }
    if (loader == 0) {
      execl(LOGCAT_PATH, "logcat", "late-load", "--kmi", kmi,
            "--package-name", package, (char *)NULL);
      dprintf(STDERR_FILENO, "late-load: exec: %s\n", strerror(errno));
      _exit(12);
    }

    int loader_status = wait_status(loader);
    if (loader_status != 0) {
      _exit(loader_status);
    }
    _exit(verify_kernelsu_control());
  }
  close_request_fds(request);
  return wait_status(pid);
}
