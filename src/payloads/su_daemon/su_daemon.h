#ifndef SU_DAEMON_H
#define SU_DAEMON_H

/*
 * The seam between the su daemon proper and the two things that are not it.
 *
 * One helper binary is built and the application ships that one copy in its
 * APK for every target, so nothing here may know which device it is running
 * on. What used to sit in su_daemon.c and did know is now separated out:
 *
 *   late_load.c  everything that knows KernelSU exists. The KMI and the
 *                manager package are the target's, and arrive as arguments
 *                rather than being compiled in.
 *   hold_refs.c  the kernel-page reference holder, which exists for core66
 *                alone and is dead weight on any other core.
 *
 * su_daemon.c is then a plain su daemon: a protocol, a uid check, and exec.
 * It reaches the two above through the entry points at the bottom of this
 * file and knows nothing else about either.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <termios.h>
#include <sys/ioctl.h>

/*
 * Paths that are contracts with something outside this program, so they are
 * spelled here rather than wherever they happen to be used.
 *
 * BOOTSTRAP_SOCK_PATH is also spelled in the payload's root glue
 * (core66/root.c and core612/root.c, as ROOT_SOCKET_PATH): that is where the
 * two sides meet, and the payload cannot include this header.
 */
#define BOOTSTRAP_SOCK_PATH "/data/local/tmp/temp_su.sock"
#define SH_PATH "/system/bin/sh"

#define SU_PASSED_FDS 5U

struct su_tty_state {
  uint8_t has_termios;
  uint8_t has_winsize;
  struct termios termios;
  struct winsize winsize;
};

struct su_request_header {
  uint32_t magic;
  uint32_t version;
  uint32_t argc;
  uint32_t envc;
  uint8_t interactive;
  uint8_t reserved[3];
  struct su_tty_state tty;
};

struct su_request {
  struct su_request_header header;
  char **argv;
  char **envp;
  int stdin_fd;
  int stdout_fd;
  int stderr_fd;
  int cwd_fd;
  int io_fd;
};

/* su_daemon.c, for the separated parts. */
int write_full(int fd, const void *buf, size_t len);
int wait_status(pid_t pid);
void close_request_fds(struct su_request *request);

/*
 * late_load.c. Serves `su --late-load <kmi> <package>`: bind-mounts the staged
 * ksud over a binary it may exec, runs it, and checks the module answered.
 * Both arguments are the target's and are required -- see the file.
 */
int su_run_late_load(struct su_request *request, int conn);

/*
 * hold_refs.c. Serves the 'H' opcode: takes file descriptors over the
 * connection and never closes them. Only core66 sends it.
 */
void su_hold_kernel_references(int conn);

#endif
