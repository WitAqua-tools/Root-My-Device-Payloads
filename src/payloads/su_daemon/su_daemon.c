#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

#include "su_daemon.h"

/* Overwritten by --umh with the uid the payload was launched as, before the
 * daemon starts serving. 2000 is adb shell, the uid a hand-run daemon serves. */
static uid_t allowed_client_uid = 2000;

#define SU_PROTOCOL_MAGIC 0x53553235U
#define SU_PROTOCOL_VERSION 1U
#define SU_RESPONSE_MAGIC 0x53555235U
#define SU_MAX_ARGC 256U
#define SU_MAX_ENVC 512U
#define SU_MAX_STRING 65536U
#define SU_MAX_REQUEST_BYTES (1024U * 1024U)

extern char **environ;

struct su_response {
  uint32_t magic;
  int32_t status;
};

static int saved_terminal_fd = -1;
static struct termios saved_terminal;

static void restore_terminal(void) {
  if (saved_terminal_fd >= 0) {
    tcsetattr(saved_terminal_fd, TCSANOW, &saved_terminal);
    saved_terminal_fd = -1;
  }
}

static void set_root_env(void) {
  char hostname[PROP_VALUE_MAX];

  setenv("PATH",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin",
         1);
  setenv("HOME", "/data/local/tmp", 1);
  setenv("USER", "root", 1);
  setenv("LOGNAME", "root", 1);
  if (__system_property_get("ro.product.device", hostname) > 0) {
    setenv("HOSTNAME", hostname, 1);
  }
}

int write_full(int fd, const void *buf, size_t len) {
  const char *p = buf;

  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int read_full(int fd, void *buf, size_t len) {
  char *p = buf;

  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int connect_daemon(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    perror("su: socket");
    return -1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("su: connect daemon");
    close(fd);
    return -1;
  }
  return fd;
}

static uint32_t vector_count(char *const values[], uint32_t limit) {
  uint32_t count = 0;

  while (values[count]) {
    if (count == limit) {
      return UINT32_MAX;
    }
    count++;
  }
  return count;
}

static int send_fds(int socket_fd, const int fds[SU_PASSED_FDS]) {
  char marker = 'F';
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int) * SU_PASSED_FDS);
  memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * SU_PASSED_FDS);

  return sendmsg(socket_fd, &msg, 0) == (ssize_t)sizeof(marker);
}

static int recv_fds(int socket_fd, int fds[SU_PASSED_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * SU_PASSED_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'F') {
    return 0;
  }

  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * SU_PASSED_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * SU_PASSED_FDS);
  return 1;
}

static int send_vector(int fd, char *const values[], uint32_t count) {
  for (uint32_t i = 0; i < count; i++) {
    size_t len = strlen(values[i]);
    if (len > SU_MAX_STRING) {
      return 0;
    }
    uint32_t wire_len = (uint32_t)len;
    if (!write_full(fd, &wire_len, sizeof(wire_len)) ||
        !write_full(fd, values[i], wire_len)) {
      return 0;
    }
  }
  return 1;
}

static char **recv_vector(int fd, uint32_t count, size_t *total_bytes) {
  char **values = calloc((size_t)count + 1, sizeof(*values));
  if (!values) {
    return NULL;
  }

  for (uint32_t i = 0; i < count; i++) {
    uint32_t len;
    if (!read_full(fd, &len, sizeof(len)) || len > SU_MAX_STRING ||
        *total_bytes + len > SU_MAX_REQUEST_BYTES) {
      goto fail;
    }
    values[i] = calloc(1, (size_t)len + 1);
    if (!values[i] || !read_full(fd, values[i], len)) {
      goto fail;
    }
    *total_bytes += len;
  }
  return values;

fail:
  for (uint32_t i = 0; i < count; i++) {
    free(values[i]);
  }
  free(values);
  return NULL;
}

void close_request_fds(struct su_request *request) {
  int *fds[] = {&request->stdin_fd, &request->stdout_fd, &request->stderr_fd,
                &request->cwd_fd, &request->io_fd};
  for (size_t i = 0; i < SU_PASSED_FDS; i++) {
    if (*fds[i] >= 0) {
      close(*fds[i]);
      *fds[i] = -1;
    }
  }
}

static void free_request(struct su_request *request) {
  if (request->argv) {
    for (uint32_t i = 0; i < request->header.argc; i++) {
      free(request->argv[i]);
    }
    free(request->argv);
  }
  if (request->envp) {
    for (uint32_t i = 0; i < request->header.envc; i++) {
      free(request->envp[i]);
    }
    free(request->envp);
  }
  close_request_fds(request);
}

static int recv_request(int conn, struct su_request *request) {
  int fds[SU_PASSED_FDS];
  size_t total_bytes = 0;
  memset(request, 0, sizeof(*request));
  request->stdin_fd = -1;
  request->stdout_fd = -1;
  request->stderr_fd = -1;
  request->cwd_fd = -1;
  request->io_fd = -1;

  if (!recv_fds(conn, fds)) {
    return 0;
  }
  request->stdin_fd = fds[0];
  request->stdout_fd = fds[1];
  request->stderr_fd = fds[2];
  request->cwd_fd = fds[3];
  request->io_fd = fds[4];

  if (!read_full(conn, &request->header, sizeof(request->header)) ||
      request->header.magic != SU_PROTOCOL_MAGIC ||
      request->header.version != SU_PROTOCOL_VERSION ||
      request->header.argc == 0 || request->header.argc > SU_MAX_ARGC ||
      request->header.envc > SU_MAX_ENVC) {
    return 0;
  }

  request->argv =
      recv_vector(conn, request->header.argc, &total_bytes);
  if (!request->argv) {
    return 0;
  }
  request->envp =
      recv_vector(conn, request->header.envc, &total_bytes);
  return request->envp != NULL;
}

int wait_status(pid_t pid) {
  int status;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) {
      return 1;
    }
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return 1;
}

static void send_response(int conn, int status) {
  struct su_response response = {
      .magic = SU_RESPONSE_MAGIC,
      .status = status,
  };
  write_full(conn, &response, sizeof(response));
}

static int prepare_child(struct su_request *request) {
  environ = request->envp;
  if (fchdir(request->cwd_fd) != 0) {
    return 0;
  }
  set_root_env();
  request->argv[0] = "sh";
  return 1;
}

static void close_child_request_fds(struct su_request *request) {
  close_request_fds(request);
}

static int run_direct(struct su_request *request, int conn) {
  pid_t pid = fork();
  if (pid < 0) {
    return 1;
  }
  if (pid == 0) {
    if (dup2(request->stdin_fd, STDIN_FILENO) < 0 ||
        dup2(request->stdout_fd, STDOUT_FILENO) < 0 ||
        dup2(request->stderr_fd, STDERR_FILENO) < 0 ||
        !prepare_child(request)) {
      _exit(126);
    }
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }
  close_request_fds(request);
  return wait_status(pid);
}

static int open_pty_master(char *slave, size_t slave_len) {
  int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (master < 0) {
    return -1;
  }
  if (grantpt(master) != 0 || unlockpt(master) != 0 ||
      ptsname_r(master, slave, slave_len) != 0) {
    close(master);
    return -1;
  }
  return master;
}

static int pump_client_io(int tty_fd, int io_fd) {
  char buf[4096];
  int tty_open = 1;

  while (1) {
    struct pollfd pfd[2];
    int nfd = 0;
    if (tty_open) {
      pfd[nfd].fd = tty_fd;
      pfd[nfd].events = POLLIN;
      nfd++;
    }
    pfd[nfd].fd = io_fd;
    pfd[nfd].events = POLLIN;
    int io_index = nfd++;

    int ret = poll(pfd, (nfds_t)nfd, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (tty_open) {
      short events = pfd[0].revents;
      if (events & POLLIN) {
        ssize_t n = read(tty_fd, buf, sizeof(buf));
        if (n > 0) {
          if (!write_full(io_fd, buf, (size_t)n)) {
            return 0;
          }
        } else {
          tty_open = 0;
          shutdown(io_fd, SHUT_WR);
        }
      } else if (events & (POLLHUP | POLLERR | POLLNVAL)) {
        tty_open = 0;
        shutdown(io_fd, SHUT_WR);
      }
    }

    short io_events = pfd[io_index].revents;
    if (io_events & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(STDOUT_FILENO, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (io_events & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int pump_server_pty(int io_fd, int master_fd) {
  char buf[4096];

  while (1) {
    struct pollfd pfd[2] = {
        {.fd = io_fd, .events = POLLIN},
        {.fd = master_fd, .events = POLLIN},
    };
    int ret = poll(pfd, 2, -1);
    if (ret < 0 && errno == EINTR) {
      continue;
    }
    if (ret < 0) {
      return 1;
    }

    if (pfd[0].revents & POLLIN) {
      ssize_t n = read(io_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(master_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 1;
      }
    }
    if (pfd[0].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 1;
    }

    if (pfd[1].revents & POLLIN) {
      ssize_t n = read(master_fd, buf, sizeof(buf));
      if (n > 0) {
        if (!write_full(io_fd, buf, (size_t)n)) {
          return 1;
        }
      } else {
        return 0;
      }
    }
    if (pfd[1].revents & (POLLHUP | POLLERR | POLLNVAL)) {
      return 0;
    }
  }
}

static int run_interactive(struct su_request *request, int conn) {
  char slave_name[128];
  int master = open_pty_master(slave_name, sizeof(slave_name));
  if (master < 0) {
    close_request_fds(request);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    close(master);
    close_request_fds(request);
    return 1;
  }
  if (pid == 0) {
    setsid();
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
      _exit(126);
    }
    if (request->header.tty.has_termios) {
      tcsetattr(slave, TCSANOW, &request->header.tty.termios);
    }
    if (request->header.tty.has_winsize) {
      ioctl(slave, TIOCSWINSZ, &request->header.tty.winsize);
    }
    ioctl(slave, TIOCSCTTY, 0);
    if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 ||
        dup2(slave, STDERR_FILENO) < 0 || !prepare_child(request)) {
      _exit(126);
    }
    if (slave > STDERR_FILENO) {
      close(slave);
    }
    close(master);
    close(conn);
    close_child_request_fds(request);
    execv(SH_PATH, request->argv);
    _exit(127);
  }

  int io_fd = request->io_fd;
  request->io_fd = -1;
  close_request_fds(request);
  int client_gone = pump_server_pty(io_fd, master);
  if (client_gone) {
    kill(pid, SIGHUP);
  }
  int status = wait_status(pid);
  close(master);
  close(io_fd);
  return status;
}

static int client_send_request(int conn, int argc, char **argv,
                               int interactive, int io_server_fd) {
  uint32_t envc = vector_count(environ, SU_MAX_ENVC);
  if ((uint32_t)argc > SU_MAX_ARGC || envc == UINT32_MAX) {
    return 0;
  }

  int cwd_fd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (cwd_fd < 0) {
    return 0;
  }
  int fds[SU_PASSED_FDS] = {STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO,
                            cwd_fd, io_server_fd};

  struct su_request_header header;
  memset(&header, 0, sizeof(header));
  header.magic = SU_PROTOCOL_MAGIC;
  header.version = SU_PROTOCOL_VERSION;
  header.argc = (uint32_t)argc;
  header.envc = envc;
  header.interactive = interactive != 0;
  if (interactive) {
    header.tty.has_termios =
        tcgetattr(STDIN_FILENO, &header.tty.termios) == 0;
    header.tty.has_winsize =
        ioctl(STDIN_FILENO, TIOCGWINSZ, &header.tty.winsize) == 0;
  }

  int ok = send_fds(conn, fds) &&
           write_full(conn, &header, sizeof(header)) &&
           send_vector(conn, argv, header.argc) &&
           send_vector(conn, environ, header.envc);
  close(cwd_fd);
  return ok;
}

static int client_main(int argc, char **argv) {
  int conn = connect_daemon();
  if (conn < 0) {
    return 127;
  }

  char auth;
  if (!read_full(conn, &auth, sizeof(auth))) {
    close(conn);
    return 1;
  }
  if (auth != 'A') {
    dprintf(STDERR_FILENO, "su: permission denied\n");
    close(conn);
    return 1;
  }

  int interactive = isatty(STDIN_FILENO);
  int io_pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, io_pair) != 0) {
    close(conn);
    return 1;
  }
  if (!client_send_request(conn, argc, argv, interactive, io_pair[1])) {
    close(io_pair[0]);
    close(io_pair[1]);
    close(conn);
    return 1;
  }
  close(io_pair[1]);

  if (interactive) {
    if (tcgetattr(STDIN_FILENO, &saved_terminal) == 0) {
      struct termios raw = saved_terminal;
      cfmakeraw(&raw);
      if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
        saved_terminal_fd = STDIN_FILENO;
        atexit(restore_terminal);
      }
    }
    pump_client_io(STDIN_FILENO, io_pair[0]);
    restore_terminal();
  }
  close(io_pair[0]);

  struct su_response response;
  if (!read_full(conn, &response, sizeof(response)) ||
      response.magic != SU_RESPONSE_MAGIC) {
    close(conn);
    return 1;
  }
  close(conn);
  /* A late-load reports here rather than where it happened: it reloads the
   * sepolicy partway through, and from then on the daemon side is writing to
   * descriptors this process owns but its domain no longer may. This side is
   * the caller, so this line always arrives. */
  if (argc >= 2 && strcmp(argv[1], "--late-load") == 0) {
    su_late_load_report(response.status, STDERR_FILENO);
  }
  return response.status;
}

static int get_peer_cred(int conn, struct ucred *peer) {
  socklen_t peer_len = sizeof(*peer);
  return getsockopt(conn, SOL_SOCKET, SO_PEERCRED, peer, &peer_len) == 0 &&
         peer_len == sizeof(*peer);
}

static void serve_one(int conn) {
  struct ucred peer;
  if (!get_peer_cred(conn, &peer) || peer.uid != allowed_client_uid) {
    char denied = 'D';
    write_full(conn, &denied, sizeof(denied));
    return;
  }
  char allowed = 'A';
  if (!write_full(conn, &allowed, sizeof(allowed))) {
    return;
  }

  char operation = 0;
  if (recv(conn, &operation, sizeof(operation), MSG_PEEK) ==
          (ssize_t)sizeof(operation) &&
      operation == 'H') {
    if (!read_full(conn, &operation, sizeof(operation))) {
      return;
    }
    su_hold_kernel_references(conn);
    return;
  }

  struct su_request request;
  if (!recv_request(conn, &request)) {
    free_request(&request);
    send_response(conn, 1);
    return;
  }

  /* Dispatched on the verb alone, so a --late-load with the wrong number of
   * arguments is answered by the code that knows what they should be rather
   * than falling through to `sh --late-load`. */
  int is_late_load = request.header.argc >= 2 &&
                     strcmp(request.argv[1], "--late-load") == 0;
  int status = is_late_load
                   ? su_run_late_load(&request, conn)
                   : request.header.interactive
                         ? run_interactive(&request, conn)
                         : run_direct(&request, conn);
  send_response(conn, status);
  free_request(&request);
}

/*
 * Pin /proc/sys/kernel/random/boot_id back to the value the device booted with.
 *
 * This is the repair for the one piece of collateral that stops the device
 * being usable afterwards, and the chain is longer than it looks.
 *
 * core612's 64-bit read is a write to a known kernel global followed by reading
 * that global back out through proc, and the global it borrows is the boot_id
 * buffer -- that is how the value crosses into userspace at all. Nothing puts
 * it back, and worse, the writes do not stop when the run does: read boot_id
 * after a run and it is not a UUID but a kernel pointer, and a different one
 * over time --
 *
 *     0080b302-80ff-ffff-90a9-520280ffffff
 *     40963516-80ff-ffff-90a9-520280ffffff
 *
 * -- the low half moving while the high half stays at the scratch address.
 *
 * Android names the ashmem character device after the boot id: init creates
 * /dev/ashmem<boot_id> at boot, and libcutils recomputes that path in every
 * process that needs it, because get_ashmem_device_path() reads the file each
 * time. Once the file stops matching, every process started afterwards looks
 * for a node that was never created:
 *
 *     E ashmem : Unable to open ashmem device: No such file or directory
 *
 * That lands where it hurts. bindApplication hands the application a
 * SharedMemory over binder; SharedMemory's constructor asks libcutils for the
 * region size; libcutils cannot validate the descriptor without the device, and
 * the transaction throws:
 *
 *     java.lang.IllegalArgumentException: FileDescriptor is not a valid ashmem fd
 *       at android.os.SharedMemory.<init>
 *       at android.app.IApplicationThread$Stub.onTransact
 *
 * So the Application object is never built and the activity launch behind it
 * dies on it with a NullPointerException in ConfigurationController. *Every*
 * application started after a run does this. The ones already resident are
 * fine, which is why `am start -W` on Settings answers `Status: ok` while the
 * device is, from the user's side, broken -- and why this went unnoticed.
 *
 * The value the device booted with is not lost: init spelled it into the device
 * node's own name, so it can be read back off /dev. Writing it into a file and
 * bind-mounting that over the proc entry makes every later reader see it again,
 * which is what the node is named after. Measured on warhol: 0 of 7 launchable
 * third-party applications survive a launch before this, 6 of 7 after, against
 * a clean-boot baseline of 7.
 *
 * The alternatives do not hold. Restoring the buffer itself is not available --
 * the write primitive only places real kernel pointers -- and hard-linking the
 * node under each new name loses the race: 484 links in, applications were
 * still dying, because the value moves at process-creation time, which is
 * exactly when the application reads it.
 */
#define BOOT_ID_PATH "/proc/sys/kernel/random/boot_id"
#define BOOT_ID_PINNED "/dev/.rmd_boot_id"
#define ASHMEM_PREFIX "ashmem"
#define BOOT_ID_LEN 36U

static int read_first_line(const char *path, char *out, size_t size) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }
  ssize_t got = read(fd, out, size - 1);
  close(fd);
  if (got <= 0) {
    return 0;
  }
  out[got] = '\0';
  char *newline = strchr(out, '\n');
  if (newline) {
    *newline = '\0';
  }
  return 1;
}

/* The boot id init actually used, read back off the name of the node it made:
 * "ashmem" followed by a 36-character UUID, on a character device. */
static int find_booted_boot_id(char *out, size_t size) {
  DIR *dev = opendir("/dev");
  if (!dev) {
    return 0;
  }
  int found = 0;
  struct dirent *entry;
  while (!found && (entry = readdir(dev)) != NULL) {
    if (strncmp(entry->d_name, ASHMEM_PREFIX, sizeof(ASHMEM_PREFIX) - 1) != 0 ||
        strlen(entry->d_name) != sizeof(ASHMEM_PREFIX) - 1 + BOOT_ID_LEN) {
      continue;
    }
    char path[96];
    struct stat st;
    snprintf(path, sizeof(path), "/dev/%s", entry->d_name);
    if (stat(path, &st) == 0 && S_ISCHR(st.st_mode)) {
      snprintf(out, size, "%s", entry->d_name + sizeof(ASHMEM_PREFIX) - 1);
      found = 1;
    }
  }
  closedir(dev);
  return found;
}

static void pin_boot_id(void) {
  char booted[BOOT_ID_LEN + 1];
  char current[64];
  if (!find_booted_boot_id(booted, sizeof(booted)) ||
      !read_first_line(BOOT_ID_PATH, current, sizeof(current))) {
    return;
  }
  if (strcmp(booted, current) == 0) {
    /* Either the oracle has not run yet or this is a second install: the file
     * already says what the device node is named after, so there is nothing to
     * pin and nothing to stack a second mount onto. */
    return;
  }

  /* The label is copied rather than left to a type transition, because the
   * readers are applications and this has to keep working once ksud puts
   * enforcing back. */
  char context[128];
  ssize_t context_len =
      getxattr(BOOT_ID_PATH, "security.selinux", context, sizeof(context));

  int fd = open(BOOT_ID_PINNED, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0444);
  if (fd < 0) {
    return;
  }
  char line[BOOT_ID_LEN + 2];
  int len = snprintf(line, sizeof(line), "%s\n", booted);
  int written = len > 0 && write(fd, line, (size_t)len) == (ssize_t)len;
  close(fd);
  if (!written) {
    unlink(BOOT_ID_PINNED);
    return;
  }
  chmod(BOOT_ID_PINNED, 0444);
  if (context_len > 0) {
    setxattr(BOOT_ID_PINNED, "security.selinux", context, (size_t)context_len,
             0);
  }
  if (mount(BOOT_ID_PINNED, BOOT_ID_PATH, NULL, MS_BIND, NULL) != 0) {
    unlink(BOOT_ID_PINNED);
  }
}

static int daemon_main(void) {
  signal(SIGPIPE, SIG_IGN);
  set_root_env();
  pin_boot_id();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 1;
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  unlink(BOOTSTRAP_SOCK_PATH);
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", BOOTSTRAP_SOCK_PATH);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0 ||
      listen(fd, 16) != 0) {
    close(fd);
    return 1;
  }
  chmod(BOOTSTRAP_SOCK_PATH, 0666);

  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0 && errno == EINTR) {
      continue;
    }
    if (conn < 0) {
      sleep(1);
      continue;
    }

    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      serve_one(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
  }
}

/*
 * The uid to serve, as a word rather than as a second argument.
 *
 * When the payload cannot fork this helper itself -- an application's process
 * carries Android's seccomp filter and the helper would inherit it -- it has
 * init exec the helper instead, by overwriting an init service's argv strings
 * in place. In place means the length cannot change, so a uid cannot be
 * appended as a separate word: it has to fit inside the argument that is
 * already there. `--umh=<uid>` padded out with spaces is what fits, so the
 * padding is trimmed here rather than rejected.
 */
static int umh_serve(const char *uid_text) {
  if (geteuid() != 0) {
    return 126;
  }
  char *end = NULL;
  errno = 0;
  unsigned long parsed_uid = strtoul(uid_text, &end, 10);
  if (errno || end == uid_text || parsed_uid == 0 || parsed_uid > UINT32_MAX) {
    return 123;
  }
  while (*end == ' ') {
    end++;
  }
  if (*end) {
    return 123;
  }
  allowed_client_uid = (uid_t)parsed_uid;
  /*
   * Only call these if they would change something.
   *
   * Both routes arrive here already at 0 across the board -- core66's is
   * exec'd by the kernel, core612's has just had init_cred installed over its
   * own -- so on the normal path these are no-ops. They were belt and braces
   * in front of the check below, which is the part that matters.
   *
   * They are not free, though. The application's payload runs inside an app
   * process, and an app carries Android's seccomp filter, which this helper
   * inherits across fork and exec and which no amount of uid 0 removes.
   * setresgid is not on the app allowlist: it is arm64 syscall 149, and
   * calling it killed the helper with SIGSYS the moment the app route first
   * got far enough to exec it --
   *
   *     Fatal signal 31 (SIGSYS), code 1 (SYS_SECCOMP), syscall 149
   *     seccomp prevented call to disallowed arm64 system call 149
   *
   * which the payload saw only as `su install helper exited early status=31`.
   * The adb route never hit it because a shell process carries no such filter.
   */
  if ((getgid() != 0 || getegid() != 0) && setresgid(0, 0, 0) != 0) {
    return 125;
  }
  if ((getuid() != 0 || geteuid() != 0) && setresuid(0, 0, 0) != 0) {
    return 125;
  }
  if (getuid() != 0 || geteuid() != 0 || getgid() != 0 || getegid() != 0) {
    return 125;
  }
  return daemon_main();
}

static int umh_main(int argc, char **argv) {
  if (argc != 3) {
    return 124;
  }
  return umh_serve(argv[2]);
}

static int payload_runner_main(int argc, char **argv) {
  if (argc != 5) {
    return 2;
  }

  if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() == 1) {
    return errno ? errno : ESRCH;
  }

  int log_fd = open(argv[4], O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (log_fd < 0 || dup2(log_fd, STDOUT_FILENO) < 0 ||
      dup2(log_fd, STDERR_FILENO) < 0) {
    return errno ? errno : EIO;
  }
  if (log_fd > STDERR_FILENO) {
    close(log_fd);
  }

  if (setenv("CVE43499_ROOT_HELPER", argv[3], 1) != 0) {
    return errno;
  }
  dprintf(STDERR_FILENO, "[app] loading verified payload=%s\n", argv[2]);
  void *handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
  if (!handle) {
    dprintf(STDERR_FILENO, "[app] dlopen failed: %s\n", dlerror());
    return ENOEXEC;
  }
  dprintf(STDERR_FILENO, "[app] payload constructor returned\n");
  return 0;
}

int main(int argc, char **argv) {
  signal(SIGPIPE, SIG_IGN);
  if (argc >= 2 && strcmp(argv[1], "--run-payload") == 0) {
    return payload_runner_main(argc, argv);
  }
  if (argc >= 2 && strcmp(argv[1], "--daemon") == 0) {
    return daemon_main();
  }
  if (argc >= 2 && strcmp(argv[1], "--umh") == 0) {
    return umh_main(argc, argv);
  }
  if (argc >= 2 && strncmp(argv[1], "--umh=", 6) == 0) {
    return umh_serve(argv[1] + 6);
  }
  return client_main(argc, argv);
}
