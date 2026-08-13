#define _GNU_SOURCE

#include "su_daemon.h"

#include <stdint.h>
#include <string.h>

/*
 * One target-independent entry point, two explicit protocols.
 *
 * The historical protocol remains the default and is byte-for-byte compatible
 * with existing callers:
 *
 *   su --late-load <kmi> <package> [allow-shell] [modules]
 *
 * A caller which supplies run-id=<32-lowercase-hex> opts into the sealed
 * completion protocol used by targets whose KernelSU patch set publishes an
 * authenticated post-load receipt.  Selection depends on an explicit protocol
 * word, never on manufacturer, model, KMI, package name, or device ID.
 */
int su_run_late_load_legacy(struct su_request *request, int conn);
int su_run_late_load_sealed(struct su_request *request, int conn);
void su_late_load_report_legacy(int status, int fd);
void su_late_load_report_sealed(int status, int fd);

static int argv_requests_sealed_protocol(uint32_t argc, char *const *argv) {
  static const char prefix[] = "run-id=";
  if (!argv) {
    return 0;
  }
  for (uint32_t i = 4; i < argc; i++) {
    if (strncmp(argv[i], prefix, sizeof(prefix) - 1) == 0) {
      return 1;
    }
  }
  return 0;
}

int su_run_late_load(struct su_request *request, int conn) {
  int sealed = request && argv_requests_sealed_protocol(
                              request->header.argc, request->argv);
  return sealed ? su_run_late_load_sealed(request, conn)
                : su_run_late_load_legacy(request, conn);
}

void su_late_load_report(int status, int fd, uint32_t argc,
                         char *const *argv) {
  if (argv_requests_sealed_protocol(argc, argv)) {
    su_late_load_report_sealed(status, fd);
  } else {
    su_late_load_report_legacy(status, fd);
  }
}
