API ?= 35
TARGET ?= pa3q-S938NKSUACZF1
OUTDIR ?= build/$(TARGET)

TARGET_HEADER := src/targets/$(TARGET)/target.h
TARGET_INCLUDE := targets/$(TARGET)/target.h
TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

PRELOAD := $(OUTDIR)/cve-2026-43499
APP_PRELOAD := $(OUTDIR)/cve-2026-43499-app.so
APP_RELEASE := $(OUTDIR)/cve-2026-43499-app.release.so
APP_RELEASE_SIZE := 104128
ROOT_HELPER := $(OUTDIR)/cve-2026-43499-root

PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

APP_PRELOAD_SRCS := \
  src/main.c \
  src/util.c \
  src/slide_app.c \
  src/fops.c \
  src/pipe.c \
  src/root.c \
  src/preload.c

# A profile that ships src/targets/<t>/target-core66.h is built from the 6.6
# core in src/core66/ instead of the Samsung-lineage sources above. That core is
# pmg110-root's, which roots the device it was measured on; what it does not
# carry is the usermodehelper route, so src/root.c stays this repository's --
# the kernel execs the app's helper as root and that helper is what serves -c
# and --late-load. install_android_root(int fd) is the whole seam between them.
CORE66_HEADER := src/targets/$(TARGET)/target-core66.h
CORE66 := $(wildcard $(CORE66_HEADER))
ifneq ($(CORE66),)
TARGET_HEADER := $(CORE66_HEADER)
TARGET_INCLUDE := ../targets/$(TARGET)/target-core66.h
CORE66_SRCS := \
  src/core66/main.c \
  src/core66/util.c \
  src/core66/slide.c \
  src/core66/fops.c \
  src/core66/pipe.c \
  src/root.c \
  src/preload.c
PRELOAD_SRCS := $(CORE66_SRCS)
APP_PRELOAD_SRCS := $(CORE66_SRCS)
CORE66_INCLUDE := -Isrc/core66
CORE66_DEPS := $(wildcard src/core66/*.h src/core66/kernelsnitch/*.h)
endif

COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  $(CORE66_INCLUDE) -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"'

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER)

release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(TARGET_HEADER) $(CORE66_DEPS) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(ROOT_HELPER): src/su_daemon.c | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra $< -ldl -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) $(CORE66_DEPS) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(APP_RELEASE): $(APP_PRELOAD_SRCS) $(TARGET_HEADER) $(CORE66_DEPS) src/offset.h src/common.h src/kernelsnitch/*.h | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC -Oz -g0 \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  $(CORE66_INCLUDE) -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' \
	  $(APP_PRELOAD_SRCS) -shared -pthread \
	  -Wl,--gc-sections -Wl,--icf=all -s -o $@
	@test $$(stat -c %s $@) -le $(APP_RELEASE_SIZE)
	truncate -s $(APP_RELEASE_SIZE) $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "APP_PRELOAD=$(APP_PRELOAD)"
	@echo "APP_RELEASE=$(APP_RELEASE)"
	@echo "ROOT_HELPER=$(ROOT_HELPER)"

clean:
	rm -rf $(OUTDIR)
