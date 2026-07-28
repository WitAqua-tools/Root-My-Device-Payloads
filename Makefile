API ?= 35

# A target is identified by the path it lives at, so TARGET doubles as the
# device/region/kernel key used everywhere else: src/targets.json derives the
# same path from its device, region and kernelRelease fields.
TARGET ?= pmg110/cn/6.6.118-android15-8-g93e223c276e7-abogki500782043-4k
PAYLOAD ?= CVE-2026-43499

TARGET_DIR := src/targets/$(TARGET)
TARGET_HEADER_NAME ?= target-core66.h
TARGET_HEADER := $(TARGET_DIR)/$(TARGET_HEADER_NAME)
TARGET_INCLUDE := targets/$(TARGET)/$(TARGET_HEADER_NAME)
PAYLOAD_DIR := src/payloads/$(PAYLOAD)
CORE_DIR := $(PAYLOAD_DIR)/core66
HELPER_DIR := src/payloads/su_daemon

# The bootstrap helper depends on no target -- one binary serves every one of
# them and the application ships that one copy in its APK. The two things that
# did know better than that are separated out: late_load.c is all it knows
# about KernelSU, and hold_refs.c is the kernel-page reference holder that
# exists for the exploit's sake alone.
HELPER_SRCS := \
  $(HELPER_DIR)/su_daemon.c \
  $(HELPER_DIR)/late_load.c \
  $(HELPER_DIR)/hold_refs.c

# '/' is legal in TARGET but not in a directory name that has to stay flat.
OUTDIR ?= build/$(subst /,_,$(TARGET))

TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error no $(TARGET_HEADER_NAME) at $(TARGET_DIR) -- TARGET is <device>/<region>/<kernel release>)
endif

# Artifact names follow the payload, so a second payload does not collide with
# this one in build/ or in the flat release-asset namespace.
PAYLOAD_SLUG := $(shell echo '$(PAYLOAD)' | tr 'A-Z' 'a-z')

PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)
APP_PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)-app.so
APP_RELEASE := $(OUTDIR)/$(PAYLOAD_SLUG)-app.release.so
APP_RELEASE_SIZE := 104128
ROOT_HELPER := $(OUTDIR)/$(PAYLOAD_SLUG)-root

# The exploit core is core66/, which is pmg110-root's -- the tree that roots
# this device. root.c is this repository's own and stays: it is the
# usermodehelper route that gets the app's helper exec'd as root, which is what
# makes -c and --late-load available. install_android_root(int fd) is the seam.
PRELOAD_SRCS := \
  $(CORE_DIR)/main.c \
  $(CORE_DIR)/util.c \
  $(CORE_DIR)/slide.c \
  $(CORE_DIR)/fops.c \
  $(CORE_DIR)/pipe.c \
  $(PAYLOAD_DIR)/root.c \
  $(PAYLOAD_DIR)/preload.c

APP_PRELOAD_SRCS := $(PRELOAD_SRCS)
PAYLOAD_DEPS := $(TARGET_HEADER) \
  $(wildcard $(CORE_DIR)/*.h $(CORE_DIR)/kernelsnitch/*.h)

# -Isrc resolves the "targets/<...>/<header>" form that core66/offset.h
# includes -- it was "../targets/..." while the core sat directly under src/,
# which no longer resolves now that it is a level deeper. -I$(CORE_DIR) covers
# the core's own headers, and -I$(TARGET_DIR) any header
# the target header names as a sibling. That last one is why a target header
# does not have to spell out its own path: such an include expands inside a core
# .c file and would otherwise be resolved against the core directory.
COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -I$(CORE_DIR) -I$(TARGET_DIR) -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"'

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER)

release: $(APP_RELEASE)

$(OUTDIR):
	mkdir -p $@

$(PRELOAD): $(PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -fPIC $(COMMON_CFLAGS) $(PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(ROOT_HELPER): $(HELPER_SRCS) $(HELPER_DIR)/su_daemon.h | $(OUTDIR)
	$(TARGET_CC) -fPIE -pie -O2 -g0 -Wall -Wextra -I$(HELPER_DIR) \
	  $(HELPER_SRCS) -ldl -o $@

$(APP_PRELOAD): $(APP_PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC $(COMMON_CFLAGS) $(APP_PRELOAD_SRCS) \
	  -shared -pthread -o $@

$(APP_RELEASE): $(APP_PRELOAD_SRCS) $(PAYLOAD_DEPS) | $(OUTDIR)
	$(TARGET_CC) -DAPP_PAYLOAD=1 -fPIC -Oz -g0 \
	  -fno-unwind-tables -fno-asynchronous-unwind-tables \
	  -ffunction-sections -fdata-sections \
	  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
	  -I$(CORE_DIR) -I$(TARGET_DIR) -Isrc -DTARGET_HEADER='"$(TARGET_INCLUDE)"' \
	  $(APP_PRELOAD_SRCS) -shared -pthread \
	  -Wl,--gc-sections -Wl,--icf=all -s -o $@
	@test $$(stat -c %s $@) -le $(APP_RELEASE_SIZE)
	truncate -s $(APP_RELEASE_SIZE) $@

info:
	@echo "TARGET=$(TARGET)"
	@echo "PAYLOAD=$(PAYLOAD)"
	@echo "TARGET_DIR=$(TARGET_DIR)"
	@echo "TARGET_HEADER=$(TARGET_HEADER)"
	@echo "TARGET_CC=$(TARGET_CC)"
	@echo "PRELOAD=$(PRELOAD)"
	@echo "APP_PRELOAD=$(APP_PRELOAD)"
	@echo "APP_RELEASE=$(APP_RELEASE)"
	@echo "ROOT_HELPER=$(ROOT_HELPER)"

clean:
	rm -rf $(OUTDIR)
