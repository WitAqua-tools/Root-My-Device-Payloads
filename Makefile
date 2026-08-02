API ?= 35

# A target is identified by the path it lives at, so TARGET doubles as the
# device/region/kernel key used everywhere else: src/targets.json derives the
# same path from its device, region and kernelRelease fields.
TARGET ?= pmg110/cn/6.6.118-android15-8-g93e223c276e7-abogki500782043-4k
PAYLOAD ?= CVE-2026-43499

# Which exploit core the target's kernel needs. The attack chain is fixed to a
# GKI branch rather than to a SoC, so a target on a different kernel series
# needs a different core, not a different set of offsets:
#
#   core66   android15-6.6, from pmg110-root
#   core612  android16-6.12, from warhol-root (upstream popsicle plus its MTE fix)
#   core510  5.10 (Meta's own kernel, not a GKI branch), from IonStackQuest3
#
# It is declared per target in src/targets.json and CI passes it down, so the
# default here only matters for a hand-typed build.
CORE ?= core66

# core510 stamps its fake waiter into a compat syscall's stack frame, so it
# execs a 32-bit stage to do it. API32 is that stage's minSdk, not this
# repository's: it is what upstream builds it against.
API32 ?= 28

TARGET_DIR := src/targets/$(TARGET)
# One header per core, because a core reads offsets the other has never heard
# of; naming it after the core keeps both in the same target directory.
TARGET_HEADER_NAME ?= target-$(CORE).h
TARGET_HEADER := $(TARGET_DIR)/$(TARGET_HEADER_NAME)
TARGET_INCLUDE := targets/$(TARGET)/$(TARGET_HEADER_NAME)
PAYLOAD_DIR := src/payloads/$(PAYLOAD)
CORE_DIR := $(PAYLOAD_DIR)/$(CORE)
HELPER_DIR := src/payloads/su_daemon

# The bootstrap helper depends on neither the target nor the core -- one binary
# serves every target and the application ships that one copy in its APK. The
# two things that did know better than that are separated out: late_load.c is
# all it knows about KernelSU, and hold_refs.c is core66's kernel-page
# reference holder, unreachable on any other core.
HELPER_SRCS := \
  $(HELPER_DIR)/su_daemon.c \
  $(HELPER_DIR)/late_load.c \
  $(HELPER_DIR)/hold_refs.c

# '/' is legal in TARGET but not in a directory name that has to stay flat.
OUTDIR ?= build/$(subst /,_,$(TARGET))

TARGET_CC := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android$(API)-clang
TARGET_CC32 := $(ANDROID_NDK_HOME)/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi$(API32)-clang

ifeq ($(wildcard $(TARGET_CC)),)
$(error set ANDROID_NDK_HOME to an Android NDK containing $(TARGET_CC))
endif

ifeq ($(wildcard $(TARGET_HEADER)),)
$(error no $(TARGET_HEADER_NAME) at $(TARGET_DIR) -- TARGET is <device>/<region>/<kernel release>)
endif

ifeq ($(wildcard $(CORE_DIR)),)
$(error no $(CORE) core at $(PAYLOAD_DIR) -- CORE names a directory under the payload)
endif

# Artifact names follow the payload, so a second payload does not collide with
# this one in build/ or in the flat release-asset namespace.
PAYLOAD_SLUG := $(shell echo '$(PAYLOAD)' | tr 'A-Z' 'a-z')

PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)
APP_PRELOAD := $(OUTDIR)/$(PAYLOAD_SLUG)-app.so
APP_RELEASE := $(OUTDIR)/$(PAYLOAD_SLUG)-app.release.so
APP_RELEASE_SIZE := 104128
ROOT_HELPER := $(OUTDIR)/$(PAYLOAD_SLUG)-root

# core510 is the one core that needs a second binary on the device before it
# can reach root: it stamps its fake waiter into a compat syscall's stack
# frame, so that part runs in a 32-bit process it execs. Upstream carries it as
# an .incbin blob inside its own app glue; here it is a separate artifact,
# because the application payload is a fixed-size release object and a static
# armv7 binary does not fit in it. core510/root.c is the seam that gets it to
# the path api.c execs.
EXP32_CORES := core510
EXP32 := $(OUTDIR)/$(PAYLOAD_SLUG)-exp32
EXP32_SRCS := $(CORE_DIR)/exp32/main.c $(CORE_DIR)/exp32/stack.c
EXP32_ARTIFACT := $(if $(filter $(CORE),$(EXP32_CORES)),$(EXP32))

ifneq ($(EXP32_ARTIFACT),)
ifeq ($(wildcard $(TARGET_CC32)),)
$(error $(CORE) needs a 32-bit stage; set ANDROID_NDK_HOME to an NDK containing $(TARGET_CC32))
endif
endif

# Every core is an imported tree kept as close to the port it came from as it
# can be: core612 carries one delta against warhol-root, core66 two against
# pmg110-root and core510 three against IonStackQuest3, all listed in the
# README. The one file under $(CORE_DIR) that is *not* imported is root.c,
# which is this repository's own and is named so that a core's code stays in
# that core's directory:
#
#   <core>/root.c  how that core gets the bootstrap helper resident as root.
#                  core66 queues a usermodehelper work item from an
#                  unprivileged process (install_android_root); core612 is
#                  already root and execs it (install_embedded_su); core510
#                  roots a forked child that has had its seccomp filter cleared
#                  as well, and that child execs it. One is linked per build,
#                  and it is listed apart from CORE_SRCS below so the build
#                  still says which side of the import each file is on.
#
# No port has a file by that name -- their own app glue is preload.c,
# su_daemon.c and an .incbin blob, none of which was copied -- so re-importing
# a core is still "replace everything here but root.c".
#
# What is this repository's own and shared by every core:
#
#   mte.c          whether this boot's kernel tags heap pointers. Core-neutral
#                  and linked into every build; core612 is the one that reads
#                  it, because warhol's answer follows the flashed preloader
#                  rather than the firmware its target header came from.
#   preload.c      the retry supervisor, shared by all.
#
# payload.h is the seam between them.
CORE_SRCS := \
  $(CORE_DIR)/main.c \
  $(CORE_DIR)/util.c \
  $(CORE_DIR)/slide.c \
  $(CORE_DIR)/fops.c \
  $(CORE_DIR)/pipe.c

# core510 came from a tree that splits the chain across more files, and one of
# them is its own root.c: there the cred and seccomp arithmetic is the
# exploit's final stage rather than app glue, so the import keeps it
# byte-identical as root_stage.c and core510/root.c is only the seam. Listed
# here rather than merged into CORE_SRCS so each file still says which side of
# the import it is on.
CORE_SRCS += $(if $(filter $(CORE),core510),\
  $(CORE_DIR)/api.c \
  $(CORE_DIR)/config.c \
  $(CORE_DIR)/q3slide.c \
  $(CORE_DIR)/root_stage.c)

PRELOAD_SRCS := \
  $(CORE_SRCS) \
  $(CORE_DIR)/root.c \
  $(PAYLOAD_DIR)/mte.c \
  $(PAYLOAD_DIR)/preload.c

APP_PRELOAD_SRCS := $(PRELOAD_SRCS)
PAYLOAD_DEPS := $(TARGET_HEADER) $(PAYLOAD_DIR)/payload.h \
  $(wildcard $(CORE_DIR)/*.h $(CORE_DIR)/kernelsnitch/*.h)

# -Isrc resolves the "targets/<...>/<header>" form that core66/offset.h
# includes -- it was "../targets/..." while the core sat directly under src/,
# which no longer resolves now that it is a level deeper. -I$(CORE_DIR) covers
# the core's own headers, and -I$(TARGET_DIR) any header
# the target header names as a sibling. That last one is why a target header
# does not have to spell out its own path: such an include expands inside a core
# .c file and would otherwise be resolved against the core directory.
# -I$(PAYLOAD_DIR) is for payload.h, which the glue and the supervisor share and
# which no core knows about.

# core66's offset.h names the target header through TARGET_HEADER; core612 came
# from popsicle, whose offset.h names it through TARGET_CONFIG_H. Defining both
# to the same include is what lets each core stay exactly as it was imported --
# editing one to agree with the other is how a foreign kernel's constants got
# into a core last time.
TARGET_HEADER_DEFINES := \
  -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"'

# EXTRA_CFLAGS is for the constants a target header deliberately leaves
# overridable -- quest3's P0_KERNEL_PHYS_LOAD is one, and it is the only way to
# try its alternates without editing a generated block.
COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -I$(CORE_DIR) -I$(PAYLOAD_DIR) -I$(TARGET_DIR) -Isrc $(TARGET_HEADER_DEFINES) \
  $(EXTRA_CFLAGS)

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER) $(EXP32_ARTIFACT)

release: $(APP_RELEASE) $(EXP32_ARTIFACT)

$(OUTDIR):
	mkdir -p $@

# armeabi-v7a and static. It has to stay 32-bit: the stack geometry the stamp
# is written at is the compat one, and a 64-bit build of the same source would
# land somewhere else entirely. -fPIE -pie is upstream's spelling and is kept
# so the two build the same binary; -static wins over it and what comes out is
# an ELF32 ARM EXEC, which is what upstream ships too. Built with the core's
# own flags rather than COMMON_CFLAGS -- it shares no header with the payload
# but the kernelsnitch helpers, and it never sees the target header.
#
# EXP32_CFLAGS is a lever of its own rather than a share of EXTRA_CFLAGS,
# because the one flag anybody needs here must NOT reach the 64-bit payload.
# The run that reached root on quest3 was a -DDEBUG build of THIS stage only
# (verified by hash: the stage's pr_debug sites are what put "consumer:
# calling sched_setattr" in that run's log) against a payload built without
# it. -DDEBUG turns on six one-shot pr_debug lines in the 32-bit stage, one
# of which sits immediately before the syscall that triggers the prio-chain
# walk -- with IONSTACK_LOG pointing at an O_SYNC file, that line is a
# synchronous write inside the race window, so it is not obviously
# decoration. Reproduce that build with EXP32_CFLAGS=-DDEBUG.
EXP32_CFLAGS ?=
$(EXP32): $(EXP32_SRCS) $(wildcard $(CORE_DIR)/kernelsnitch/*.h) | $(OUTDIR)
	$(TARGET_CC32) -O2 -g0 -Wall -Wno-unused-parameter -Wno-unused-function \
	  -I$(CORE_DIR) $(EXP32_CFLAGS) -fPIE -pie -static $(EXP32_SRCS) -o $@

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
	  -I$(CORE_DIR) -I$(PAYLOAD_DIR) -I$(TARGET_DIR) -Isrc \
	  $(TARGET_HEADER_DEFINES) \
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
