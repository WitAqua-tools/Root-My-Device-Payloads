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
# frame, so that part runs in a 32-bit process it execs. It is built as an
# artifact, the way the bootstrap helper is, so a shell run can push it -- and
# the same artifact is then .incbin'd back into the payload, because an
# application-launched run has nothing to push with. One build, two ways to
# arrive; core510/root.c is the seam that decides which one a run uses.
EXP32_CORES := core510
EXP32 := $(OUTDIR)/$(PAYLOAD_SLUG)-exp32
EXP32_SRCS := $(CORE_DIR)/exp32/main.c $(CORE_DIR)/exp32/stack.c
EXP32_ARTIFACT := $(if $(filter $(CORE),$(EXP32_CORES)),$(EXP32))
EXP32_BLOB_SRC := $(if $(EXP32_ARTIFACT),$(CORE_DIR)/exp32_blob.S)
EXP32_BLOB_DEFINE := $(if $(EXP32_ARTIFACT),-DEXP32_BLOB_FILE='"$(EXP32)"')

ifneq ($(EXP32_ARTIFACT),)
ifeq ($(wildcard $(TARGET_CC32)),)
$(error $(CORE) needs a 32-bit stage; set ANDROID_NDK_HOME to an NDK containing $(TARGET_CC32))
endif
endif

# Every core is an imported tree kept as close to the port it came from as it
# can be: core612 carries one delta against warhol-root, core66 three against
# pmg110-root and core510 three against IonStackQuest3, all listed in the
# README. What under $(CORE_DIR) is *not* imported is root.c -- and, for
# core510 alone, the exp32_blob.S that carries its 32-bit stage inside the
# payload. Both are this repository's own, and are named so that a core's code
# stays in that core's directory:
#
#   <core>/root.c  how that core gets the bootstrap helper resident as root.
#                  core66 and core61 queue a usermodehelper work item from an
#                  unprivileged process (install_android_root); core612 is
#                  already root and execs it (install_embedded_su -> the shared
#                  root_helper.c); core510 roots a forked child that has had
#                  its seccomp filter cleared as well, and that child execs it
#                  from an install_embedded_su of its own. One is linked per
#                  build, and it is listed apart from CORE_SRCS below so the
#                  build still says which side of the import each file is on.
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
#   root_helper.c  getting the helper resident from a context that is already
#                  root, init hijack included. Linked only into the cores whose
#                  glue calls it -- see ROOT_HELPER_CORES below.
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

# Which cores reach a root context of their own and so install the helper from
# user space. core61 does not: it has the kernel exec the helper through a
# usermodehelper work item and calls none of root_helper.c, so linking it there
# would carry an init hijack no run of that core can reach.
# core510 does not either: its root.c carries an install_embedded_su of its
# own, so linking the shared one would define the symbol twice.
ROOT_HELPER_CORES := core66 core612
ROOT_HELPER_SRCS := \
  $(if $(filter $(CORE),$(ROOT_HELPER_CORES)),$(PAYLOAD_DIR)/root_helper.c)

PRELOAD_SRCS := \
  $(CORE_SRCS) \
  $(CORE_DIR)/root.c \
  $(EXP32_BLOB_SRC) \
  $(ROOT_HELPER_SRCS) \
  $(PAYLOAD_DIR)/mte.c \
  $(PAYLOAD_DIR)/preload.c

APP_PRELOAD_SRCS := $(PRELOAD_SRCS)
# The blob source .incbin's the exp32 artifact, so the artifact is a
# prerequisite of every payload that carries it.
PAYLOAD_DEPS := $(TARGET_HEADER) $(PAYLOAD_DIR)/payload.h \
  $(wildcard $(CORE_DIR)/*.h $(CORE_DIR)/kernelsnitch/*.h) $(EXP32_ARTIFACT)

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
#
# TARGET_KERNEL_RELEASE is the last component of TARGET, which is the kernel
# release the target is stored under. core66 refuses to run on a kernel other
# than the one it was built for and needs the string to compare against; taking
# it from the path means it cannot disagree with where the target lives.
TARGET_HEADER_DEFINES := \
  -DTARGET_HEADER='"$(TARGET_INCLUDE)"' -DTARGET_CONFIG_H='"$(TARGET_INCLUDE)"' \
  -DTARGET_KERNEL_RELEASE='"$(notdir $(TARGET))"'

# EXTRA_CFLAGS is for the constants a target header deliberately leaves
# overridable -- quest3's P0_KERNEL_PHYS_LOAD is one, and it is the only way to
# try its alternates without editing a generated block.
COMMON_CFLAGS := \
  -O2 -g0 -Wall -Wextra \
  -Wno-unused-parameter -Wno-sign-compare \
  -I$(CORE_DIR) -I$(PAYLOAD_DIR) -I$(TARGET_DIR) -Isrc $(TARGET_HEADER_DEFINES) \
  $(EXP32_BLOB_DEFINE) $(EXTRA_CFLAGS)

.DEFAULT_GOAL := all

.PHONY: all clean info release

all: $(PRELOAD) $(APP_PRELOAD) $(ROOT_HELPER) $(EXP32_ARTIFACT)

release: $(APP_RELEASE) $(EXP32_ARTIFACT)

$(OUTDIR):
	mkdir -p $@

# armeabi-v7a, and a dynamically linked PIE. It has to stay 32-bit: the stack
# geometry the stamp is written at is the compat one, and a 64-bit build of the
# same source would land somewhere else entirely. Built with the core's own
# flags rather than COMMON_CFLAGS -- it shares no header with the payload but
# the kernelsnitch helpers, and it never sees the target header.
#
# DELTA against IonStackQuest3, which builds this -static: an
# application-launched run may not execve() a file it wrote itself, and its one
# remaining way to start this stage is to hand it to bionic's linker as a
# loader -- which can only load a dynamic PIE (core510/root.c has the policy
# read). Dropping -static is what makes that route exist, and it takes the
# stage from about 1.6MB to tens of kilobytes, which is also what lets the
# payload carry a copy at all. A shell run execs it directly either way. The
# static build is still one flag away (EXP32_CFLAGS=-static) for comparing
# against the run that first reached root on quest3, which was a static one.
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
# Makefile is a prerequisite here and nowhere else: this artifact's flags are
# the ones that get changed by hand, and a stale copy of it is now linked into
# the payload rather than only pushed, so "left over from the previous flags"
# would be a payload carrying a stage nobody asked for.
$(EXP32): $(EXP32_SRCS) $(wildcard $(CORE_DIR)/kernelsnitch/*.h) Makefile | $(OUTDIR)
	$(TARGET_CC32) -O2 -g0 -Wall -Wno-unused-parameter -Wno-unused-function \
	  -I$(CORE_DIR) $(EXP32_CFLAGS) -fPIE -pie $(EXP32_SRCS) -o $@

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
	  $(TARGET_HEADER_DEFINES) $(EXP32_BLOB_DEFINE) \
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
