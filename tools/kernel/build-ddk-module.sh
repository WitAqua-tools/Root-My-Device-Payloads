#!/usr/bin/env bash
# Build KernelSU as an external module inside a DDK image, against the headers
# that image ships for its KMI. Runs inside the container.
#
#   $1  path to the KernelSU checkout
#
# From the environment:
#   KERNEL_RELEASE        the exact UTS release the module must claim
#   TARGET_CONFIG         extra CONFIG_KSU_* options, space separated, may be empty
#   KSU_MANAGER_PACKAGE   the package the module will accept as its manager
#   KSU_EXPECTED_SIZE     DER size of the certificate it will accept
#   KSU_EXPECTED_HASH     sha256 of that certificate
#
# This is a file and not a `bash -c` body in the workflow for the reason the
# other two are: a multi-line shell body inside a single-quoted `bash -c`
# inside a YAML block is three levels of quoting. It has now broken three
# times, every time from an apostrophe or a quote inside a *comment* closing
# the body early and handing the rest to the outer shell -- which then ran
# `make` at the repository root and compiled the payload instead.
set -eu

kernelsu=$1

# Without this the module records no KSU_GIT_VERSION, because the bind-mounted
# tree is owned by a different uid than the container.
git config --global --add safe.directory "$kernelsu"

# The DDK ships its own release string and the targets set
# CONFIG_MODULE_FORCE_LOAD=n, so the module has to be built claiming the exact
# release of the kernel it will be loaded into. For a build whose kernelRelease
# is already the image default this is a no-op, which is how the S25U module
# was originally produced.
old=$(cat "$KDIR/include/config/kernel.release")
echo "kernel release: $old -> $KERNEL_RELEASE"
sed -i "s|$old|$KERNEL_RELEASE|g" "$KDIR/include/generated/utsrelease.h"
printf '%s\n' "$KERNEL_RELEASE" > "$KDIR/include/config/kernel.release"

# ksud late-load resolves undefined symbols from /proc/kallsyms before
# init_module, which requires a zero-length __versions section. Leaving the DDK
# Module.symvers in place would make modpost emit CRCs for a kernel that is not
# the target.
: > "$KDIR/Module.symvers"

cd "$kernelsu/kernel"
make clean >/dev/null 2>&1 || true

# Kbuild takes all three as make variables, and environment variables are make
# variables, so being exported is all it takes. The certificate pair has
# defaults there -- the ones upstream signs with -- and setting it replaces
# them rather than adding a second slot, so the module accepts one manager and
# it is not the official one.
echo "manager: $KSU_MANAGER_PACKAGE $KSU_EXPECTED_SIZE $KSU_EXPECTED_HASH"

# env, not a bare prefix: the shell only recognises assignments written
# literally before expansion, so $TARGET_CONFIG would be run as a command
# instead of setting the options.
# shellcheck disable=SC2086
env CONFIG_KSU=m $TARGET_CONFIG KBUILD_MODPOST_WARN=1 CC=clang make -j"$(nproc)"
