#!/usr/bin/env bash
# Bring a vendor kernel tree to the point where an external module can be built
# against it. Runs inside the toolchain container.
#
#   $1  path to the kernel tree
#   $2  clang directory name inside /opt/ddk/clang
#
# Two different things are missing from a fresh tree and each comes from a
# different half of this:
#
#   scripts/module.lds        modules_prepare. Linking an external module needs
#                             it and a partial build never reaches it.
#   security/selinux/flask.h  a real build. modules_prepare does not generate
#                             it and the KernelSU SELinux part will not compile
#                             without it.
#
# The real build is expected to FAIL, on the vendor drivers and their
# tracepoint includes, after it has written flask.h. Nothing here needs vmlinux
# and Module.symvers is emptied later on purpose, so the caller checks for the
# two files rather than for an exit status.
set -eu

tree=$1
clang=$2
export PATH="/opt/ddk/clang/$clang/bin:$PATH"

tools="ARCH=arm64 CC=clang HOSTCC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm"
tools="$tools OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip"
tools="$tools READELF=llvm-readelf HOSTLD=ld.lld HOSTAR=llvm-ar"

cd "$tree"
# shellcheck disable=SC2086
make $tools olddefconfig
# shellcheck disable=SC2086
make $tools -j"$(nproc)" modules_prepare
# shellcheck disable=SC2086
make $tools -j"$(nproc)" Image modules || true
