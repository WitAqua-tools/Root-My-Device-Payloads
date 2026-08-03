#!/usr/bin/env bash
# Build KernelSU as an external module against a prepared kernel tree. Runs
# inside the toolchain container.
#
#   $1  path to the kernel tree
#   $2  path to the KernelSU checkout
#   $3  clang directory name inside /opt/ddk/clang
#   $4  the release the module must claim
#
# KSU_EXPECTED_SIZE2 / KSU_EXPECTED_HASH2 are read from the environment when
# set; Kbuild errors out if only one half is, so an empty pair is unset rather
# than passed through empty.
set -eu

tree=$1
kernelsu=$2
clang=$3
release=$4
export PATH="/opt/ddk/clang/$clang/bin:$PATH"

git config --global --add safe.directory "$kernelsu"

# The published tree is not always the commit the device booted -- Quest 3's
# g55be3759aea4 is internal -- so the release string is forced, the same way
# the DDK path in .github/actions/build-kernelsu does it. With a zero-length
# __versions section same_magic() skips the release half of vermagic anyway,
# but a module that says the wrong thing about itself is not worth shipping.
old=$(cat "$tree/include/config/kernel.release")
echo "kernel release: $old -> $release"
sed -i "s|$old|$release|g" "$tree/include/generated/utsrelease.h"
printf '%s\n' "$release" > "$tree/include/config/kernel.release"

# ksud resolves the undefined symbols from /proc/kallsyms before init_module,
# which requires a zero-length __versions section. Leaving the tree's
# Module.symvers in place would make modpost emit CRCs instead.
: > "$tree/Module.symvers"

if [ -z "${KSU_EXPECTED_SIZE2:-}" ]; then
  unset KSU_EXPECTED_SIZE2 KSU_EXPECTED_HASH2 || true
else
  echo "manager signature slot 2: $KSU_EXPECTED_SIZE2 ${KSU_EXPECTED_HASH2:-}"
fi

cd "$kernelsu/kernel"
make -C "$tree" M="$PWD" src="$PWD" \
  ARCH=arm64 CC=clang HOSTCC=clang LD=ld.lld AR=llvm-ar NM=llvm-nm \
  OBJCOPY=llvm-objcopy OBJDUMP=llvm-objdump STRIP=llvm-strip \
  READELF=llvm-readelf HOSTLD=ld.lld HOSTAR=llvm-ar \
  CONFIG_KSU=m KBUILD_MODPOST_WARN=1 modules -j"$(nproc)"
