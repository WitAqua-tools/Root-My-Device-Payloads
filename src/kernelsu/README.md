# KernelSU late-load builds

| Path | Contents |
| --- | --- |
| `KernelSU/` | upstream submodule, pinned to `v3.2.5` (`b0bc817b4e966aa6aa830834eaf6ef765d821d40`) |
| `patches/` | applied to every build, before any the target adds |
| `tools/` | module auditing against a recovered target kernel |

Nothing here is committed as a binary. Each target declares the build it pairs
with in its own `kernelsu.json`, and CI produces `ksud-<id>` and
`kernelsu-<id>.ko` from this submodule as release assets. The pair is always
published together, because `ksud` embeds the module it loads.

## Why the patch is applied to every build

[`patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch`](patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch)
carries two independent halves.

The **`ksud` half is required by every target**, Samsung or not. Upstream
late-load could not write a new `/data/adb/ksud` after the module changed the
loader's security context — the destination stayed a zero-byte file. The patch
stages the daemon at `/data/local/tmp/.ksud-stage`, renames it onto the same
`/data` filesystem before loading the module, and finishes labels and assets
once the module is active. The bootstrap helper in
[`src/payloads/su_daemon`](../payloads/su_daemon) drives exactly that sequence,
so removing this patch breaks installation on any device.

The **kernel half is compiled out unless a target asks for it**, through the
`config` array in its `kernelsu.json`. It exists because a generic build panics
on Samsung firmware: an inline `put_cred()` writes directly to a KDP-protected
credential refcount, RKP rejects the write to an unused syscall-table slot while
the generic code still treats the dispatcher as installed, and DEFEX keeps its
own task credential tuple that a KernelSU UID transition leaves unsynchronised.
Under `CONFIG_KSU_SAMSUNG_{KDP,RKP,DEFEX}` the patch resolves
`kdp_usecount_dec_and_test()` and `kdp_assign_pgd()` from the running kernel,
installs credentials through `prepare_ro_creds()`, synchronises the DEFEX
record, records a syscall-table hook only if the RKP-protected write succeeds,
and otherwise falls back to kretprobe/kprobe sucompat.

No target in this repository currently sets those options.

## How a build is produced

CI runs this from each target's `kernelsu.json`; the steps are here for
reproducing one by hand.

```sh
git submodule update --init src/kernelsu/KernelSU
git -C src/kernelsu/KernelSU apply \
  src/kernelsu/patches/KernelSU-v3.2.5-samsung-kdp-rkp-defex.patch
```

Build the module inside the KMI's DDK image, overwriting the image's own
release strings with the target's exact `kernelRelease` and emptying its
`Module.symvers` first:

```sh
docker run --rm -v "$PWD:/workspace" \
  -w /workspace/src/kernelsu/KernelSU/kernel <ddkImage> bash -eu -c '
    old=$(cat "$KDIR/include/config/kernel.release")
    sed -i "s|$old|<kernelRelease>|g" "$KDIR/include/generated/utsrelease.h"
    printf "%s\n" "<kernelRelease>" > "$KDIR/include/config/kernel.release"
    : > "$KDIR/Module.symvers"
    make clean
    env CONFIG_KSU=m <config> KBUILD_MODPOST_WARN=1 CC=clang make -j"$(nproc)"
  '
```

Both edits are load-time contracts, and CI asserts them:

```text
vermagic:        <kernelRelease> SMP preempt mod_unload modversions aarch64
__versions size: 0
```

The targets set `CONFIG_MODULE_FORCE_LOAD=n`, so a module whose `vermagic` does
not match is refused. `__versions` must be empty because `ksud late-load` uses
KernelSU's manual-relocation loader: it replaces undefined ELF symbols with
absolute `/proc/kallsyms` addresses before `init_module`, which
`kernel/check_symbol` requires a zero-length `__versions` section for. Importing
another kernel's `Module.symvers` breaks this.

Then strip debug sections only, place the module where `ksud` embeds it, and
build the daemon:

```sh
llvm-strip -d src/kernelsu/KernelSU/kernel/kernelsu.ko
cp src/kernelsu/KernelSU/kernel/kernelsu.ko \
  src/kernelsu/KernelSU/userspace/ksud/bin/aarch64/<kmi>_kernelsu.ko
cargo build --release --target aarch64-linux-android -p ksud \
  --manifest-path src/kernelsu/KernelSU/Cargo.toml
```

`ksud` picks its module by KMI at run time from the embedded
`<kmi>_kernelsu.ko` assets, so the name matters.

## The audit CI cannot run

Everything above is checkable from the module alone. Confirming that the module
will actually resolve against a specific device's kernel is not: it needs that
target's recovered `vmlinux` and symbol table, which are not in this repository.

```sh
src/kernelsu/KernelSU/kernel/check_symbol \
  src/kernelsu/KernelSU/kernel/kernelsu.ko <path to target vmlinux>

python3 src/kernelsu/tools/audit_module_against_target.py \
  src/kernelsu/KernelSU/kernel/kernelsu.ko \
  <target vmlinux> <target Module.symvers> --manual-relocation
```

The audit must report zero symbols missing from the target symbol table, zero
module version entries, and zero CRC mismatches.
[`tools/extract_target_symvers.py`](tools/extract_target_symvers.py) recovers
that symbol-version table from a reconstructed arm64 `vmlinux` when the target
does not ship one.

A build that passes CI is therefore **build-verified, not target-verified**.
Treat a new `kernelsu.json` as untested until this audit has been run by hand
and the device has booted.
