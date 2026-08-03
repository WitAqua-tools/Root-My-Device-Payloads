# KernelSU late-load builds

| Path | Contents |
| --- | --- |
| `KernelSU/` | upstream submodule, pinned to `v3.2.5` (`b0bc817b4e966aa6aa830834eaf6ef765d821d40`) |
| `Root-My-Device-KSU/` | submodule holding the patches, in sets a build selects between |
| `tools/` | module auditing against a recovered target kernel |

The patches are a derivative work of KernelSU and carry its GPL terms, not this
repository's Apache-2.0 ones, so they live in
[Root-My-Device-KSU](https://github.com/Witaqua-tools/Root-My-Device-KSU) with
verbatim copies of both upstream licence files. Hunks under `kernel/` are
GPL-2.0 and those under `userspace/` are GPL-3.0. Clone with
`--recurse-submodules` or nothing will build.

Nothing here is committed as a binary. Each target declares the build it pairs
with in its own `kernelsu.json`, and CI produces `ksud-<id>` and
`kernelsu-<id>.ko` from this submodule as release assets. The pair is always
published together, because `ksud` embeds the module it loads.

## One manager, for every target

[`manager.json`](manager.json) is the whole of it. Which manager a device gets
is not a property of the device, so no `kernelsu.json` names one; a leftover
`manager`, `managerSignature` or `managerPackage` key in one fails validation
rather than being ignored.

It is not upstream's manager. Upstream's rewrites `/data/adb/ksud` with the copy
bundled in its own APK the first time it runs, which puts an unpatched daemon
back — measured on Quest 3, where opening it undid `common/0004` and the next
soft restart went back to leaving stale daemons behind, with nothing in any log
to say so. A soft restart is the only restart a late-loaded device has.

So every module here is built with that file's `package` as
`KSU_MANAGER_PACKAGE` and its `signature` as `KSU_EXPECTED_SIZE` /
`KSU_EXPECTED_HASH`. Those two are upstream's own defaults in `kernel/Kbuild`,
**replaced rather than added to**, so nothing is left holding upstream's
certificate: `is_manager_apk()` never returns true for the official manager, it
is never found, and a manager the kernel does not recognise cannot rewrite
`ksud`. The package names differ, so both can be installed at once.

`signature.size` has a ceiling. `apk_sign.c` reads the certificate into a
1024-byte buffer before hashing it and refuses anything longer, so a longer one
is never compared against the hash at all — which on a device is
`is_manager: 0` and nothing else. The first key used here was RSA-4096 at 1316
bytes and **no module ever recognised the manager it signed**; it is RSA-2048
and 804 bytes now, against upstream's own 827. `generate_feed.py` rejects a
pair past the limit rather than letting it reach a device.

The APK itself is built by
[Root-My-Device-KSU](https://github.com/Witaqua-tools/Root-My-Device-KSU),
beside the patches that make it ours. Neither repository can check the other's
strings, so both check the artifact: that build asserts the package and the
certificate against what it actually signed, and the `feed` job here downloads
the published APK and asserts them again against what the modules were built
with.

## Which patches a build gets

The patches are keyed by the upstream version they were written against:
`Root-My-Device-KSU/patches/<version>/<set>/`. **Nothing names the version.**
The action derives it from the KernelSU submodule pin as `30000 + git rev-list
--count HEAD` — KernelSU's own number, the one `kernel/Kbuild` compiles into
`KSU_VERSION` — so moving the pin selects the sets written for it, and a pin
nothing has been rebased onto fails the build instead of applying hunks meant
for another tree. `Root-My-Device-KSU` keeps three versions at a time; which,
and why those, is documented there.

Each directory under that version is one **patch set**, and a build's tree
carries `common` plus whatever its `kernelsu.json` names in `patchSets`.
Nothing else is applied to it, so a workaround for one vendor is not merely
compiled out of another vendor's module — it is not in the tree that module was
built from.

| Set | Applied to | Holds |
| --- | --- | --- |
| `common/` | every build, always, first | what no target can boot without |
| `galaxy/` | builds that name it | Samsung KDP / RKP / DEFEX |
| `oppo/` | builds that name it | OPPO, OnePlus and realme — empty today |
| `devices/<id>/` | the build of that id | what nothing else can use — empty today |

**`common` is required by every target**, on any vendor's firmware. Upstream
late-load could not write a new `/data/adb/ksud` after the module changed the
loader's security context — the destination stayed a zero-byte file. The set
stages the daemon at `/data/local/tmp/.ksud-stage`, renames it onto the same
`/data` filesystem before loading the module, and finishes labels and assets
once the module is active. The bootstrap helper in
[`src/payloads/su_daemon`](../payloads/su_daemon) drives exactly that sequence,
so a build without this set cannot install on any device. It also carries the
include paths a module built out of a DDK image needs.

**`common` also stops a late-load from running module stage scripts.** A module
script assumes what a boot gives it: its own module mount already established,
and no framework running yet. A late-load has neither — there is no metamodule
to mount anything, and zygote has been serving for minutes. What the scripts do
instead is start daemons against a live zygote, and those daemons restart it to
inject. On warhol that killed the device every time: `system_server` came back
and died in `ApplicationSharedMemory.nativeCreate` with `ENOENT`, seven seconds
after the module loaded, on every retry until a reboot — while `ksud` itself
exited `0` and KernelSU answered its control ioctl throughout. Measured, not
inferred: with the same build and the same three Zygisk modules left in place
and enabled, skipping the scripts alone keeps `system_server` at its original
pid.

`KSU_LATE_LOAD_MODULES=1` in `ksud`'s environment runs them anyway. It is a
bring-up knob, not a user setting: `ksud` is `execl`'d by the bootstrap helper
and inherits the daemon's environment, so reaching it means editing
`su_daemon.c`'s `set_root_env()` or the helper. Neither `su --late-load`, the
feed, nor the application can set it as things stand.

The set carries two smaller things with it. `late_load` rejoins init's mount
namespace before touching modules, because the caller has to exec it from a
throwaway private namespace and every mount made in that one dies with the
process — that is not what fixed the crash above, and is kept because it is
right, not because it was shown to help. And it logs one line naming what the
module reports, so a run has evidence of KernelSU being live that does not
depend on descriptors the sepolicy reload takes away:

```text
KernelSU live: version=32525 uapi=2 flags=0x5 features=0x5 late_load=true
```

Those first two numbers are the pair the manager shows on its home screen as
`バージョン: 32525-2`, and both have to be right for it to accept the module:
`requireNewKernel()` refuses a version below `MINIMAL_SUPPORTED_KERNEL` (32513)
and a `uapi_version` that is not its own.

**`galaxy` exists because a generic build panics on Samsung firmware**: an
inline `put_cred()` writes directly to a KDP-protected credential refcount, RKP
rejects the write to an unused syscall-table slot while the generic code still
treats the dispatcher as installed, and DEFEX keeps its own task credential
tuple that a KernelSU UID transition leaves unsynchronised. The set resolves
`kdp_usecount_dec_and_test()` and `kdp_assign_pgd()` from the running kernel,
installs credentials through `prepare_ro_creds()`, synchronises the DEFEX
record, records a syscall-table hook only if the RKP-protected write succeeds,
and otherwise falls back to kretprobe/kprobe sucompat. Each of the three sits
behind its own `CONFIG_KSU_SAMSUNG_*` option, which the target passes in
`config` alongside the set — the options gate code that only the set puts there,
so either one without the other does nothing.

One target names a set: `quest3` takes `devices/quest3`, which keeps the
tracepoint mark on the zygote launcher Horizon OS boots through. Every other
build here is `common` alone.

A name that resolves to nothing fails the build, and `tools/generate_feed.py`
fails on it in seconds beforehand whenever the submodule is checked out. That is
also why an empty `oppo/` costs nothing: no target can name it until it holds a
patch.

## How a build is produced

CI runs this from each target's `kernelsu.json`; the steps are here for
reproducing one by hand.

```sh
git submodule update --init --recursive src/kernelsu
# the pin's own KernelSU version names the directory; a shallow submodule
# counts 1 and belongs to no directory, which is the error you want
version=$((30000 + $(git -C src/kernelsu/KernelSU rev-list --count HEAD)))
patches="$PWD/src/kernelsu/Root-My-Device-KSU/patches/$version"
# common first, then each set in patchSets, in the order it lists them
for set in common <patchSets>; do
  git -C src/kernelsu/KernelSU apply "$patches/$set"/*.patch
done
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

## When the DDK image is not close enough

A DDK image is a stand-in for a device's kernel, and for some devices it is not
a good enough one — close enough to build and link, not close enough to load.
Such a target names a `kernelSource` in its `kernelsu.json` and keeps the
device's own `/proc/config.gz` as `kernel.config` beside it. The
**build kernel-source modules** workflow builds that one against the kernel it
names, and the target references the result by digest under `prebuiltModule`;
the payload build then downloads and checks it rather than building one, and
everything after that — the `ksud` that embeds it, the asset names — is the
same. `ddkImage` still names the closest KMI, because that is what `ksud` is
built with.

The two keys are required together: a `kernelSource` nothing references is a
ten-minute build with no consumer, and a `prebuiltModule` with no
`kernelSource` is a URL with no recipe behind it. `tools/generate_feed.py`
fails on either.

That workflow does not run in the payload build because it takes ten minutes on
a tree that never changes. It publishes a `modules-*` **prerelease**, never the
latest one: the app resolves `releases/latest` and downloads every asset from
that tag, so only the `payloads-*` releases may hold that spot.

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
