# Root My Device Payloads

A fork of [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads),
the work of [BuSung-dev](https://github.com/BuSung-dev). This repository keeps
the original Apache License 2.0 — see [LICENSE](LICENSE).

This repository contains the device-specific native side of
[Root My Device](https://github.com/Witaqua-tools/Root-My-Device):

- exact firmware profiles and offsets;
- the exploit payload sources;
- the app bootstrap helper source;
- the KernelSU late-load build definitions, and which patch sets each takes;
- the generator for the support feed the application reads.

It intentionally does not contain Android application source code, and it
contains no built payloads. Every artifact the app downloads is produced by CI
and published as a release asset — see [Feed delivery](#feed-delivery).

## Supported targets

| Target | Core | Device | SoC | Region | Firmware | Kernel | Fingerprint | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pmg110-cn-16.0.9.400` | `core66` | OPPO PMG110 / K15 Pro+ | MediaTek MT6991 | CN | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` (`android15-6.6`, 4K pages) | `OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/B.c24acd_188efc3_187038b:user/release-keys` | Exploit core device-verified through the non-app build; the feed entry ships, but the app payload has not completed a run here. |
| `warhol-jp-OS3.0.304.0.WPSJPXM` | `core612` | Xiaomi 17T Pro | MediaTek MT6993 | JP | `OS3.0.304.0.WPSJPXM` | `6.12.38-android16-5-g1d46253471dd-ab15048002-4k` (`android16-6.12`, 4K pages) | `Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/OS3.0.304.0.WPSJPXM:user/release-keys` | Exploit core device-verified through the non-app build, first attempt; `buildDisplay` is `BP2A.250605.031.A3`, read from the device, not the firmware string in the Firmware column. The app payload has not completed a run here. |

The Samsung profiles this repository began with were removed along with their
payloads, artifacts, KernelSU builds and feed entries.

Targets are exact-firmware targets. A matching model with a different build is
not equivalent and must be ported separately.

A target directory holds what the build reads and nothing else. Where each
number came from, what was ruled out, and what is still unverified are that
port's own notes and are kept outside this repository;
[`docs/PORTING.md`](docs/PORTING.md) is the part that generalises.

### Carried, but not in the feed

An entry in `src/targets.json` is what puts a target in the feed and in CI's
build matrix, and it is a claim that the payload has been built and can be
served to a device that matches. One target is carried without one:

| Target | Core | Device | SoC | Firmware | Kernel |
| --- | --- | --- | --- | --- | --- |
| `quest3/global/5.10.240-gce8cca212ac5` | `core510` | Meta Quest 3 (`eureka`) | Qualcomm SXR2230P (`anorak`) | Horizon OS, incremental `52345320027600520`, `UP1A.231005.007.A1`, SDK 34 | `5.10.240-gce8cca212ac5` (Meta's own 5.10, 4K pages, `VA_BITS=39`) |

It builds — `make TARGET=quest3/global/5.10.240-gce8cca212ac5 CORE=core510` —
and it is out of the feed for two reasons, both of which have to be answered
before it goes in:

- **Nothing here has run on this device.** The offsets are recovered from this
  build's own boot image and cross-checked twice over, and the core they feed
  is a port whose author reports a working root on a different build of the
  same device; neither of those is a run. Upstream also warns that a failed
  attempt can hang the device until the power button is held.
- **A target directory must contain a `kernelsu.json`**, and this device has no
  KernelSU build to name: the kernel is Meta's own rather than a GKI branch, so
  there is no KMI a module could be built against. Carrying it out of
  `src/targets.json` is the smaller answer; teaching the feed generator that a
  target can have no KernelSU build is the other one, and it would change what
  the app is told about every target.

The application route has a third open end of its own, described in
[`core510/root.c`](src/payloads/CVE-2026-43499/core510/root.c): this core execs
a second, 32-bit binary partway through, and both the path it is staged at and
the path it is exec'd from are inside `/data/local/tmp`, which an
application-launched run cannot write.

One number this core needs is build-dependent and does not live in a target
header: the `0x34` in `core510/exp32/stack.c`, where inside the 260-byte
`setsockopt` payload the fake waiter has to sit for it to land on the real
one's stack slot. It is a compiler's frame layout rather than anything in the
image's symbols or BTF, and it was measured live for this build — the kernel
booted under QEMU with a 32-bit process making the two calls, `&greqs` read out
of `ip6_mc_source`'s argument and the waiter slot out of the futex frame's SP.
A second 5.10 target has to re-measure it rather than inherit it from here.

## Cores

This attack chain is fixed to a **GKI branch**, not to a SoC. A target on a
different kernel series therefore takes a different exploit core — not the same
core with different offsets — and each target names the one it needs in
`src/targets.json`:

| Core | Kernel | From | Route to root |
| --- | --- | --- | --- |
| `core66` | `android15-6.6` | pmg110-root | swaps a forked *child*'s cred, then queues a `call_usermodehelper` work item from the still-unprivileged parent to exec the helper |
| `core612` | `android16-6.12` | warhol-root — upstream popsicle plus the kernel-MTE fix that device needs | swaps the exploit process's own cred and reloads the SELinux policy, then execs the helper directly |
| `core510` | `5.10` — Meta's own kernel for Quest 3, which is not a GKI branch at all | [IonStackQuest3](https://github.com/grayawa/IonStackQuest3) | swaps a forked *child*'s cred and clears that child's seccomp filter through the same write, and the child execs the helper |

No core is this repository's own work and none is edited to resemble another,
so a fix can be taken from upstream and no kernel's constants can leak into
another kernel's tree. What is this repository's own is the glue around them —
`<core>/root.c`, `mte.c`, `preload.c` and `payload.h`, described under
[Layout](#layout).

A core's own code stays in that core's directory, `root.c` included: it is the
one file under `src/payloads/<payload>/<core>/` that this repository wrote
rather than imported. No port has a file by that name — their app glue is
`preload.c`, `su_daemon.c` and an `.incbin` blob, none of which was copied — so
re-importing a core is still "replace everything there but `root.c`", and the
build lists it apart from the imported sources for the same reason.

`core510` is the exception to that last sentence, and the reason is worth
stating once: the tree it came from *does* have a `root.c`, and there it is the
exploit's own final stage rather than app glue. It is imported byte-identical
as `root_stage.c`, so re-importing that core is "replace everything there but
`root.c`", with `root_stage.c` among the files replaced.

`core612` carries one delta against warhol-root, and only this one:

- `util.c` includes `payload.h` and asks `payload_mte_tagged()` whether this
  boot's kernel tags heap pointers, where upstream passes a hard-coded
  `mte_enabled = 1` to `kernelsnitch_setup()`. Two hunks: that include and that
  call. See [Kernel MTE](#kernel-mte) for why it cannot be a constant on
  warhol.

`core66` carries two deltas against pmg110-root, and only these two:

- `offset.h` names the target header through `TARGET_HEADER` rather than
  upstream's `TARGET_CONFIG_H`. The Makefile now defines both macros to the
  same include, so this delta no longer buys anything and could be dropped to
  make the tree exact.
- `main.c` has lost `run_bootstrap()`, its `--bootstrap` argument and the
  `extern int mini_adb_shell(const char *)` it called. Upstream defines that in
  `miniadb.c`, which was never copied here — so the reference was dangling, and
  it left `mini_adb_shell` **undefined in the shipped payload**. The
  application loads the payload with `dlopen(RTLD_NOW)`, which resolves
  everything up front, so pmg110's app payload could not load at all. The mode
  itself is unreachable here: nothing in this repository or in the application
  passes `--bootstrap`.

`core510` carries three deltas against IonStackQuest3, and only these three:

- `q3slide.c` returns `0` rather than `1` from every failure path of
  `getkerneltextstart()`. Upstream's `1` is indistinguishable from a leaked
  base of `0x1`, and the caller does not check: on a device where
  `perf_event_open` is closed, the run would go on to aim its arbitrary write
  at `0x1 + offset`.
- `slide.c` gains `slide_base_plausible()`, which refuses a base that is not a
  kernel VA, not 2 MiB aligned, or implausibly far from the link-time base, so
  a failed leak stops before the write instead of after it. Neither of these
  two is gated: there is no target for which upstream's behaviour is the
  wanted default, and both were written while porting this core to the build
  the `quest3` target describes.
- `common.h` guards `EXP32_LOCAL` with `#ifndef`, leaving upstream's value as
  the default, so a target header can name the path instead. `api.c` execs that
  path as a compile-time constant, and a run that cannot write
  `/data/local/tmp` has no way to move it at run time.

One piece of upstream behaviour is left in place rather than made a fourth
delta: `run_exploit()` ends by forking and exec'ing `/data/local/tmp/su`, the
interactive `su` that port unpacks from its own blob. This repository does not
produce that file, so the exec fails and that child exits — the run is
unaffected, because what an install is gated on is `payload_report_root()` from
the root glue, not this. It is the last thing in the file the import replaces,
so leaving it costs nothing and keeps the tree exact.

Whichever core a target names, `readelf --dyn-syms` on the built
`*-app.release.so` should report no undefined symbol outside `@LIBC`. Anything
else is a call that will fail at `dlopen` on the device rather than in the
build.

A new core is added by dropping the tree in as `src/payloads/<payload>/<core>/`,
writing the `root.c` beside it that fills its root seam, and naming it from a
target. The Makefile has to learn about it only where the core's shape differs
from the two it was written for: `core510` compiles four more files than
`CORE_SRCS` lists and builds a second artifact, and both are one conditional
each, keyed on the core name.

Root My Device requires both the exact `uname -r` value in `kernelRelease` and
the exact `uname -v` value in `kernelBuildVersion`. The second distinguishes
vendor kernels that expose the same release string but were linked from
different builds. `kernelVersion` is the whole `/proc/version` line the other
two are read off; it is carried in the feed for the record and the app does not
match on it. Model, device, SoC and region are descriptive metadata; build
display ID, SDK, ABI, and page size remain part of automatic target selection.

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.
[grayawa/IonStackQuest3](https://github.com/grayawa/IonStackQuest3) is that
source adapted to Meta Quest 3, and is the reference implementation `core510`
was imported from — including its `gen_ionstack_config.py`, which is what
recovers a build's symbol offsets for that core.

## Kernel MTE

With `KASAN_HW_TAGS` active, every slab pointer carries an allocation tag in
bits [59:56]. The `mm_struct` leak hashes the whole pointer the way
`futex_hash()` does, so it has to sweep the same shape the kernel produced: an
untagged sweep on a tagged kernel matches nothing and the leak fails with no
other symptom. Sweeping all 16 tags is the safe answer either way — tag `0xf`
*is* the untagged pointer — but on a kernel that tags nothing it costs 16x the
candidates and 16x the false-positive exposure.

On warhol that is not a property of the firmware. The device boots the same
images under an engineering preloader, which enables MTE, or a retail one,
which does not, so `src/targets/warhol/.../target-core612.h` deliberately does
not answer and `mte.c` answers per boot instead:

| | |
|---|---|
| `GHOSTLOCK_MTE=0` / `=1` | forces it, for a device that disagrees or to reproduce the other case |
| `KS_MTE_TAGGED` in the target header | pins it where a target does know — pmg110's does, from a measurement on that device |
| `AT_HWCAP2 & HWCAP2_MTE` | otherwise |

The last one is not a guess. `HWCAP2_MTE` comes from the `ARM64_MTE` cpu
capability and `kasan_init_hw_tags()` returns early on
`!system_supports_mte()`, which is that same capability — `arm64.nomte` clears
both together — so a kernel that does not report MTE to userspace cannot be
tagging slab pointers. The converse is weaker: MTE reported with `kasan=off` on
the command line leaves pointers untagged and this still answers "tagged",
which costs the 16x sweep and still finds the object. Every uncertain case
resolves that way on purpose.

Only `core612` reads it. `core66`'s own knob predates this and stays as
imported, and its one target pins the answer.

## Layout

```text
src/targets.json                      every target, and the only hand-authored feed input
src/targets/<device>/<region>/<kernel release>/
                     target-<core>.h  offsets recovered from that exact firmware,
                                      for the core that reads them
                     p0_fingerprint.h optional, and only core66 reads it
                     kernelsu.json    the KernelSU build this target pairs with,
                                      and the patch sets that build takes
src/payloads/<payload>/               one directory per exploit
                     core66/          the 6.6 core, from pmg110-root
                       root.c         usermodehelper route to a resident root,
                                      and this repository's, not the port's
                     core612/         the 6.12 core, from warhol-root
                       root.c         direct-exec route to the same
                     core510/         the 5.10 core, from IonStackQuest3
                       root.c         the seam: helper install, and staging the
                                      32-bit stage the core execs
                       root_stage.c   that port's own root.c, imported unchanged
                       exp32/          the 32-bit stage, built as its own artifact
                     mte.c            whether this boot's kernel tags heap pointers
                     preload.c        the retry supervisor, shared by all
                     payload.h        what those agree on
src/payloads/su_daemon/               the bootstrap helper the app ships in its APK
                     su_daemon.c      the su daemon: protocol, uid check, exec
                     late_load.c      all it knows about KernelSU
                     hold_refs.c      core66's kernel-page reference holder
                     su_daemon.h      the seam between those three
src/kernelsu/                         KernelSU submodule, patch submodule and audit tools
```

A target's directory is derived from its `device`, `region` and `kernelRelease`
in `src/targets.json` — it is never written down twice, so the two cannot drift
apart. `region` is part of the path because the same model and kernel version
ship as different builds per region. Its header and its root glue are derived
the same way, from `core`.

The application refuses an install unless the exploit log contains both
`exploit completed` and `done=1 root=1`. The first is the supervisor's; the
second is `payload_report_root()`, which every root glue calls and which has to
be printed from inside the attempt, because nothing about the attempt's result
crosses back to the supervisor that forked it.

## Feed delivery

Every push to `main` builds all payloads and publishes them as a GitHub release
under a tag unique to that run (`payloads-<run>-<sha>`). Root My Device resolves
`releases/latest`, reads the `targets-v2.json` asset from it, and downloads every
artifact named in it. Because the tag is unique, a resolved release is an
immutable set: its assets never change once published.

Nothing about the feed is committed. `targets-v2.json` is generated by
[`tools/generate_feed.py`](tools/generate_feed.py), which joins `src/targets.json`
with the sizes and URLs of what the build matrix actually produced. The same
script emits the build matrices, so no other file has to know how a target maps
onto a path.

`kernelVersion` and `kernelBuildVersion` are the kernel's own `linux_banner` and
`UTS_VERSION`. `adb shell cat /proc/version` on the device prints the first and
contains the second; both can also be read out of the boot image's kernel, which
is where this repository's values came from when no device was to hand. Reading
them from an image proves what that image would print, not that the slot the
device boots is the one that was read — prefer the device where there is one. A
target whose `kernelVersion` is `null` still builds, but is reported and left out
of the feed, because the app matches on those exact strings.

Each entry's `kernelsu` object also names **which KernelSU manager that module
pairs with** — `managerVersionCode`, `managerVersionName` and `managerUrl`,
derived from the KernelSU submodule pin exactly as `KSU_VERSION` is. The two
carry the same number and the manager refuses a module below its own
`MINIMAL_SUPPORTED_KERNEL`, so which manager to install is not a matter of
taste; publishing it with the module is what stops the app having to guess from
a constant of its own. The three are read as optional on the app side, so a
feed published before they existed still installs.

Per-artifact SHA-256 fields and manifest signatures are not part of feed schema
version 2.

## Build

The exploit payloads need only an NDK. `TARGET` is the target's path key,
`PAYLOAD` selects the directory under `src/payloads`, and `CORE` selects the
exploit core within it — all three are what the target says in
`src/targets.json`, and CI passes them from there:

```sh
make TARGET=pmg110/cn/6.6.118-android15-8-g93e223c276e7-abogki500782043-4k \
  CORE=core66 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=pmg110/cn/6.6.118-android15-8-g93e223c276e7-abogki500782043-4k \
  CORE=core66 ANDROID_NDK_HOME=/path/to/android-ndk release
```

```sh
make TARGET=warhol/jp/6.12.38-android16-5-g1d46253471dd-ab15048002-4k \
  CORE=core612 ANDROID_NDK_HOME=/path/to/android-ndk
```

```sh
make TARGET=quest3/global/5.10.240-gce8cca212ac5 \
  CORE=core510 ANDROID_NDK_HOME=/path/to/android-ndk
```

`TARGET` and `PAYLOAD` default to the pmg110 values above and `CORE` to
`core66`. Outputs land in `build/<target with / as _>/`:

```text
cve-2026-43499
cve-2026-43499-app.so
cve-2026-43499-app.release.so
cve-2026-43499-root
cve-2026-43499-exp32       core510 only
```

`cve-2026-43499-exp32` is armeabi-v7a and static, and the NDK has to carry that
toolchain as well — the build says so rather than failing in the compiler. It
has to stay 32-bit: the stack geometry `core510` stamps its fake waiter at is
the compat one. A target header's `EXP32_STAGED_PATH` is where
`core510/root.c` looks for it, and `EXP32_LOCAL` (its `common.h`, overridable
from the target header) is where the core execs it from.

`P0_KERNEL_PHYS_LOAD` is the one constant the quest3 target could not measure,
and its header leaves it overridable rather than pretending otherwise:

```sh
make TARGET=quest3/global/5.10.240-gce8cca212ac5 CORE=core510 \
  EXTRA_CFLAGS=-DP0_KERNEL_PHYS_LOAD=0x8E780000ULL
```

`CORE` also decides which header the build reads and which root glue it links:
`TARGET_HEADER_NAME` defaults to `target-$(CORE).h` and the glue is
`$(CORE)/root.c`. Set `TARGET_HEADER_NAME` explicitly only to read a header
that is not named after the core.

`cve-2026-43499-root` does not depend on the target or the core, so every
target's build of it is the same binary — the builds are byte-identical, and CI
publishes one. That is a constraint, not just an observation: one copy serves
every target, so nothing in it may be compiled for a particular one. The two
things that were are separated out, `late_load.c` and `hold_refs.c`, and what
they used to hard-code now arrives at run time — the KMI and manager package as
arguments from the feed, the reference holder only when a core asks for it.

This is still built and published here because the payload's standalone route
needs it: both target headers name a fixed path the payload execs
(`ROOT_HELPER_PATH`, `ROOT_UMH_PATH`), and an `adb shell` bring-up run stages
this binary there.

The application does not fetch it. It compiles the same source into its own
APK, reaching it through a submodule of this repository rather than a copy, so
`src/payloads/su_daemon/` is the one source and a change here needs nothing
carried over — only the app's submodule pin moved to the commit that has it.

`release` is the one the feed publishes: it is size-checked and then padded to
the fixed `APP_RELEASE_SIZE` the app expects. `cve-2026-43499-root` is the
bootstrap helper the app ships inside its APK.

KernelSU is a pinned submodule rather than a set of committed binaries, so clone
with it:

```sh
git clone --recurse-submodules <this repository>
```

The late-load artifacts are rebuilt from that submodule plus the patches in
[Root-My-Device-KSU](https://github.com/Witaqua-tools/Root-My-Device-KSU),
itself a submodule. Those patches are a derivative work of KernelSU and carry
its GPL terms rather than this repository's Apache-2.0 ones, which is why none
of them are stored here — down to the ones that would only ever serve one
device. They come in sets: one every build takes, and vendor or single-build
sets a target names in its `kernelsu.json`, so a build compiles only what it is
the reason for. The build procedure and the per-target audit steps are in
[`src/kernelsu/README.md`](src/kernelsu/README.md).

The firmware-to-target procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md), which still describes the previous layout
and is being rewritten.

## Continuous integration

[`.github/workflows/build.yml`](.github/workflows/build.yml) is what produces
every published artifact. It runs on push and pull request; only a push to
`main` publishes a release.

| Job | What it does |
| --- | --- |
| `discover` | validates `src/targets.json`, then emits the build matrices from it |
| `exploit` | builds each target with the pinned NDK and asserts the fixed release payload size |
| `kernelsu` | the builds a publishable target depends on: applies the patches to the pinned submodule, builds the module in its KMI's DDK image, then builds the `ksud` that embeds it |
| `kernelsu-extra` | the same for builds nothing publishable needs, but unable to block a release |
| `feed` | generates `targets-v2.json` from what was actually built and checks every URL is anchored to this run's tag |
| `publish` | creates the release and uploads every asset |

`discover` fails in seconds on a bad `src/targets.json`, rather than after a
matrix of kernel builds — nothing it checks is derivable from a binary later on.

The KernelSU jobs assert the two load-time contracts that otherwise fail on the
device instead of in the build: the module's `vermagic` must equal the build's
exact `kernelRelease`, and its `__versions` section must be empty. What they
cannot check is the audit against a specific device's recovered kernel, which is
described in [`src/kernelsu/README.md`](src/kernelsu/README.md).

Use only on devices you own or are explicitly authorized to test.
