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
| `pmg110-cn-16.0.9.400` | `core66` | OPPO PMG110 / K15 Pro+ | MediaTek MT6991 | CN | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` (`android15-6.6`, 4K pages) | `OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/B.c24acd_188efc3_187038b:user/release-keys` | Exploit core device-verified through the tree it was imported from; the feed entry ships, but the payload built here has not completed a run, and until its root glue was wired up no build of it could have reported one. |
| `warhol-jp-OS3.0.304.0.WPSJPXM` | `core612` | Xiaomi 17T Pro | MediaTek MT6993 | JP | `OS3.0.304.0.WPSJPXM` | `6.12.38-android16-5-g1d46253471dd-ab15048002-4k` (`android16-6.12`, 4K pages) | `Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/OS3.0.304.0.WPSJPXM:user/release-keys` | Working from the app, KernelSU `32525-2`. |
| `xig07-jp-OS3.0.7.0.WNEJPKD` | `core61` | Xiaomi 14T (au XIG07) | MediaTek MT6897 | JP | `OS3.0.7.0.WNEJPKD` | `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` (`android14-6.1`, 4K pages) | `Xiaomi/XIG07_jp_kdi/XIG07:16/BP2A.250605.031.A3/OS3.0.7.0.WNEJPKD:user/release-keys` | Working from the app, KernelSU `32525-2`; nothing has been served through the feed yet. |

The Samsung profiles this repository began with were removed along with their
payloads, artifacts, KernelSU builds and feed entries.

Targets are exact-firmware targets. A matching model with a different build is
not equivalent and must be ported separately.

A target directory holds what the build reads and nothing else. Where each
number came from, what was ruled out, and what is still unverified are that
port's own notes and are kept outside this repository;
[`docs/PORTING.md`](docs/PORTING.md) is the part that generalises.

## Cores

This attack chain is fixed to a **GKI branch**, not to a SoC. A target on a
different kernel series therefore takes a different exploit core — not the same
core with different offsets — and each target names the one it needs in
`src/targets.json`:

| Core | Kernel | From | Route to root |
| --- | --- | --- | --- |
| `core61` | `android14-6.1` | Root-My-Galaxy-Payloads' own `src/`, the tree this repository is a fork of | reaches no root context in user space, so it queues a `call_usermodehelper` work item and the kernel execs the helper |
| `core66` | `android15-6.6` | pmg110-root | swaps a forked *child*'s cred; that child is root and execs the helper itself |
| `core612` | `android16-6.12` | warhol-root — upstream popsicle plus the kernel-MTE fix that device needs | swaps the exploit process's own cred and reloads the SELinux policy, then execs the helper directly |

The last two arrive at the same place — root, SELinux permissive, helper not yet
running — so what follows is one implementation, `root_helper.c`, and each of
their `root.c` is the seam that calls it. `core61` links none of it.

No core is this repository's own work and none is edited to resemble another, so
a fix can be taken from upstream and no kernel's constants can leak into another
kernel's tree. What is this repository's own is the glue around them —
`<core>/root.c`, `mte.c`, `preload.c` and `payload.h`, described under
[Layout](#layout).

A core's own code stays in that core's directory, `root.c` included: it is the
one file under `src/payloads/<payload>/<core>/` that this repository wrote
rather than imported. None of the trees they came from has a file by that name —
their app glue is `preload.c`, `su_daemon.c` and an `.incbin` blob, none of which
was copied — so re-importing a core is still "replace everything there but
`root.c`", and the build lists it apart from the imported sources for the same
reason.

Each core carries deltas against the tree it came from. The ones that change
what a run does are gated on a macro whose default is what upstream did — so a
target that names none of them gets upstream's behaviour unchanged — and what
each is and why it was needed sits beside its gate in the source.

The rest are ungated because upstream's version names something this repository
does not have. `core66` has all three of those: a bootstrap mode that called
into a file that was never copied here, an include macro spelled the way
`core612` spells it, and the check at the end of `run_exploit()` that upstream
answers by running the `su` binary it unpacks from its own blob. The helper here
is a separate artifact and promises a socket rather than a path, so the check
asks the socket. A gate would not help: the default side of it would be a probe
for a file no build of this repository produces.

Whichever core a target names, `readelf --dyn-syms` on the built
`*-app.release.so` should report no undefined symbol outside `@LIBC`. Anything
else is a call that will fail at `dlopen` on the device rather than in the
build.

A new core is added by dropping the tree in as `src/payloads/<payload>/<core>/`,
writing the `root.c` beside it that fills its root seam, and naming it from a
target. Nothing in the Makefile or the workflow has to learn about it.

Root My Device requires both the exact `uname -r` value in `kernelRelease` and
the exact `uname -v` value in `kernelBuildVersion`. The second distinguishes
vendor kernels that expose the same release string but were linked from
different builds. `kernelVersion` is the whole `/proc/version` line the other
two are read off; it is carried in the feed for the record and the app does not
match on it. Model, device, SoC and region are descriptive metadata; build
display ID, SDK, ABI, and page size remain part of automatic target selection.

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.

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

`core66` reads it too, for a target that sets `KS_MTE_PER_BOOT`. Its own
`KS_MTE_TAGGED` predates this and still decides for a target that pins one, so
a device that cannot vary keeps saying so and pays nothing for the question.

Which of the two a target wants is not a style choice. Pinned to `0` on a
tagging boot the `mm_struct` leak matches nothing and the run fails, visibly
and safely. Pinned to `1` on a non-tagging boot it does not fail safely: the
sweep tries fifteen tags that cannot be there, which multiplies the chance a
wrong `(address, tag)` pair satisfies the collision constraints, and a wrong
base is a wild write rather than a retry. So a target pins only where the
device cannot boot the other way.

## Layout

```text
src/targets.json                      every target, and the only hand-authored feed input
src/targets/<device>/<region>/<kernel release>/
                     target-<core>.h  offsets recovered from that exact firmware,
                                      for the core that reads them
                     p0_fingerprint.h optional, and only core61 reads it
                     kernelsu.json    the KernelSU build this target pairs with,
                                      and the patch sets that build takes
src/payloads/<payload>/               one directory per exploit
                     core66/          the 6.6 core, from pmg110-root
                       root.c         which of the two routes below this core
                                      hands over on, and this repository's,
                                      not the port's
                     core612/         the 6.12 core, from warhol-root
                       root.c         the same seam for that core
                     root_helper.c    getting the helper resident from a context
                                      that is already root, init hijack
                                      included; linked into the cores that
                                      reach one
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

`TARGET` and `PAYLOAD` default to the pmg110 values above and `CORE` to
`core66`. Outputs land in `build/<target with / as _>/`:

```text
cve-2026-43499
cve-2026-43499-app.so
cve-2026-43499-app.release.so
cve-2026-43499-root
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
