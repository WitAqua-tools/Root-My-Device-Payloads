# Root My Device Payloads

A fork of [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads).
This repository keeps the original Apache License 2.0 — see [LICENSE](LICENSE).
Everything here that came from somewhere else is named in [Credits](#credits).

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

Use only on devices you own or are explicitly authorized to test.

## Supported targets

| Target | Core | Device | SoC | Region | Firmware | Kernel | Fingerprint | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `pmg110-cn-16.0.9.400` | `core66` | OPPO PMG110 / K15 Pro+ | MediaTek MT6991 | CN | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` (`android15-6.6`, 4K pages) | `OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/B.c24acd_188efc3_187038b:user/release-keys` | Exploit core device-verified through the tree it was imported from; the feed entry ships, but the payload built here has not completed a run, and until its root glue was wired up no build of it could have reported one. |
| `warhol-jp-OS3.0.304.0.WPSJPXM` | `core612` | Xiaomi 17T Pro | MediaTek MT6993 | JP | `OS3.0.304.0.WPSJPXM` | `6.12.38-android16-5-g1d46253471dd-ab15048002-4k` (`android16-6.12`, 4K pages) | `Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/OS3.0.304.0.WPSJPXM:user/release-keys` | Working from the app, KernelSU `32525-2`. |
| `xig07-jp-OS3.0.7.0.WNEJPKD` | `core61` | Xiaomi 14T (au XIG07) | MediaTek MT6897 | JP | `OS3.0.7.0.WNEJPKD` | `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` (`android14-6.1`, 4K pages) | `Xiaomi/XIG07_jp_kdi/XIG07:16/BP2A.250605.031.A3/OS3.0.7.0.WNEJPKD:user/release-keys` | Working from the app, KernelSU `32525-2`; nothing has been served through the feed yet. |

The Samsung profiles this repository began with were removed along with their
payloads, artifacts, KernelSU builds and feed entries.

Targets are exact-firmware targets. A matching model with a different build is
not equivalent and must be ported separately. Which fields a device is matched
against is in [`docs/FEED.md`](docs/FEED.md).

A target directory holds what the build reads and nothing else. Where each
number came from, what was ruled out, and what is still unverified are that
port's own notes and are kept outside this repository;
[`docs/PORTING.md`](docs/PORTING.md) is the part that generalises.

## Cores

This attack chain is fixed to a **GKI branch**, not to a SoC. A target on a
different kernel series therefore takes a different exploit core — not the same
core with different offsets — and each target names the one it needs in
`src/targets.json`:

| Core | Kernel | From |
| --- | --- | --- |
| `core61` | `android14-6.1` | Root-My-Galaxy-Payloads' own `src/`, the tree this repository is a fork of |
| `core66` | `android15-6.6` | pmg110-root |
| `core612` | `android16-6.12` | warhol-root |

What each core is, how it reaches root, what it carries against the tree it came
from, how a boot's kernel-MTE answer is decided, and how to add a core are in
[`docs/CORES.md`](docs/CORES.md). No core is this repository's own work; which
project each tree above is, with links, is in [Credits](#credits). What *is* this
repository's own is the glue around them, in [Layout](#layout).

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

A target's directory, its header and its root glue are all derived from
`src/targets.json` rather than written down twice —
[`docs/PORTING.md`](docs/PORTING.md) step 5. The two markers the application
refuses an install without, and which piece of the payload prints each, are
step 10 of the same document.

## Feed delivery

Nothing about the feed is committed, and no artifact is. Every push to `main`
builds all payloads and publishes them as a GitHub release under a tag unique to
that run; `targets-v2.json` is generated by
[`tools/generate_feed.py`](tools/generate_feed.py) from `src/targets.json` joined
with the sizes and URLs of what was actually built. Root My Device resolves
`releases/latest` and downloads every artifact that asset names.

Why the unique tag makes a resolved release immutable, what the app matches a
device against, which KernelSU manager an entry names, and why the bootstrap
helper has to be one binary for every target are in
[`docs/FEED.md`](docs/FEED.md).

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

`release` is the one the feed publishes: it is size-checked and then padded to
the fixed `APP_RELEASE_SIZE` the app expects. `cve-2026-43499-root` is the
bootstrap helper the app ships inside its APK; every target's build of it is the
same binary, and [`docs/FEED.md`](docs/FEED.md) says why that has to stay true
and why it is published here at all.

What to check on a build before trusting it — the release size, undefined
symbols, the root glue, and that helper's hash — is
[`docs/PORTING.md`](docs/PORTING.md) step 7.

KernelSU is a pinned submodule rather than a set of committed binaries, so clone
with it:

```sh
git clone --recurse-submodules <this repository>
```

The late-load artifacts are rebuilt from that submodule plus the patches in
[Root-My-Device-KSU](https://github.com/Witaqua-tools/Root-My-Device-KSU),
itself a submodule. They come in sets: one every build takes, and vendor or
single-build sets a target names in its `kernelsu.json`, so a build compiles only
what it is the reason for. The patches are not stored here because they carry
KernelSU's GPL terms rather than this repository's Apache-2.0 ones — see
[Credits](#credits). The build procedure and the per-target audit steps are in
[`src/kernelsu/README.md`](src/kernelsu/README.md).

The firmware-to-target procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md).

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
device instead of in the build, and the one audit they cannot run is the one
against a specific device's recovered kernel. Both are described in
[`src/kernelsu/README.md`](src/kernelsu/README.md).

## Credits

### This repository

A fork of [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads),
the work of [BuSung-dev](https://github.com/BuSung-dev), keeping its Apache
License 2.0 — see [LICENSE](LICENSE). The Samsung profiles that tree was written
for are gone from here; `core61` is its `src/`, imported as a core.

### The exploit

The published source this repository's payload was originally based on is
IonStack, in
[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit).

No exploit core here is this repository's own work; each is imported from a port
of that exploit, and the one file this repository writes in a core's directory is
`root.c`:

| Core | Imported from | Which is |
| --- | --- | --- |
| `core61` | [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) | that tree's own `src/`, imported as a core |
| `core66` | [pmg110-root](https://github.com/soralis0912/CVE-2026-43499-pmg110-root) | whose own exploit core is a GhostLock 6.6 tree |
| `core612` | [warhol-root](https://github.com/soralis0912/CVE-2026-43499-warhol-root) | [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle) plus the kernel-MTE fix that device needs |

The `kernelsnitch/` directory under each core is the software-only timing side
channel published as
[lukasmaar/kernelsnitch](https://github.com/lukasmaar/kernelsnitch), imported
with the core that uses it rather than separately. The Jenkins hash it carries
keeps Bob Jenkins' and Jozsef Kadlecsik's notices in the file, where they are.

### KernelSU

[tiann/KernelSU](https://github.com/tiann/KernelSU), pinned as a submodule
rather than committed as binaries. The patches applied to it are a derivative
work of it and carry its GPL terms rather than this repository's Apache-2.0
ones, so none of them are stored here — down to the ones that would only ever
serve one device. They live in
[Root-My-Device-KSU](https://github.com/Witaqua-tools/Root-My-Device-KSU) with
verbatim copies of both upstream licence files: hunks under `kernel/` are
GPL-2.0 and those under `userspace/` are GPL-3.0.
