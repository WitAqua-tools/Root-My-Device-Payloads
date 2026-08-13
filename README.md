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
| `pmg110-cn-16.0.9.400` | `core66` | OPPO PMG110 / K15 Pro+ | MediaTek MT6991 | CN | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-g93e223c276e7-abogki500782043-4k` (`android15-6.6`, 4K pages) | `OPPO/PMG110/OP61E5L1:16/BP2A.250605.015/B.c24acd_188efc3_187038b:user/release-keys` | Exploit core device-verified on this firmware outside this repository; the feed entry ships, but the payload built here has not completed a run, and until its root glue was wired up no build of it could have reported one. |
| `oneplus-pad3-ex-16.0.9.400` | `core66` | OnePlus Pad 3 (OPD2415) | Qualcomm SM8750P | EX | `OPD2415_16.0.9.400(EX01)` | `6.6.118-android15-8-g2e6b9c3812c5-ab15114928-4k` (`android15-6.6`, 4K pages) | `OnePlus/OPD2415IN/OP6190L1:16/AP3A.240617.008/V.R4T3.17bf73d_cf42a1_c9913b:user/release-keys` | Maintainer device-verified: app-route temporary root, KernelSU `32525`, signer-matched manager grant, SELinux enforcing restoration, and authenticated module/zygote/Vector completion. |
| `warhol-jp-OS3.0.304.0.WPSJPXM` | `core612` | Xiaomi 17T Pro | MediaTek MT6993 | JP | `OS3.0.304.0.WPSJPXM` | `6.12.38-android16-5-g1d46253471dd-ab15048002-4k` (`android16-6.12`, 4K pages) | `Xiaomi/warhol_jp/warhol:16/BP2A.250605.031.A3/OS3.0.304.0.WPSJPXM:user/release-keys` | Working from the app, KernelSU `32525-2`. |
| `xig07-jp-OS3.0.7.0.WNEJPKD` | `core61` | Xiaomi 14T (au XIG07) | MediaTek MT6897 | JP | `OS3.0.7.0.WNEJPKD` | `6.1.138-android14-11-g44bda9e8f6e9-ab13792638` (`android14-6.1`, 4K pages) | `Xiaomi/XIG07_jp_kdi/XIG07:16/BP2A.250605.031.A3/OS3.0.7.0.WNEJPKD:user/release-keys` | Working from the app, KernelSU `32525-2`; nothing has been served through the feed yet. |
| `asteroids-jp-B4.1-260618-1048` | `core61` | Nothing Phone (3a) (A059) | Qualcomm SM7635 | JP | `B4.1-260618-1048` | `6.1.157-android14-11-g82d681c9b06b-ab14634535` (`android14-6.1`, 4K pages) | `Nothing/AsteroidsJPN/Asteroids:16/BQ2A.250721.001-BP2A.250605.031.A3/2606181048:user/release-keys` | Maintainer device-verified: app-route temporary root, KernelSU `32525`, paired-manager authentication, SELinux enforcing restoration, and explicit module/zygote completion. |
| `quest3-global-5.10.240-g55be3759aea4` | `core510` | Meta Quest 3 (eureka) | Qualcomm SXR2230P | GLOBAL | `UP1A.231005.007.A1` | `5.10.240-g55be3759aea4` (Meta's own 5.10, not a GKI branch, 4K pages) | `oculus/eureka/eureka:14/UP1A.231005.007.A1/52345320035400520:user/abl_signing_keys:release,amss_signing_keys:release,release-keys` | Working from the app, KernelSU loaded and answering; its module is built from Meta's own kernel source rather than a DDK image. |

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

| Core | Kernel |
| --- | --- |
| `core61` | `android14-6.1` |
| `core66` | `android15-6.6` |
| `core612` | `android16-6.12` |
| `core510` | `5.10` (not a GKI branch) |

Core behavior and porting details are in [`docs/CORES.md`](docs/CORES.md). The
imported baselines and their published references are in [Credits](#credits).

## Layout

```text
src/targets.json                      every target, and the only hand-authored feed input
src/targets/<device>/<region>/<kernel release>/
                     target-<core>.h  exact offsets and capability selections
                     *.h              optional target tables
                     build.mk         optional build metadata
                     p0_fingerprint.h optional core61 fingerprint data
                     kernelsu.json    the KernelSU build this target pairs with,
                                      and the patch sets that build takes
src/payloads/<payload>/               one directory per exploit
                     core61/          the 6.1 core
                     core66/          the 6.6 core
                     core612/         the 6.12 core
                     core510/         the 5.10 core
                       root.c         repository-owned root handoff
                       exp32/         its 32-bit stage, built as its own
                                      artifact and carried in the payload
                     root_helper.c    getting the helper resident from a context
                                      that is already root, init hijack included
                     mte.c            whether this boot's kernel tags heap pointers
                     preload.c        the shared retry supervisor
                     payload.h        the glue interface
src/payloads/su_daemon/               the bootstrap helper
                     su_daemon.c      protocol, uid check and dispatch
                     late_load.c      late-load dispatcher
                     late_load_legacy.c / late_load_sealed.c
                                      KernelSU late-load implementations
                     hold_refs.c      core66's kernel-page reference holder
                     su_daemon.h      the seam between those parts
src/kernelsu/                         KernelSU submodule, patch submodule and audit tools
```

A target's directory and header name are derived from `src/targets.json` — see
[`docs/PORTING.md`](docs/PORTING.md). Targets on the same kernel series share a
core and select exact constants and optional capabilities through their header.

## Feed delivery

Nothing about the feed is committed, and no artifact is. `targets-v2.json` is
generated by [`tools/generate_feed.py`](tools/generate_feed.py) from
`src/targets.json`, joined with the sizes and URLs of what CI actually built,
and published as a release asset under a tag unique to that run. Root My Device
resolves `releases/latest` and downloads every artifact that asset names.

**Publishing is a hand-started run**, not something a merge does: run *build
payloads* from the Actions tab with **release** ticked. A push to `main` builds
and checks the targets it changed and publishes nothing — the app takes every
asset from whatever tag is sitting at `releases/latest`, so putting one there
is a decision rather than a side effect. A release is always every target,
because each feed entry is joined to its artifact's exact size.

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
`APP_RELEASE_SIZE`, normally 104128 bytes. A target may override it in
`build.mk`. `cve-2026-43499-root` is the target-independent bootstrap helper.

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

## Credits

### This repository

A fork of [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads),
the work of [BuSung-dev](https://github.com/BuSung-dev), keeping its Apache
License 2.0 — see [LICENSE](LICENSE).

### The exploit

The published source this repository's payload was originally based on is
IonStack, in
[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit).

No exploit core here is this repository's own work. Each was written with a
published implementation of that exploit as its reference:

| Core | Reference |
| --- | --- |
| `core61` | [BuSung-dev/Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads) |
| `core66` | [JoinChang/ghostlock-oneplus](https://github.com/JoinChang/ghostlock-oneplus) |
| `core612` | [x-spy/CVE-2026-43499-popsicle](https://github.com/x-spy/CVE-2026-43499-popsicle) |

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
