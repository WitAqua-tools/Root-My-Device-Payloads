# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported profiles

| Profile | Device | Firmware | Kernel/KMI | Status |
| --- | --- | --- | --- | --- |
| `pa3q-S938NKSUACZF1` | Galaxy S25 Ultra `SM-S938N` | `BP4A.251205.006.S938NKSUACZF1` | `android15-6.6` | Device-tested |
| `pa3q-S9380ZHUBCZF1` | Galaxy S25 Ultra `SM-S9380` | `BP4A.251205.006.S9380ZHUBCZF1` | `android15-6.6` | Device-tested |
| `e3q-S928USQS6DZF2` | Galaxy S24 Ultra `SM-S928U/SM-S928U1` (Snapdragon 8 Gen 3) | `BP4A.251205.006.S928USQS6DZF2` | `6.1.145-android14-11-33419968-abS928USQS6DZF2` | Hardware debugging in progress |
| `pmg110-16.0.9.400` | OPPO PMG110 / K15 Pro+ (MediaTek MT6991) | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-...-abogki500782043-4k` | Offsets cross-checked against a verified port; device bring-up pending, no feed entry yet |

Profiles are exact-firmware profiles. A matching model with a different build
is not equivalent and must be ported separately.

Root My Galaxy requires both the exact `uname -r` value in `kernelRelease` and
the complete `/proc/version` value in `kernelVersion`. This distinguishes
vendor kernels that expose the same release string but were linked from
different builds. Model and device fields are descriptive metadata; build
display ID, SDK, ABI, and page size remain part of automatic profile selection.

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.

## Feed delivery

Root My Galaxy resolves the payload repository's current commit first and
fetches `support/targets-v2.json` and every artifact from that immutable commit.
Per-artifact SHA-256 fields and manifest signatures are not part of schema
version 2.

## Build

```sh
make TARGET=pa3q-S938NKSUACZF1 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e3q-S928USQS6DZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e1s-S921BXXSFDZF2 ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=a15-A155NKSS6BYH1 ANDROID_NDK_HOME=/path/to/android-ndk
```

Outputs:

```text
build/<profile>/cve-2026-43499
build/<profile>/cve-2026-43499-app.so
build/<profile>/cve-2026-43499-root
```

The release app payload is built with:

```sh
make TARGET=essi-S721NKSSCDZF3 ANDROID_NDK_HOME=/path/to/android-ndk release
```

The complete firmware-to-profile procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md). Samsung-specific KernelSU changes and
versioned artifacts are documented in [`kernelsu/README.md`](kernelsu/README.md).
The first non-Samsung profile, OPPO PMG110 (MediaTek MT6991), is documented in
[`docs/PMG110-16.0.9.400.md`](docs/PMG110-16.0.9.400.md); it also records why it
has no `support/targets-v2.json` entry yet.
The exact S921B DZF2 analysis is recorded separately in
[`docs/SM-S921B-S921BXXSFDZF2.md`](docs/SM-S921B-S921BXXSFDZF2.md), and the
S928U/S928U1 DZF2 analysis is in
[`docs/SM-S928U1-S928U1UES6DZF2.md`](docs/SM-S928U1-S928U1UES6DZF2.md). S921B
is an Exynos 2400 target and is not a Qualcomm/Snapdragon reference for E3Q.
The 5.10 A15 analysis is in
[`docs/SM-A155N-A155NKSS6BYH1.md`](docs/SM-A155N-A155NKSS6BYH1.md).

## Continuous integration

[`.github/workflows/build.yml`](.github/workflows/build.yml) builds every
directory under `src/targets` on push and pull request, so adding a profile
needs no workflow change. Each build asserts the fixed release payload size,
and reports — without failing — whether the committed artifact reproduces
byte-for-byte from the pinned NDK. A separate job validates
`support/targets-v2.json`: required fields, unique profile IDs, that
`kernelRelease` and `kernelBuildVersion` really are substrings of the recorded
`/proc/version`, and that every referenced artifact exists at the declared size.
It also lists profiles that build but have no feed entry.

Use only on devices you own or are explicitly authorized to test.
