# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/soralis0912/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported profiles

| Profile | Device | Firmware | Kernel/KMI | Status |
| --- | --- | --- | --- | --- |
| `pmg110-16.0.9.400` | OPPO PMG110 / K15 Pro+ (MediaTek MT6991) | `PMG110_16.0.9.400(CN01)` | `6.6.118-android15-8-...-abogki500782043-4k` | Exploit core device-verified via the non-app build; the app payload and its feed entry are outstanding. See the profile doc |

The Samsung profiles this repository began with have been removed along with
their payloads, artifacts, KernelSU builds and feed entries. What remains is
built from `src/core66/`, the 6.6 core that reaches root on the profile above;
the Samsung-lineage core it replaced is gone with them.

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
make ANDROID_NDK_HOME=/path/to/android-ndk
```

`TARGET` defaults to the only profile present; pass it explicitly once there is
more than one. A profile is built from `src/core66/` when it ships a
`target-core66.h`.

Outputs:

```text
build/<profile>/cve-2026-43499
build/<profile>/cve-2026-43499-app.so
build/<profile>/cve-2026-43499-root
```

The release app payload is built with:

```sh
make ANDROID_NDK_HOME=/path/to/android-ndk release
```

The complete firmware-to-profile procedure is recorded in
[`docs/PORTING.md`](docs/PORTING.md); parts of it still describe the removed
Samsung core and are marked where they do. KernelSU build and audit steps are in
[`kernelsu/README.md`](kernelsu/README.md). The PMG110 profile, including why it
has no `support/targets-v2.json` entry yet, is documented in
[`docs/PMG110-16.0.9.400.md`](docs/PMG110-16.0.9.400.md).

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
