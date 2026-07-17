# Root My Galaxy Payloads

This repository contains the device-specific native side of
[Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy):

- exact firmware profiles and offsets;
- the app-domain CVE-2026-43499 exploit source and compiled payload;
- the app bootstrap helper source;
- the verified KernelSU late-load build artifacts;
- the Ed25519-signed support feed consumed by the application.

It intentionally does not contain Android application source code.

## Supported profile

```text
profile: pa3q-S938NKSUACZF1
model: SM-S938N
build: BP4A.251205.006.S938NKSUACZF1
fingerprint: samsung/pa3qksx/pa3q:16/BP4A.251205.006/S938NKSUACZF1_OKRACZF1:user/release-keys
ABI: arm64-v8a
page size: 4096
```

The port is based on the exploit source published at
<https://github.com/NebuSec/CyberMeowfia/tree/main/IonStack/CVE-2026-43499/exploit>.

## Feed integrity

`support/targets-v2.json` is signed with Ed25519. Root My Galaxy resolves the
payload repository's current commit first and fetches the manifest, signature,
and every artifact from that immutable commit. Per-artifact SHA-256 fields are
not part of schema version 2.

The signing private key is not stored in this repository.

## Build

```sh
make ANDROID_NDK_HOME=/path/to/android-ndk
```

Outputs:

```text
build/cve-2026-43499
build/cve-2026-43499-app.so
build/cve-2026-43499-root
```

Use only on devices you own or are explicitly authorized to test.
