# Adding a target

What it takes to make one exact firmware build installable, in the order the
questions actually come up. Written against the ports this repository has done —
pmg110 on `android15-6.6`, warhol on `android16-6.12` and xig07 on
`android14-6.1` — and describing the layout as it is.

Per-target derivation records are **not kept here**. A target directory holds
what the build reads and nothing else; where each number came from, what was
ruled out, and what remains unverified belong in that port's own notes, outside
this repository. What follows is the part that generalises.

## 0. A target is one firmware build

Not a model, and not a kernel version. `TargetProfile.matches()` on the app side
requires the exact `kernelRelease`, `kernelBuildVersion`, `buildDisplay`, `sdk`,
`abi` and `pageSize`, so a device of the same model on a different build is a
different target and must be ported separately. Two builds that ship a
byte-identical kernel image can share one entry; check, do not assume.

A target has two independent axes, and confusing them is the most expensive
mistake available here:

| Axis | What varies | Where it lives |
| --- | --- | --- |
| **core** | the GKI branch the exploit chain is written against | `src/payloads/<payload>/<core>/` |
| **target** | the offsets of one firmware build | `src/targets/<device>/<region>/<release>/` |

The chain is fixed to a GKI branch, not to a SoC or a vendor. A 6.6 kernel and a
6.12 kernel need different cores — different `rt_mutex_waiter` and `task_struct`
shapes, a different reclaim, a different primitive at the end — not the same core
with different numbers.

## 1. Decide whether an existing core covers this kernel

Read `uname -r`. If the GKI branch matches a core this repository already has,
the port is a matter of offsets and you can skip to step 3. If it does not, the
port needs a new core first, and that is a much larger piece of work: it is
someone's exploit tree, not something derived from the firmware. Which cores
exist, and what each already answers, is [`CORES.md`](CORES.md).

Bringing in a new core, as `core612` was:

1. Work from a checkout of its reference that you have verified is clean.
   `git status` and `git diff --stat` first, then extract with `git archive HEAD`
   and compare — an uncommitted local experiment taken in as though it were the
   published work is a failure mode that has already happened once, and it is
   invisible afterwards.
2. Take only the exploit tree. The reference's own `preload.c`, `su_daemon.c` and
   any `.incbin` blob are its app glue; this repository has its own. The core
   directory ends up holding exactly one file this repository wrote, `root.c`
   below, so bringing it up to date later is "replace everything here but
   `root.c`" -- check first that the reference has not since grown a file by that
   name.
3. Do not edit it to resemble the core already here — not the naming, and
   especially not the constants each spells differently. Where the two disagree
   about something the build has to reconcile, reconcile it in the Makefile.
   `TARGET_HEADER` versus `TARGET_CONFIG_H` is handled that way: both macros are
   defined to the same include so neither core is touched.
4. Write `<core>/root.c`. That is this repository's own code, and it is where a
   core hands over: it fills whichever seam the core calls to get the bootstrap
   helper resident as root, and it answers `payload_default_attempts()`,
   `payload_attempt_timeout_sec()` and `payload_report_root()` from `payload.h`.

Whether that seam is a weak symbol matters. Both cores here stub
`install_embedded_su()` weakly, so a build that fails to provide a strong
definition compiles, links, runs and installs nothing. Check after building —
see step 7.

## 2. Confirm the bug is unfixed in this image

Version numbers are not a usable test on Android branches; a vendor kernel at a
sublevel below the fix can still carry a backport. Disassemble.

For CVE-2026-43499 the shape to look for is `remove_waiter()` operating on
`current` rather than on `waiter->task`, reached from
`rt_mutex_start_proxy_lock()`'s failure path:

```
mrs x20, sp_el0            ; current, not waiter->task
add x21, x20, #<pi_lock>
str xzr, [x20, #<pi_blocked_on>]
```

The same disassembly re-confirms `FAKE_TASK_PI_LOCK_OFF`,
`FAKE_TASK_PI_WAITERS_OFF`, `FAKE_TASK_PI_BLOCKED_ON_OFF` and `WAITER_LOCK_OFF`,
so it is worth doing carefully even when the answer is already known.

## 3. Recover the offsets

The generator belongs with the core's reference, not with this repository. Run it
there and copy its output in verbatim, between markers, with a comment saying
what produced it. Never hand-edit a number inside that block — regenerate.

Two things the MediaTek ports had to learn, both likely to recur:

- The boot image's kernel may not be a raw `Image`. Both MediaTek targets here
  ship it **LZ4-legacy compressed**; the Qualcomm ones did not.
- With no `xbl_config`, `P0_PHYS_OFFSET` comes from the vendor_boot FDT's
  `/memory@…` node rounded down to `ARM64_MEMSTART_ALIGN`, and
  `P0_KERNEL_PHYS_LOAD` from the preloader's own `mb_kernel` reservation — lk
  refuses to boot a kernel placed anywhere else, so that table is authoritative
  rather than indicative.

Only the **delta** `P0_KERNEL_PHYS_LOAD - P0_PHYS_OFFSET` reaches the payload,
through `P0_DATA_ALIAS_CONST()`. Both MediaTek targets measured zero. Measure it
rather than inheriting it.

## 4. Check that a static header is sound

`arm64_memblock_init()` reads `memstart_offset_seed` and will shift
`memstart_addr` by a multiple of 1 GiB, which would make any compiled-in
`P0_PHYS_OFFSET` wrong from one boot to the next. Both targets here are safe for
the same reason, and it is a property of the configuration rather than of the
device: the guard ahead of the shift compares `linear_region_size - BIT(parange)`
against `ARM64_MEMSTART_ALIGN`, and at `VA_BITS=39` with a 48-bit PA that range
is negative, so the randomisation is skipped whatever the seed is.

Confirm this by disassembly on any new device before trusting a static header. A
kernel where it does not hold needs the offset discovered at run time, which is a
different port.

## 5. Write the target's files

```text
src/targets/<device>/<region lowercased>/<kernelRelease>/
    target-<core>.h    the offsets, for the core that reads them
    kernelsu.json      the KernelSU build this target pairs with
    p0_fingerprint.h   only if the core asks for one — core66 does, core612 does not
```

The directory path is derived from `device`, `region` and `kernelRelease` in
`src/targets.json`, so it is never written down twice and the two cannot drift.
`region` is part of the path because the same model and kernel version ship as
different builds per region. The header's name and the root glue the build links
follow `core` for the same reason.

Anything about how the payload is *deployed* rather than about the kernel goes
below the generated block, with a comment: `ROOT_HELPER_PATH` (or core66's
`ROOT_UMH_PATH`), and the two supervisor numbers if this core's defaults do not
suit the device — `PAYLOAD_ATTEMPT_BUDGET` and `PAYLOAD_ATTEMPT_TIMEOUT_SEC`.

Be conservative with both. The supervisor `SIGKILL`s an attempt that overruns,
and the kill lands wherever the attempt happens to be — which, for a core that
swaps its own cred and reloads the SELinux policy, can be halfway through
becoming root. A timeout below what a healthy attempt takes does not detect a
hang, it manufactures one. Raise either only after a retry has been observed to
be safe on that device.

## 6. Add the `src/targets.json` entry

The only hand-authored input. Three kinds of field, and the difference decides
how hard you have to work for each:

- **Matched by the app** — `kernelRelease`, `kernelBuildVersion`, `buildDisplay`,
  `sdk`, `abi`, `pageSize`. A wrong value here means the device silently never
  matches. `buildDisplay` is `ro.build.display.id`, and it is easy to guess
  wrong; read it off the device. Vendors disagree about what to put there:
  OPPO's PMG110 overrides it with its own firmware string
  (`PMG110_16.0.9.400(CN01)`, against ID `BP2A.250605.015`), while Xiaomi's
  warhol leaves it as the platform ID (`BP2A.250605.031.A3`) and shows the
  firmware version through `ro.build.version.incremental` instead. Neither
  half of the fingerprint predicts the other vendor's choice.
- **Device-only** — `kernelVersion` and `kernelBuildVersion` are the kernel's own
  `linux_banner` and `UTS_VERSION`. `adb shell cat /proc/version` prints the
  first and contains the second. Both can be read out of the boot image instead,
  which proves what that image would print and not that it is the slot the device
  boots; prefer the device. A target with `kernelVersion` null still builds and
  is reported, but is left out of the feed.
- **Descriptive** — `manufacturer`, `model`, `marketingName`, `soc`, `region`,
  `status`. Nothing matches on these. `status` is where honesty goes: say which
  parts have run on hardware and which have not, in those words.

Also `payload` and `core`, which select the sources, and `profileId`, which names
the published assets.

Validate before anything else:

```sh
python3 tools/generate_feed.py --emit validate
```

This checks in seconds what no later step can: that the core exists, that its
root glue exists, that the named header is there, that `kernelRelease` and
`kernelBuildVersion` really are substrings of `kernelVersion`, and that the patch
sets a KernelSU build names resolve to directories with patches in them.

## 7. Build and check

```sh
make TARGET=<device>/<region>/<kernelRelease> PAYLOAD=CVE-2026-43499 \
  CORE=<core> ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=… PAYLOAD=… CORE=… release
```

Four checks, each catching something that otherwise fails on the device rather
than in the build:

```sh
out=build/<target with / as _>

# 1. the release payload fits the fixed size the app expects
#    (the Makefile already asserts this, then pads to it)
stat -c %s "$out/cve-2026-43499-app.release.so"

# 2. no undefined symbol outside libc. The app loads the payload with
#    dlopen(RTLD_NOW), so one dangling reference means it never loads at all
readelf --dyn-syms -W "$out/cve-2026-43499-app.release.so" \
  | awk '$7=="UND" && $8!=""{print $8}' | grep -v '@LIBC'

# 3. the strong root glue beat the core's weak stub. A 'W', or a size around
#    0x30, means the stub is what will run and nothing will be installed
llvm-nm -S --defined-only "$out/cve-2026-43499-app.so" | grep install_embedded_su

# 4. nothing device-specific reached the bootstrap helper: one binary serves
#    every target, so every target's build of it must be byte-identical
sha256sum build/*/cve-2026-43499-root
```

## 8. Pair a KernelSU build

`kernelsu.json` names the module this target loads. Targets that load the same
module share one `id` and are built once, so an `id` is a module rather than a
device — two targets that need different modules need different ids.

`kmi` selects which embedded module `ksud` loads at run time and reaches the
device through the feed, so it is a target's property and never a default;
`ddkImage` must be the image for that KMI; `kernelRelease` is the exact UTS
release the module's `vermagic` must claim, which the build stamps over the DDK's
own. `patchSets` names what this build takes on top of `common` — a set that
resolves to no patches fails the build rather than being skipped, so a device
with no vendor hardening names none. It does not name a KernelSU version: the
sets live under `patches/<version>/`, and the version comes from the submodule
pin, not from any target.

CI asserts the two load-time contracts: the module's `vermagic`, and an empty
`__versions` section. It cannot do the audit against the device's own recovered
kernel; that procedure is in
[`../src/kernelsu/README.md`](../src/kernelsu/README.md) and is a manual step.

**A feed-ready target's KernelSU build can stop the release for every target.**
`feed_ready()` is both device-only fields being non-null, and that routes the
build into the job the feed waits on. A port whose module build is not working
yet should leave `kernelVersion` null until it is.

## 9. Do not write the feed

`targets-v2.json` is generated by `tools/generate_feed.py` from
`src/targets.json`, joined with the sizes and URLs of what CI actually built, and
published as a release asset under a tag unique to that run. Nothing about it is
committed, and no artifact is committed either. Adding a target needs no change
to the Makefile or to the workflow — both read the target list.

## 10. Bring it up on the device

Two routes, and they fail differently, so use them in this order.

**The standalone route** first, over `adb`: `LD_PRELOAD` the non-app payload, with
the bootstrap helper staged at the path the target header names. This exercises
the exploit without the application's SELinux domain, allocator history, boot
quiet window or attempt supervisor.

**The application route** second, which is what the feed serves. It is
materially harder, and nothing about the first route proves it. The app refuses
an install unless the exploit log contains both markers:

```sh
adb shell run-as <app package> cat files/exploit.log \
  | grep -E 'exploit completed|done=1 root=1'
```

`exploit completed` is the supervisor's; `done=1 root=1` is
`payload_report_root()`, which every root glue calls and which has to be printed
from inside the attempt, because the supervisor is the parent and nothing about
the attempt's result crosses back to it. A payload that
reaches root but does not print the second is an install the app will reject.

## 11. Say what is true

The `status` field and the port's own notes are read by whoever ports the next
device, and a port that overstates itself costs them a day. Distinguish, in
words: what ran on hardware, what was read out of an image, what was inferred
from a sibling port, and what has never been executed. "The exploit is verified"
and "the exploit is verified through the standalone build, and the app payload
has never run here" are different claims, and only one of them is usually true.
