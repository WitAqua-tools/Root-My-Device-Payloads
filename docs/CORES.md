# Exploit cores

An exploit core is one implementation of the attack chain, and the chain is fixed
to a **GKI branch** rather than to a SoC. A target on a different kernel series
therefore takes a different exploit core — not the same core with different
offsets — and each target names the one it needs in `src/targets.json`.

| Core | Kernel | Route to root |
| --- | --- | --- |
| `core61` | `android14-6.1` | the compatibility route queues a `call_usermodehelper` work item; `RMD_CORE61_DIRECT_CRED_ROUTE` instead patches a private child task/cred and lets that rooted child exec the helper |
| `core66` | `android15-6.6` | the compatibility route uses the core's historical child/root handoff; `RMD_CORE66_TRANSACTIONAL_ROUTE` uses a checked private-credential transaction and the authenticated sealed-helper contract |
| `core612` | `android16-6.12` | swaps the exploit process's own cred and reloads the SELinux policy, then execs the helper directly |
| `core510` | `5.10` — not a GKI branch at all, but Meta's own kernel for Quest 3 | swaps a forked *child*'s cred and clears that child's seccomp filter through the same write; the child execs the helper |

The published implementation each core was written against, with links, is in
[Credits](../README.md#credits).

`core510` is the one core that needs a second binary on the device before it
can reach root: the stamp goes into a compat syscall's stack frame, so that
part runs in a 32-bit process it execs. The stage is built as its own artifact
and also `.incbin`'d back into the payload, because a run started by the
application has nothing to push it with and may not `execve()` a file it wrote
itself — it hands it to bionic's linker instead. It is also the one core whose
KASLR slide does not come from `perf_event_open`: SELinux gives `untrusted_app`
no `perf_event` class, so the slide is read back through a sysctl the exploit's
own write re-points. `CVE43499_SLIDE=perf|stamp|auto` forces either route.

`core66`'s compatibility route and `core612` share `root_helper.c`. Other
handoffs remain in their core's `root.c`.

## What is a core's, and what is this repository's

Each core starts from the implementation named in
[Credits](../README.md#credits). Devices on the same kernel series share it;
exact constants and compile-time capability selections stay in target headers.
Repository-owned integration includes `<core>/root.c`, `mte.c`, `preload.c`
and `payload.h`.

## Shared-core capability routes

Unflagged targets compile the compatibility route. Current opt-ins are:

| Capability | Scope | Meaning |
| --- | --- | --- |
| `RMD_CORE61_DIRECT_CRED_ROUTE` | `core61` | uses the verified direct task/cred handoff and waiter cleanup route |
| `RMD_CORE66_TRANSACTIONAL_ROUTE` | `core66` | uses the checked transactional cleanup/root handoff route |
| `RMD_SUPERVISOR_RETRY_STATE` | shared supervisor | persists one-shot retry state between managed app attempts |
| `RMD_SUPERVISOR_DIRTY_GUARD` | shared supervisor | refuses a new managed attempt after an unsafe partial state |

Capability names describe behavior, not devices. Target-only constants belong
in the target header; build metadata belongs in optional `build.mk`.

## What to check after building

Whichever core a target names, `readelf --dyn-syms` on the built
`*-app.release.so` should report no undefined symbol outside `@LIBC`. Anything
else is a call that will fail at `dlopen` on the device rather than in the
build. The full post-build check list is
[`PORTING.md`](PORTING.md) step 7.

## Adding a core

A new core is added as `src/payloads/<payload>/<core>/`, with the `root.c` beside
it that fills its root seam, and named from a target. Nothing in the Makefile or
the workflow has to learn about it. What each file is for, what not to edit, and
what `root.c` has to answer are
[`PORTING.md`](PORTING.md) step 1.

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

Only `core612` reads it. `core66`'s own knob predates this and stays as it is,
and its one target pins the answer.
