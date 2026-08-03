#!/usr/bin/env python3
"""Read src/targets.json and emit what the build needs from it.

Targets are hand-authored; artifacts are not. A target's URL and exact size are
only knowable after CI has built it, so this script owns the join between the
two halves and is the single place that knows how a target maps onto a path:

    src/targets/<device>/<region lowercased>/<kernelRelease>/

Modes:
    --emit validate        check the hand-authored sources, build nothing
    --emit plan            the build matrices, narrowed by --changed-file
    --emit kernel-modules  the matrix for the modules built from a kernel source
    --emit feed            the targets-v2.json the app reads (needs built artifacts)
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

FEED_SCHEMA_VERSION = 2
SOURCE_SCHEMA_VERSION = 1

# Mirrors SupportManifest.parse on the app side. A field the app reads but the
# feed omits is a crash on the device, so the two lists must stay together.
FEED_FIELDS = [
    "profileId",
    "manufacturer",
    "model",
    "device",
    "kernelRelease",
    "kernelVersion",
    "kernelBuildVersion",
    "buildDisplay",
    "buildFingerprint",
    "sdk",
    "abi",
    "pageSize",
]

# Present in src/targets.json for the repository's own organisation and for the
# README table. They are not part of feed schema 2, so the app never sees them.
SOURCE_ONLY_FIELDS = ["payload", "core", "region", "marketingName", "soc", "status"]

REQUIRED_FIELDS = FEED_FIELDS + ["payload", "core", "region"]

FIELD_TYPES = {"sdk": int, "pageSize": int}

# Captured from a running device, not derivable from a firmware image.
DEVICE_ONLY_FIELDS = ["kernelVersion", "kernelBuildVersion"]

# Where the KernelSU patch sets live. A kernelsu.json names the ones its build
# takes on top of common, as directory names under patches/<version>/ -- see
# patch_sets_dir for where the version comes from.
PATCHES_DIR = Path("src/kernelsu/Root-My-Device-KSU/patches")
KERNELSU_DIR = Path("src/kernelsu/KernelSU")

# The one manager every target pairs with. Not a per-target choice: which
# manager a device gets is not a property of the device, and the modules are
# built to accept this one and no other.
MANAGER_FILE = Path("src/kernelsu/manager.json")

# What the module can physically read. kernel/manager/apk_sign.c reads the
# manager certificate into a fixed 1024-byte buffer before hashing it, and
# refuses anything longer -- so a longer certificate is never compared against
# the hash at all, and on a device that is is_manager: 0 and nothing else. The
# first key used here was RSA-4096 at 1316 bytes and no module ever recognised
# the manager it signed.
CERT_MAX_LENGTH = 1024

# The device's own /proc/config.gz, decompressed so it can be read and diffed,
# beside the kernelsu.json that names a kernelSource. Always this name, so it is
# not a key anything can get wrong.
KERNEL_CONFIG_NAME = "kernel.config"


def git_output(repository: Path, *arguments: str) -> str | None:
    """One git command's stdout, or None if git could not answer.

    A working copy without the submodules is a normal thing to run this from,
    so an unanswerable question is not by itself a problem here -- the build
    action fails on the same conditions, loudly, where it matters.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() or None


def kernelsu_repo(root: Path) -> Path | None:
    """The KernelSU submodule, but only if git answers *for it*.

    An uninitialised submodule is an empty directory inside this repository, and
    `git -C` in one walks up and answers for the parent -- so the count would be
    this repository's, and the feed would publish a KernelSU version that is
    really the payload repo's commit count. kernel/Kbuild guards the same way,
    comparing its own toplevel against the kernel tree's.
    """
    kernelsu = root / KERNELSU_DIR
    toplevel = git_output(kernelsu, "rev-parse", "--show-toplevel")
    if toplevel is None:
        return None
    try:
        if Path(toplevel).resolve() != kernelsu.resolve():
            return None
    except OSError:
        return None
    return kernelsu


def kernelsu_version(root: Path) -> int | None:
    """KernelSU's own version number for the pinned submodule.

    30000 + the commit count, the same expression kernel/Kbuild compiles into
    KSU_VERSION, which is also the manager's versionCode and the number the
    module reports at run time. Nothing writes it down; every place that needs
    it derives it from the pin, so they cannot disagree.

    None when the submodule is not checked out, or when the checkout is shallow
    and its count means nothing.
    """
    kernelsu = kernelsu_repo(root)
    if kernelsu is None:
        return None
    count = git_output(kernelsu, "rev-list", "--count", "HEAD")
    if count is None or not count.isdigit() or int(count) < 2:
        return None
    return 30000 + int(count)


def manager(root: Path) -> dict:
    """src/kernelsu/manager.json, as written."""
    return json.loads((root / MANAGER_FILE).read_text(encoding="utf-8"))


def kernelsu_manager(root: Path) -> dict | None:
    """What the feed says about the manager, for every entry.

    It belongs beside the module in each entry rather than at the top of the
    document, because it describes what that module pairs with, and a feed that
    some day carries two KernelSU builds would need it per entry anyway.

    None when the pinned version cannot be read, because the version is half of
    what the manager is.
    """
    version = kernelsu_version(root)
    if version is None:
        return None
    document = manager(root)
    return {
        "managerPackage": document["package"],
        "managerVersionCode": version,
        "managerVersionName": f"{version} ({document['name']})",
        "managerUrl": document["url"],
        # Always. There is no build here that pairs with upstream's manager,
        # so the application has nothing to decide and every entry says so.
        "managerCustom": True,
        "managerNote": document["note"],
    }


def patch_sets_dir(root: Path) -> Path | None:
    """patches/<version> for the pinned KernelSU, or None if it cannot be read.

    The build action derives the same directory the same way, so the sets a
    build applies and the tree it applies them to cannot come apart.
    """
    version = kernelsu_version(root)
    if version is None:
        return None
    return root / PATCHES_DIR / str(version)


class Problems:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def add(self, message: str) -> None:
        self.messages.append(message)
        print(f"  {message}", file=sys.stderr)

    def __bool__(self) -> bool:
        return bool(self.messages)


def target_path(targets_dir: Path, target: dict) -> Path:
    return targets_dir / target["device"] / target["region"].lower() / target["kernelRelease"]


def target_key(target: dict) -> str:
    """The TARGET= value the Makefile takes, and the target's identity."""
    return f"{target['device']}/{target['region'].lower()}/{target['kernelRelease']}"


def target_header_name(target: dict) -> str:
    """The header the Makefile reads for this target, which follows its core."""
    return f"target-{target['core']}.h"


def exploit_asset_name(target: dict) -> str:
    return f"{target['payload'].lower()}-app-{target['profileId']}.so"


def check_manager_file(root: Path, problems: Problems) -> None:
    """The one manager, and whether it is the one the pin implies.

    The manager and the module carry the same number and the manager refuses a
    module below its own MINIMAL_SUPPORTED_KERNEL, so a pin move that is not
    followed by a manager release leaves the feed sending people to a manager
    that will not talk to what they just installed. The version is not written
    in the file -- it is derived from the pin like everywhere else -- so the one
    thing that can disagree is the URL, and that is what is checked.
    """
    label = str(MANAGER_FILE)
    try:
        document = manager(root)
    except (OSError, ValueError) as error:
        problems.add(f"{label}: cannot be read ({error})")
        return

    unknown = set(document) - {"package", "name", "url", "note", "signature", "$comment"}
    if unknown:
        problems.add(f"{label}: unknown key(s) {sorted(unknown)}")
    for field in ("package", "name", "url", "note"):
        if not isinstance(document.get(field), str) or not document[field]:
            problems.add(f"{label}: {field} must be a non-empty string")
    url = document.get("url")
    if isinstance(url, str) and not url.startswith("https://"):
        problems.add(f"{label}: url must be https, got {url!r}")

    signature = document.get("signature")
    if not isinstance(signature, dict) or set(signature) - {"size", "hash"}:
        problems.add(f"{label}: signature must be an object of size and hash")
    else:
        size = str(signature.get("size"))
        if not re.fullmatch(r"0x[0-9a-f]{4}", size):
            problems.add(f"{label}: signature.size must look like 0x0324, got {signature.get('size')!r}")
        elif int(size, 16) > CERT_MAX_LENGTH:
            problems.add(
                f"{label}: signature.size is {int(size, 16)} bytes, past the "
                f"{CERT_MAX_LENGTH} a module can read; no module would ever "
                "recognise a manager signed with that certificate"
            )
        if not re.fullmatch(r"[0-9a-f]{64}", str(signature.get("hash"))):
            problems.add(f"{label}: signature.hash must be a lowercase sha256")

    version = kernelsu_version(root)
    if version is not None and isinstance(url, str) and str(version) not in url:
        problems.add(
            f"{label}: url does not mention KernelSU {version}, which the pin says "
            "the modules will be; release a manager from Root-My-Device-KSU first"
        )


def check_no_target_manager(label: str, build: dict, problems: Problems) -> None:
    """A kernelsu.json that still picks its own manager.

    It used to. There is one manager now and it is not a property of a target,
    so a leftover key here is not a thing to ignore -- it is someone's intent
    that would silently not happen.
    """
    stale = {"manager", "managerSignature", "managerPackage"} & set(build)
    if stale:
        problems.add(
            f"{label}: kernelsu.json still has {sorted(stale)}; the manager is "
            f"one file now, {MANAGER_FILE}"
        )


KERNEL_SOURCE_KEYS = {"repo", "ref", "commit", "subject", "clang"}


def check_kernel_source(label: str, build: dict, directory: Path, problems: Problems) -> None:
    """The device's own kernel, for a target the DDK image cannot stand in for.

    This is what the kernel-module workflow builds, and it is paired with
    prebuiltModule in both directions on purpose. A kernelSource with nothing
    referencing its result is a ten-minute build nothing consumes; a
    prebuiltModule with no kernelSource is a URL with no recipe behind it, which
    is what this used to be when the recipe lived in another repository.
    """
    source = build.get("kernelSource")
    prebuilt = build.get("prebuiltModule")

    if source is None:
        if prebuilt is not None:
            problems.add(
                f"{label}: kernelsu.json names a prebuiltModule but no kernelSource, "
                "so nothing here says how that module was built"
            )
        return
    if prebuilt is None:
        problems.add(
            f"{label}: kernelsu.json names a kernelSource but no prebuiltModule, "
            "so nothing would use the module it builds"
        )

    if not isinstance(source, dict):
        problems.add(f"{label}: kernelsu.json kernelSource must be an object")
        return
    unknown = set(source) - KERNEL_SOURCE_KEYS - {"$comment"}
    if unknown:
        problems.add(f"{label}: kernelsu.json kernelSource has unknown key(s) {sorted(unknown)}")
    missing = sorted(KERNEL_SOURCE_KEYS - set(source))
    if missing:
        problems.add(f"{label}: kernelsu.json kernelSource is missing {missing}")
        return

    repo = source["repo"]
    if not isinstance(repo, str) or not repo.startswith("https://"):
        problems.add(f"{label}: kernelSource.repo must be https, got {repo!r}")
    # A branch that moves is a different kernel, so the commit is what is
    # fetched and ref is only there to say where to look for it.
    commit = source["commit"]
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        problems.add(f"{label}: kernelSource.commit must be a full sha, got {commit!r}")
    for field in ("ref", "subject", "clang"):
        if not isinstance(source[field], str) or not source[field]:
            problems.add(f"{label}: kernelSource.{field} must be a non-empty string")

    # The device's own /proc/config.gz, beside the file that names it. Not a
    # defconfig: being close to what the device runs is the entire reason this
    # target is not built in a DDK image.
    if not (directory / KERNEL_CONFIG_NAME).is_file():
        problems.add(f"{label}: kernelSource needs {directory / KERNEL_CONFIG_NAME}")


def check_prebuilt_module(label: str, build: dict, problems: Problems) -> None:
    """A module built ahead of the payload build, named by digest.

    A DDK image is a stand-in for a device's kernel, and for some devices it is
    not a good enough one -- close enough to build and link, not close enough to
    load. Those targets have their module built from the device's own kernel
    source by the kernel-module workflow, which publishes it, and name the
    result here. The digest is not optional: it is the whole difference between
    referencing a build and trusting a URL.
    """
    prebuilt = build.get("prebuiltModule")
    if prebuilt is None:
        return
    if not isinstance(prebuilt, dict) or set(prebuilt) - {"url", "sha256", "$comment"}:
        problems.add(f"{label}: kernelsu.json prebuiltModule must be an object of url and sha256")
        return
    url, digest = prebuilt.get("url"), prebuilt.get("sha256")
    if not isinstance(url, str) or not url.startswith("https://"):
        problems.add(f"{label}: prebuiltModule.url must be https, got {url!r}")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        problems.add(f"{label}: prebuiltModule.sha256 must be a lowercase sha256, got {digest!r}")


def ksud_asset_name(build_id: str) -> str:
    return f"ksud-{build_id}"


def download_url(repository: str, tag: str, name: str) -> str:
    return f"https://github.com/{repository}/releases/download/{tag}/{name}"


def check_patch_sets(root: Path, label: str, build: dict, problems: Problems) -> None:
    """Check the KernelSU patch sets a build names on top of common.

    The build action fails on a set it cannot find, which is where a wrong name
    really matters; this is what makes the same mistake fail in seconds, before
    a matrix of kernel builds. CI checks the patch submodule out for exactly
    that reason, but a working copy without it is a normal thing to run this
    from, so an absent patches/<version>/ is not itself a problem.
    """
    sets = build.get("patchSets", [])
    if not isinstance(sets, list) or not all(isinstance(name, str) for name in sets):
        problems.add(f"{label}: kernelsu.json patchSets must be a list of strings")
        return

    patches = patch_sets_dir(root)
    for name in sets:
        if name == "common":
            problems.add(f"{label}: patchSets names 'common', which every build takes anyway")
            continue
        # The action takes these space-separated, and resolves each under the
        # version directory, so neither a name with a space in it nor one that
        # climbs out of that directory is a set it could apply. A version is
        # not one of them either: the pin picks that, so a name that looks like
        # one is a set nothing will find.
        if not name or any(character.isspace() for character in name):
            problems.add(f"{label}: patch set {name!r} is not a usable directory name")
            continue
        if name.startswith("/") or ".." in Path(name).parts:
            problems.add(f"{label}: patch set {name!r} points outside {PATCHES_DIR}")
            continue
        if patches is not None and patches.is_dir() and not any((patches / name).glob("*.patch")):
            problems.add(
                f"{label}: patch set {name!r} has no patches at "
                f"{patches.relative_to(root) / name}"
            )


def load_sources(root: Path, problems: Problems) -> list[dict]:
    document = json.loads((root / "src/targets.json").read_text(encoding="utf-8"))
    if document.get("schemaVersion") != SOURCE_SCHEMA_VERSION:
        problems.add(f"src/targets.json: unsupported schemaVersion {document.get('schemaVersion')}")
        return []

    targets_dir = root / "src/targets"
    payloads_dir = root / "src/payloads"
    loaded = []
    seen: set[str] = set()

    for target in document["targets"]:
        label = target.get("profileId", "<no profileId>")

        missing = [field for field in REQUIRED_FIELDS if field not in target]
        if missing:
            problems.add(f"{label}: missing {missing}")
            continue
        if label in seen:
            problems.add(f"{label}: duplicate profileId")
        seen.add(label)

        for field, expected in FIELD_TYPES.items():
            if not isinstance(target[field], expected):
                problems.add(
                    f"{label}: {field} must be {expected.__name__}, "
                    f"got {type(target[field]).__name__}"
                )

        payload_dir = payloads_dir / target["payload"]
        if not payload_dir.is_dir():
            problems.add(f"{label}: payload {target['payload']!r} has no src/payloads directory")
            continue
        # A core is a whole exploit tree pinned to a GKI branch, not a set of
        # offsets, and the glue that fills its root seam lives inside it as
        # root.c -- the one file there this repository wrote. Both are checked
        # here so naming a core that does not exist fails in seconds rather
        # than inside a compile of the payload.
        core_dir = payload_dir / target["core"]
        root_glue = core_dir / "root.c"
        for path in (core_dir, root_glue):
            if not path.exists():
                problems.add(f"{label}: core {target['core']!r} has no {path}")
        if not core_dir.is_dir() or not root_glue.is_file():
            continue

        directory = target_path(targets_dir, target)
        if not directory.is_dir():
            problems.add(f"{label}: {directory} is missing")
            continue
        # A core reads offsets the other has never heard of, so which header
        # the build reads follows the core rather than being any header here.
        header = directory / target_header_name(target)
        if not header.is_file():
            problems.add(f"{label}: {header} is missing")
            continue

        kernelsu_path = directory / "kernelsu.json"
        if not kernelsu_path.is_file():
            problems.add(f"{label}: {kernelsu_path} is missing")
            continue
        target["_kernelsu"] = json.loads(kernelsu_path.read_text(encoding="utf-8"))
        target["_dir"] = directory
        check_patch_sets(root, label, target["_kernelsu"], problems)
        check_no_target_manager(label, target["_kernelsu"], problems)
        check_prebuilt_module(label, target["_kernelsu"], problems)
        check_kernel_source(label, target["_kernelsu"], directory, problems)

        # The app matches kernelRelease and kernelBuildVersion separately but
        # both are read off the same /proc/version line. If either is not
        # actually part of the recorded line, the two predicates disagree and a
        # device that should match silently will not.
        if all(target.get(field) for field in DEVICE_ONLY_FIELDS):
            for field in ("kernelRelease", "kernelBuildVersion"):
                if target[field] not in target["kernelVersion"]:
                    problems.add(f"{label}: {field} is not present in kernelVersion")

        loaded.append(target)

    return loaded


def feed_ready(target: dict) -> bool:
    return all(target.get(field) for field in DEVICE_ONLY_FIELDS)


def kernelsu_builds(targets: list[dict], problems: Problems) -> list[dict]:
    """The KernelSU build matrix: one entry per id, however many targets take it."""
    builds: dict[str, dict] = {}
    for target in targets:
        build = dict(target["_kernelsu"])
        build.pop("$comment", None)
        # A build that names no patch set is still a build: the action always
        # applies common, and the workflow joins this into one of its inputs.
        build.setdefault("patchSets", [])
        existing = builds.get(build["id"])
        if existing is None:
            builds[build["id"]] = build | {"feed": False}
        elif {key: value for key, value in existing.items() if key != "feed"} != build:
            # One id is one module, built once. Two targets that describe it
            # differently -- a patch set one takes and the other does not, most
            # likely -- would silently get whichever was read first, so say so
            # instead. What they want is separate ids.
            problems.add(
                f"{target['profileId']}: build id {build['id']!r} is described "
                "differently by another target"
            )
        # Whether anything that can reach the feed depends on this build, which
        # is what decides if a failure to produce it can hold up a release.
        if feed_ready(target):
            builds[build["id"]]["feed"] = True
    return list(builds.values())


def read_changed(path: Path | None) -> list[str] | None:
    """The changed paths to narrow a build to, or None for 'do not narrow'.

    A hand-started run passes nothing and builds everything. A push passes what
    it changed, and an empty list then means a push that touched nothing this
    repository builds from -- which is a build of nothing, not a build of
    everything, so it stays a list.
    """
    if path is None:
        return None
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def affected_targets(targets: list[dict], changed: list[str]) -> list[dict] | None:
    """The targets those changed paths can affect, or None for 'all of them'.

    All of them is the default answer and not a fallback. A target's own
    directory and its payload's are the only two places a change is provably
    confined to; the Makefile, the tools, a workflow, a submodule pin and
    src/targets.json can each change every artifact, and answering otherwise
    would publish a stale one.

    Every target here shares one payload and differs by core, so core is where
    the granularity has to be: a change under src/payloads/<payload>/<core>/
    reaches the targets on that core and no others, and one directly under the
    payload reaches all of them.
    """
    payloads = {target["payload"] for target in targets}
    selected: dict[str, dict] = {}
    for path in changed:
        parts = PurePosixPath(path).parts
        if parts[:2] == ("src", "targets"):
            hits = [t for t in targets if path.startswith(f"{t['_dir']}/")]
        elif parts[:2] == ("src", "payloads") and len(parts) > 2 and parts[2] in payloads:
            same_payload = [t for t in targets if t["payload"] == parts[2]]
            cores = {t["core"] for t in same_payload}
            if len(parts) > 3 and parts[3] in cores:
                hits = [t for t in same_payload if t["core"] == parts[3]]
            else:
                hits = same_payload
        else:
            return None
        for target in hits:
            selected[target["profileId"]] = target
    return list(selected.values())


def kernel_module_builds(root: Path, targets: list[dict]) -> list[dict]:
    """The matrix for the kernel-module workflow: the builds that need a kernel.

    Flat, and named the way the workflow reads them, so that adding a target
    whose module has to come from source is a kernelsu.json and a config.gz and
    no workflow change. One entry per build id, like kernelsu_builds -- the
    disagreement between two targets describing one id differently is caught
    there, before this runs.
    """
    document = manager(root)
    builds: dict[str, dict] = {}
    for target in targets:
        kernelsu = target["_kernelsu"]
        source = kernelsu.get("kernelSource")
        if source is None or kernelsu["id"] in builds:
            continue
        builds[kernelsu["id"]] = {
            "id": kernelsu["id"],
            "dir": str(target["_dir"]),
            "kernelRelease": kernelsu["kernelRelease"],
            "image": kernelsu["ddkImage"],
            "clang": source["clang"],
            "repo": source["repo"],
            "commit": source["commit"],
            "patchSets": " ".join(kernelsu.get("patchSets", [])),
            "managerPackage": document["package"],
            "sigSize": document["signature"]["size"],
            "sigHash": document["signature"]["hash"],
        }
    return list(builds.values())


def report_pending(targets: list[dict]) -> None:
    for target in targets:
        if not feed_ready(target):
            print(
                f"::warning::{target['profileId']} has no {' / '.join(DEVICE_ONLY_FIELDS)} "
                "and is left out of the feed. Capture them from the device with "
                "`adb shell cat /proc/version`."
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--emit",
                        choices=["validate", "plan", "kernel-modules", "feed"],
                        default="feed")
    parser.add_argument("--changed-file", type=Path,
                        help="file of changed paths, one per line, to narrow --emit plan to")
    parser.add_argument("--only", help="one profileId to narrow --emit plan to, instead")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--exploit-dir", type=Path)
    parser.add_argument("--ksud-dir", type=Path)
    parser.add_argument("--repository", help="owner/repo the release lives in")
    parser.add_argument("--tag", help="release tag the assets are published under")
    parser.add_argument("--output", type=Path, default=Path("support/targets-v2.json"))
    args = parser.parse_args()

    if args.emit == "feed":
        required = ["exploit_dir", "ksud_dir", "repository", "tag"]
        missing = [f"--{name.replace('_', '-')}" for name in required if not getattr(args, name)]
        if missing:
            parser.error(f"{', '.join(missing)} are required for --emit feed")

    problems = Problems()
    check_manager_file(args.root, problems)
    targets = load_sources(args.root, problems)
    if not targets and not problems:
        problems.add("src/targets.json declares no targets")
    if problems:
        print(f"{len(problems.messages)} problem(s) in src/targets.json", file=sys.stderr)
        return 1

    # Not only for --emit kernelsu: a target and the module it loads are
    # hand-authored together, so a disagreement between them belongs to the
    # check that runs before anything is built.
    builds = kernelsu_builds(targets, problems)
    if problems:
        print(f"{len(problems.messages)} problem(s) in the KernelSU builds", file=sys.stderr)
        return 1

    if args.emit == "validate":
        report_pending(targets)
        ready = [t for t in targets if feed_ready(t)]
        print(
            f"{len(targets)} target(s) validated, {len(ready)} ready for the feed, "
            f"{len(builds)} KernelSU build(s), "
            f"{len(kernel_module_builds(args.root, targets))} of them from a kernel source"
        )
        return 0

    if args.emit == "plan":
        # Narrowed or not, and both matrices, in one object -- because whether
        # the selection is everything is what decides if a feed can be built
        # from it at all, and that answer has to travel with the matrices
        # rather than be re-derived from their lengths.
        if args.only:
            chosen = [t for t in targets if t["profileId"] == args.only]
            if not chosen:
                print(f"no target called {args.only!r}", file=sys.stderr)
                return 1
        else:
            changed = read_changed(args.changed_file)
            scope = None if changed is None else affected_targets(targets, changed)
            chosen = targets if scope is None else scope
        # Every target, however it got there. A change to a file the whole
        # payload shares narrows to nothing in practice, and a feed can be
        # built from that run as well as from an unnarrowed one.
        full = len(chosen) == len(targets)
        ids = {t["_kernelsu"]["id"] for t in chosen}
        document = manager(args.root)
        print(json.dumps(
            {
                "full": full,
                # One manager, so it is not in either matrix: the workflow reads
                # it once and passes the same three values to every build.
                "managerPackage": document["package"],
                "managerSignatureSize": document["signature"]["size"],
                "managerSignatureHash": document["signature"]["hash"],
                "targets": [
                    {
                        "profileId": t["profileId"],
                        "target": target_key(t),
                        "payload": t["payload"],
                        "core": t["core"],
                        "asset": exploit_asset_name(t),
                    }
                    for t in chosen
                ],
                # Still split by whether anything publishable depends on them,
                # and still deduplicated across every target rather than only
                # the chosen ones, so a narrowed run builds the same module a
                # full one would.
                "kernelsuFeed": [b for b in builds if b["feed"] and b["id"] in ids],
                "kernelsuExtra": [b for b in builds if not b["feed"] and b["id"] in ids],
            },
            separators=(",", ":"),
        ))
        return 0

    if args.emit == "kernel-modules":
        print(json.dumps(kernel_module_builds(args.root, targets), separators=(",", ":")))
        return 0

    report_pending(targets)

    # One pin, so one manager for every entry -- but it belongs beside the
    # module in each entry rather than at the top of the document, because it
    # describes what that module pairs with, and a feed that some day carries
    # two KernelSU builds would need it per entry anyway.
    feed_manager = kernelsu_manager(args.root)
    if feed_manager is None:
        # A feed with no entries is a valid thing to publish while every port
        # is still in progress, and it names no module, so it needs no manager
        # either. Only an entry does.
        if any(feed_ready(target) for target in targets):
            print(
                "cannot read the pinned KernelSU version, so the feed cannot say "
                "which manager its modules pair with; check out "
                "src/kernelsu/KernelSU with full history",
                file=sys.stderr,
            )
            return 1
        feed_manager = {}
    else:
        print(
            f"KernelSU manager: {feed_manager['managerVersionName']} "
            f"({feed_manager['managerVersionCode']}) -> {feed_manager['managerUrl']}"
        )

    entries = []
    for target in targets:
        if not feed_ready(target):
            continue
        label = target["profileId"]
        build = target["_kernelsu"]

        exploit_name = exploit_asset_name(target)
        ksud_name = ksud_asset_name(build["id"])
        exploit = args.exploit_dir / exploit_name
        ksud = args.ksud_dir / ksud_name
        for path in (exploit, ksud):
            if not path.is_file():
                problems.add(f"{label}: {path} is missing")
            elif path.stat().st_size == 0:
                problems.add(f"{label}: {path} is empty")
        if problems:
            continue

        entry = {field: target[field] for field in FEED_FIELDS}
        entry["exploit"] = {
            "url": download_url(args.repository, args.tag, exploit_name),
            "size": exploit.stat().st_size,
        }
        entry["kernelsu"] = {
            "url": download_url(args.repository, args.tag, ksud_name),
            "size": ksud.stat().st_size,
            "kmi": build["kmi"],
        } | feed_manager
        entries.append(entry)

    if problems:
        print(f"{len(problems.messages)} problem(s) building the feed", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps({"schemaVersion": FEED_SCHEMA_VERSION, "targets": entries}, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"wrote {args.output} with {len(entries)} profile(s) at tag {args.tag}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
