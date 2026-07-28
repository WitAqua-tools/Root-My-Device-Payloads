#!/usr/bin/env python3
"""Read src/targets.json and emit what the build needs from it.

Targets are hand-authored; artifacts are not. A target's URL and exact size are
only knowable after CI has built it, so this script owns the join between the
two halves and is the single place that knows how a target maps onto a path:

    src/targets/<device>/<region lowercased>/<kernelRelease>/

Modes:
    --emit validate   check the hand-authored sources, build nothing
    --emit targets    the exploit build matrix
    --emit kernelsu   the KernelSU build matrix, deduplicated by id
    --emit feed       the targets-v2.json the app reads (needs built artifacts)
"""

import argparse
import json
import sys
from pathlib import Path

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
# takes on top of common, as directory names under this.
PATCH_SETS_DIR = Path("src/kernelsu/Root-My-Device-KSU/patches")


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
    from, so an absent patches/ is not itself a problem.
    """
    sets = build.get("patchSets", [])
    if not isinstance(sets, list) or not all(isinstance(name, str) for name in sets):
        problems.add(f"{label}: kernelsu.json patchSets must be a list of strings")
        return

    patches = root / PATCH_SETS_DIR
    for name in sets:
        if name == "common":
            problems.add(f"{label}: patchSets names 'common', which every build takes anyway")
            continue
        # The action takes these space-separated, and resolves each under
        # patches/, so neither a name with a space in it nor one that climbs out
        # of that directory is a set it could apply.
        if not name or any(character.isspace() for character in name):
            problems.add(f"{label}: patch set {name!r} is not a usable directory name")
            continue
        if name.startswith("/") or ".." in Path(name).parts:
            problems.add(f"{label}: patch set {name!r} points outside {PATCH_SETS_DIR}")
            continue
        if patches.is_dir() and not any((patches / name).glob("*.patch")):
            problems.add(f"{label}: patch set {name!r} has no patches at {PATCH_SETS_DIR / name}")


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
    parser.add_argument("--emit", choices=["validate", "targets", "kernelsu", "feed"],
                        default="feed")
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
            f"{len(builds)} KernelSU build(s)"
        )
        return 0

    if args.emit == "targets":
        print(json.dumps(
            [
                {
                    "profileId": t["profileId"],
                    "target": target_key(t),
                    "payload": t["payload"],
                    "core": t["core"],
                    "asset": exploit_asset_name(t),
                }
                for t in targets
            ],
            separators=(",", ":"),
        ))
        return 0

    if args.emit == "kernelsu":
        print(json.dumps(builds, separators=(",", ":")))
        return 0

    report_pending(targets)
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
            "managerPackage": build["managerPackage"],
        }
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
