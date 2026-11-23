#!/usr/bin/env python3
"""Plan, gate and report rebuilds of released container images on updated base images."""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SEVERITIES = ("CRITICAL", "HIGH")
STABLE_TAG = re.compile(r"(?:refs/tags/)?v(\d+)\.(\d+)\.(\d+)")
MODES = ("if-needed", "always", "report-only")
WINDOWS_IMAGES = ("windows-2022", "windows-2025", "windows-nano-2025")
REPORT_SERIES = 3


def parse_version(value):
    """Accept only a stable X.Y.Z release, with one optional v prefix."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value or "")
    if not match:
        raise ValueError(f"expected a released version such as 5.2.0, got {value!r}")
    return tuple(int(part) for part in match.groups())


def text(version):
    return ".".join(str(part) for part in version)


def stable_versions(lines):
    """Extract stable release versions from `git ls-remote --tags` output or plain tag names."""
    versions = set()
    for line in lines:
        fields = line.split()
        if not fields or fields[-1].endswith("^{}"):
            continue
        match = STABLE_TAG.fullmatch(fields[-1])
        if match:
            versions.add(tuple(int(part) for part in match.groups()))
    return sorted(versions)


def build_id(date, counter):
    return date if counter == 1 else f"{date}.{counter}"


def builds(version, registry_tags):
    """Build ids published for a version, oldest first. A build id is YYYYMMDD or YYYYMMDD.N."""
    pattern = re.compile(re.escape(version) + r"-(\d{8})(?:\.([1-9]\d*))?")
    found = set()
    for tag in registry_tags:
        match = pattern.fullmatch(tag)
        if match:
            found.add((match.group(1), int(match.group(2) or 1)))
    return [build_id(date, counter) for date, counter in sorted(found)]


def image_tag(image, version, build=""):
    """Tag of one image of a version: production, debug or a Windows image, optionally of one build."""
    base = f"{version}-{build}" if build else version
    if image == "production":
        return base
    return f"{base}-debug" if image == "debug" else f"{image}-{base}"


def resolve(requested, versions):
    if not versions:
        raise ValueError("no stable release tags found")
    version = parse_version(requested) if requested else versions[-1]
    if version not in versions:
        raise ValueError(f"{text(version)} is not a released version")
    return version


def plan(requested, versions, date, registry_tags, original_created="", series_count=REPORT_SERIES):
    """Resolve what one rebuild publishes: floating tags only move forward, never to an older patch.

    Only images the release originally published are rebuilt, older series ship fewer Windows images.
    Every build keeps a dated tag of its own. A registry cannot tell what a tag used to point to, so
    before the version tag moves for the first time the original release gets one from its build date.
    That is requested until a rebuild is published: a run that stopped half way is then completed by
    the next one, which only adds the dated tags that are still missing.
    """
    if not re.fullmatch(r"\d{8}", date):
        raise ValueError(f"expected a YYYYMMDD date, got {date!r}")
    version = resolve(requested, versions)
    newest = {}
    for candidate in versions:
        newest[candidate[:2]] = candidate
    series = version[:2]
    name = text(version)
    missing = [tag for tag in (name, f"{name}-debug") if tag not in registry_tags]
    if missing:
        raise ValueError(f"{name} has no published container images: missing {', '.join(missing)}")
    windows = [prefix for prefix in WINDOWS_IMAGES if f"{prefix}-{name}" in registry_tags]
    published = builds(name, registry_tags)
    if not published:
        if not re.fullmatch(r"\d{8}", original_created):
            raise ValueError(f"expected the YYYYMMDD build date of the published {name} image, "
                             f"got {original_created!r}")
        published = [original_created]
    preserve = []
    if len(published) == 1:  # no rebuild was published yet, the version tags still name the original
        preserve = [{"from": image_tag(image, name), "to": image_tag(image, name, published[0])}
                    for image in ["production", "debug"] + windows]
    counter = 1
    while build_id(date, counter) in published:
        counter += 1
    build = build_id(date, counter)
    tags = [name, f"{name}-{build}"]
    if newest[series] == version:
        tags.append(text(series))
    if versions[-1] == version:
        tags.append("latest")
    tags += [f"{tag}-debug" for tag in tags]
    report = [text(newest[key]) for key in sorted(newest, reverse=True)[:series_count]]
    return {
        "version": name,
        "ref": f"v{name}",
        "build": build,
        "preserve": preserve,
        "tags": tags,
        "windows-images": windows,
        "windows-tags": [f"{prefix}-{name}" for prefix in windows],
        "report-versions": report,
        "report-tags": [tag for item in report for tag in (item, f"{item}-debug")],
    }


def findings(path):
    """Return the HIGH and CRITICAL findings of one Trivy JSON report, split by whether a fix exists."""
    data = json.loads(Path(path).read_text())
    fixable, unfixed = {}, {}
    for result in data.get("Results") or []:
        for item in result.get("Vulnerabilities") or []:
            if item.get("Severity") not in SEVERITIES:
                continue
            entry = {
                "id": item.get("VulnerabilityID", ""),
                "severity": item["Severity"],
                "package": item.get("PkgName", ""),
                "installed": item.get("InstalledVersion", ""),
                "fixed": item.get("FixedVersion", ""),
                "status": item.get("Status", ""),
                "url": item.get("PrimaryURL", ""),
            }
            target = fixable if entry["fixed"] else unfixed
            target[(entry["id"], entry["package"])] = entry
    ordered = [sorted(group.values(), key=lambda entry: (SEVERITIES.index(entry["severity"]),
                                                         entry["id"], entry["package"]))
               for group in (fixable, unfixed)]
    system = (data.get("Metadata") or {}).get("OS") or {}
    return {"fixable": ordered[0], "unfixed": ordered[1],
            "os": " ".join(part for part in (system.get("Family"), system.get("Name")) if part)}


def decide_rebuild(mode, paths):
    count = sum(len(findings(path)["fixable"]) for path in paths)
    return {"fixable": count, "rebuild": mode == "always" or (mode == "if-needed" and count > 0)}


def decide_promote(mode, before, after):
    """Publish only a rebuild that is no worse, and that fixes something unless it was forced."""
    was = sum(len(findings(path)["fixable"]) for path in before)
    now = sum(len(findings(path)["fixable"]) for path in after)
    promote = now <= was and (now < was or mode == "always")
    return {"fixable-before": was, "fixable-after": now, "promote": promote}


def cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def counts(entries):
    return " / ".join(str(sum(1 for entry in entries if entry["severity"] == severity))
                      for severity in SEVERITIES)


def revision_tag(tag, registry_tags):
    """Newest dated tag published for this image; it stays on that build when the plain tag moves."""
    image = "debug" if tag.endswith("-debug") else "production"
    version = tag.removesuffix("-debug")
    for build in reversed(builds(version, registry_tags)):
        if image_tag(image, version, build) in registry_tags:
            return image_tag(image, version, build)
    return ""


def indexed_versions(versions, registry_tags, series_count=REPORT_SERIES):
    """Published releases of the most recent series, newest first, grouped by series."""
    series = sorted({version[:2] for version in versions}, reverse=True)[:series_count]
    return [(key, [version for version in reversed(versions)
                   if version[:2] == key and text(version) in registry_tags]) for key in series]


def version_images(name, registry_tags):
    known = ["production", "debug"] + list(WINDOWS_IMAGES)
    ids = builds(name, registry_tags)
    return [image for image in known
            if any(image_tag(image, name, build) in registry_tags for build in [""] + ids)]


def index_tags(versions, registry_tags, series_count=REPORT_SERIES):
    """Every tag the index needs inspected: each image of each build, and the tags that move."""
    tags = []
    for _, members in indexed_versions(versions, registry_tags, series_count):
        for version in members:
            name = text(version)
            for image in version_images(name, registry_tags):
                for build in [""] + builds(name, registry_tags):
                    if image_tag(image, name, build) in registry_tags:
                        tags.append(image_tag(image, name, build))
    return tags


def inspected(directory, tag):
    """Digest and build date of an inspected tag, or empty strings when it could not be inspected."""
    try:
        data = json.loads((Path(directory) / f"inspect-{tag}.json").read_text())
        return data["Digest"], data["Created"][:10]
    except (OSError, ValueError, KeyError, TypeError):
        return "", ""


def short(digest):
    return f"`{digest.split(':')[-1][:12]}`" if digest else "unavailable"


def render_index(versions, registry_tags, inspect_dir, images, generated, run_url="",
                 series_count=REPORT_SERIES, status_page="Container-Image-Security-Status"):
    source = f"[this workflow run]({run_url})" if run_url else "the image rebuild workflow"
    lines = [
        "# Container images",
        "",
        f"_Generated by {source} on {generated}. Do not edit this page, changes are overwritten._",
        "",
        "Every container image build of the maintained Fluent Bit series. A release is rebuilt on",
        "updated base images when a base image security fix is available, so one version can have",
        "several builds. Images are published as " + " and ".join(f"`{image}`" for image in images) + ".",
        "",
        "- **Tag** moves to the newest build of a version. Pull it again to pick up a rebuild.",
        "- **Dated tag** names one build and never moves. Use it, or the digest, to pin a build.",
        "- **Digest** is shortened here. The full references are listed under each version.",
        "- **Status** is `current` for the build to run. A superseded build has known fixes in a",
        "  newer one.",
        "",
        f"Known vulnerabilities of the current images are listed in [[{status_page}]]. To check",
        "which build is running, compare the digest reported by `docker inspect` or",
        "`kubectl describe pod` with the full references below.",
    ]
    for key, members in indexed_versions(versions, registry_tags, series_count):
        if not members:
            continue
        latest = text(members[0])
        lines += ["", f"## {text(key)}", "",
                  "| Version | Tag | Dated tag | Digest | Built | Build | Status |",
                  "|---|---|---|---|---|---|---|"]
        details = []
        for version in members:
            name = text(version)
            ids = builds(name, registry_tags)
            moving, _ = inspected(inspect_dir, name)
            references = []
            for position, build in enumerate(reversed(ids or [""])):
                tag = image_tag("production", name, build)
                digest, built = inspected(inspect_dir, tag)
                if not built and build:
                    built = f"{build[:4]}-{build[4:6]}-{build[6:8]}"
                newest = position == 0
                if newest and name == latest:
                    status = "current"
                elif newest:
                    status = f"superseded by `{latest}`"
                else:
                    status = f"superseded by `{image_tag('production', name, ids[-1])}`"
                # The version tag is shown on the build it was verified to point to, whichever it is.
                plain = f"`{name}`" if not build or (digest and digest == moving) else "–"
                kind = "release" if not build or build == ids[0] else "rebuild"
                lines.append(f"| {name} | {plain} | {f'`{tag}`' if build else '–'} | {short(digest)} | "
                             f"{built or 'unavailable'} | {kind} | {status} |")
                for image in version_images(name, registry_tags):
                    item = image_tag(image, name, build)
                    if item not in registry_tags:
                        continue
                    full, _ = inspected(inspect_dir, item)
                    reference = f"`{images[0]}@{full}`" if full else "unavailable"
                    references.append(f"| {image} | `{item}` | {reference} |")
            details += ["", f"<details><summary><code>{name}</code>: all images and full digests</summary>",
                        "", "| Image | Tag | Reference |", "|---|---|---|"] + references + ["", "</details>"]
        lines += details
    lines += ["", "Older series are not rebuilt. Their images remain available under their version tags."]
    return "\n".join(lines) + "\n"


def table(entries, fixable):
    last = "Fixed in" if fixable else "Status"
    lines = [f"| CVE | Severity | Package | Installed | {last} |", "|---|---|---|---|---|"]
    for entry in entries:
        identifier = f"[{cell(entry['id'])}]({entry['url']})" if entry["url"] else cell(entry["id"])
        value = entry["fixed"] if fixable else (entry["status"] or "no fix available")
        lines.append(f"| {identifier} | {entry['severity'].lower()} | {cell(entry['package'])} | "
                     f"{cell(entry['installed'])} | {cell(value)} |")
    return lines


def render(tags, scan_dir, registry_tags, images, generated, run_url=""):
    scan_dir = Path(scan_dir)
    source = f"[this workflow run]({run_url})" if run_url else "the image rebuild workflow"
    lines = [
        "# Container image security status",
        "",
        f"_Generated by {source} on {generated}. Do not edit this page, changes are overwritten._",
        "",
        "Released Fluent Bit container images are rebuilt on updated base images when a base image",
        "fix is available, without a new Fluent Bit release. The version tag then moves to the new",
        "build, so pulling the tag again is enough to pick up the fix.",
        "",
        "Images are published as " + " and ".join(f"`{image}`" for image in images) + ".",
        "",
        "Every build of every maintained release is listed in [[Container-Images]].",
        "",
        "## Current images",
        "",
        "| Tag | Built | Dated tag | Digest | Base OS | Fixable critical / high | No fix yet critical / high |",
        "|---|---|---|---|---|---|---|",
    ]
    details = []
    for tag in tags:
        scan = scan_dir / f"trivy-{tag}.json"
        inspect = scan_dir / f"inspect-{tag}.json"
        try:
            result = findings(scan)
            meta = json.loads(inspect.read_text())
            digest, built = meta["Digest"], meta["Created"][:10]
        except (OSError, ValueError, KeyError, TypeError):
            lines.append(f"| `{tag}` | scan unavailable | | | | | |")
            continue
        dated = revision_tag(tag, registry_tags)
        lines.append(f"| `{tag}` | {built} | {f'`{dated}`' if dated else 'original release'} | `{digest}` | "
                     f"{cell(result['os']) or 'unknown'} | {counts(result['fixable'])} | "
                     f"{counts(result['unfixed'])} |")
        total = len(result["fixable"]) + len(result["unfixed"])
        details += ["", f"<details><summary><code>{tag}</code>: {total} findings</summary>", ""]
        if result["fixable"]:
            details += ["Fixable by a rebuild:", ""] + table(result["fixable"], True) + [""]
        else:
            details += ["No fixable critical or high findings.", ""]
        if result["unfixed"]:
            details += ["No fix published by the base image distribution yet:", ""]
            details += table(result["unfixed"], False)
        else:
            details += ["No unfixed critical or high findings."]
        details += ["", "</details>"]
    lines += [
        "",
        "## Reading this page",
        "",
        "- **Built** is the build date of the image the tag points to now.",
        "- **Dated tag** names the same build and never moves to a later one. Use it, or the digest,",
        "  to pin an exact build.",
        "- **Fixable** findings have a fixed package available. A rebuild removes them; if this is",
        "  not zero, please report it.",
        "- **No fix yet** findings have no fixed package from the base image distribution. A rebuild",
        "  cannot remove them, and they are cleared by a later rebuild once a fix is published.",
        "- Findings come from Trivy scanning the `linux/amd64` image for critical and high",
        "  severities. Windows images are rebuilt together with the Linux images but are not scanned.",
        "",
        "## Findings",
    ]
    return "\n".join(lines + details) + "\n"


def emit(values):
    """Write step outputs, encoding lists and booleans the way workflow expressions expect."""
    rendered = []
    for key, value in values.items():
        if isinstance(value, bool):
            value = "true" if value else "false"
        elif isinstance(value, list):  # also lists of objects, for matrices and loops
            value = json.dumps(value, separators=(",", ":"))
        rendered.append(f"{key}={value}")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("\n".join(rendered) + "\n")
    print("\n".join(rendered))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    command = commands.add_parser("plan", help="resolve the version and tags of a rebuild")
    command.add_argument("--version", default="")
    command.add_argument("--tags-file", required=True, help="output of git ls-remote --tags")
    command.add_argument("--registry-tags", required=True, help="output of skopeo list-tags")
    command.add_argument("--date", required=True, help="YYYYMMDD suffix of the dated tag")
    command.add_argument("--original-inspect", default="",
                         help="skopeo inspect output of the published production image")
    command.add_argument("--series", type=int, default=REPORT_SERIES)

    command = commands.add_parser("resolve", help="print the version a rebuild request refers to")
    command.add_argument("--version", default="")
    command.add_argument("--tags-file", required=True)

    command = commands.add_parser("index-tags", help="print the tags the image index needs inspected")
    command.add_argument("--tags-file", required=True)
    command.add_argument("--registry-tags", required=True)

    command = commands.add_parser("index", help="render the wiki index of every published build")
    command.add_argument("--tags-file", required=True)
    command.add_argument("--registry-tags", required=True)
    command.add_argument("--scan-dir", required=True)
    command.add_argument("--image", action="append", required=True)
    command.add_argument("--run-url", default="")
    command.add_argument("--output", required=True)

    command = commands.add_parser("decide-rebuild", help="check whether published images need a rebuild")
    command.add_argument("--mode", choices=MODES, required=True)
    command.add_argument("scans", nargs="+")

    command = commands.add_parser("decide-promote", help="check whether rebuilt images may be published")
    command.add_argument("--mode", choices=MODES, required=True)
    command.add_argument("--before", nargs="+", required=True)
    command.add_argument("--after", nargs="+", required=True)

    command = commands.add_parser("report", help="render the wiki page from scans of published images")
    command.add_argument("--tags", nargs="+", required=True)
    command.add_argument("--scan-dir", required=True)
    command.add_argument("--registry-tags", required=True, help="output of skopeo list-tags")
    command.add_argument("--image", action="append", required=True)
    command.add_argument("--run-url", default="")
    command.add_argument("--output", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            lines = Path(args.tags_file).read_text().splitlines()
            registry_tags = json.loads(Path(args.registry_tags).read_text())["Tags"]
            created = ""
            if args.original_inspect:
                try:
                    created = json.loads(Path(args.original_inspect).read_text())["Created"][:10]
                except (OSError, ValueError, KeyError, TypeError):
                    created = ""
            emit(plan(args.version.strip(), stable_versions(lines), args.date, registry_tags,
                      created.replace("-", ""), args.series))
        elif args.command == "resolve":
            lines = Path(args.tags_file).read_text().splitlines()
            print(text(resolve(args.version.strip(), stable_versions(lines))))
        elif args.command in ("index-tags", "index"):
            versions = stable_versions(Path(args.tags_file).read_text().splitlines())
            registry_tags = json.loads(Path(args.registry_tags).read_text())["Tags"]
            if args.command == "index-tags":
                print("\n".join(index_tags(versions, registry_tags)))
            else:
                generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
                page = render_index(versions, registry_tags, args.scan_dir, args.image, generated, args.run_url)
                Path(args.output).write_text(page)
        elif args.command == "decide-rebuild":
            emit(decide_rebuild(args.mode, args.scans))
        elif args.command == "decide-promote":
            emit(decide_promote(args.mode, args.before, args.after))
        else:
            registry_tags = json.loads(Path(args.registry_tags).read_text())["Tags"]
            generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            page = render(args.tags, args.scan_dir, registry_tags, args.image, generated, args.run_url)
            Path(args.output).write_text(page)
    except (OSError, ValueError, KeyError) as error:
        print(f"::error::{error}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
