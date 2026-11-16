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


def plan(requested, versions, date, series_count=REPORT_SERIES):
    """Resolve what one rebuild publishes: floating tags only move forward, never to an older patch."""
    if not versions:
        raise ValueError("no stable release tags found")
    if not re.fullmatch(r"\d{8}", date):
        raise ValueError(f"expected a YYYYMMDD date, got {date!r}")
    version = parse_version(requested) if requested else versions[-1]
    if version not in versions:
        raise ValueError(f"{text(version)} is not a released version")
    newest = {}
    for candidate in versions:
        newest[candidate[:2]] = candidate
    series = version[:2]
    name = text(version)
    tags = [name, f"{name}-{date}"]
    if newest[series] == version:
        tags.append(text(series))
    if versions[-1] == version:
        tags.append("latest")
    tags += [f"{tag}-debug" for tag in tags]
    report = [text(newest[key]) for key in sorted(newest, reverse=True)[:series_count]]
    return {
        "version": name,
        "ref": f"v{name}",
        "revision": f"{name}-{date}",
        "tags": tags,
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
    suffix = "-debug" if tag.endswith("-debug") else ""
    version = tag.removesuffix("-debug")
    pattern = re.compile(re.escape(version) + r"-(\d{8})" + re.escape(suffix))
    matches = sorted(name for name in registry_tags if pattern.fullmatch(name))
    return matches[-1] if matches else ""


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
        elif isinstance(value, list):
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
    command.add_argument("--date", required=True, help="YYYYMMDD suffix of the dated tag")
    command.add_argument("--series", type=int, default=REPORT_SERIES)

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
            emit(plan(args.version.strip(), stable_versions(lines), args.date, args.series))
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
