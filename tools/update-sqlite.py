#!/usr/bin/env python3
"""Prepare the bundled SQLite library on demand.

Usage: python3 tools/update-sqlite.py VERSION
       python3 tools/update-sqlite.py --check

Updating requires Python 3, a C compiler, make, and tclsh on a Unix host.
CMake builds use committed sources without downloads or SQLite generators.
New versions are selected explicitly and must be listed on sqlite.org/download.html.
The recorded archive URLs and SHA3-256 hashes allow --check to reproduce an older
bundle after it leaves the download page. --check never changes the checkout.
"""

import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


REPOSITORY = Path(__file__).resolve().parents[1]
BUNDLE = REPOSITORY / "lib" / "sqlite"
DOWNLOAD_PAGE = "https://www.sqlite.org/download.html"


def version_number(version):
    if not re.fullmatch(r"3\.\d{1,2}\.\d{1,2}(?:\.\d{1,2})?", version):
        raise ValueError("expected a SQLite version such as 3.54.1")
    parts = [int(part) for part in version.split(".")]
    parts += [0] * (4 - len(parts))
    return parts[0] * 1000000 + parts[1] * 10000 + parts[2] * 100 + parts[3]


def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def release_metadata(version):
    number = version_number(version)
    products = {}
    for line in fetch(DOWNLOAD_PAGE).decode("utf-8").splitlines():
        if not line.startswith("PRODUCT,"):
            continue
        row = next(csv.reader([line]))
        if len(row) < 5 or row[1] != version:
            continue
        for kind in ("src", "amalgamation"):
            if row[2].endswith(f"/sqlite-{kind}-{number}.zip"):
                products[kind] = {
                    "url": "https://www.sqlite.org/" + row[2],
                    "sha3_256": row[4],
                }
    if set(products) != {"src", "amalgamation"}:
        raise ValueError(f"SQLite {version} is not listed on {DOWNLOAD_PAGE}")
    return {"version": version, "archives": products}


def unpack(archive, destination, expected_hash):
    if hashlib.sha3_256(archive).hexdigest() != expected_hash:
        raise ValueError("archive SHA3-256 does not match the recorded release hash")
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        for entry in zipped.infolist():
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError(f"unsafe archive path: {entry.filename}")
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError("archive symlinks are not supported")
        zipped.extractall(destination)
        for entry in zipped.infolist():
            if not entry.is_dir() and (entry.external_attr >> 16) & 0o111:
                (destination / entry.filename).chmod((entry.external_attr >> 16) & 0o777)
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise ValueError("expected one source directory in the SQLite archive")
    return roots[0]


def run(command, directory, log):
    subprocess.run(command, cwd=directory, check=True, stdout=log,
                   stderr=subprocess.STDOUT, env=dict(os.environ, LC_ALL="C"))


def prepare(metadata, temporary):
    source = None
    amalgamation = None
    for kind, archive in metadata["archives"].items():
        destination = temporary / kind
        destination.mkdir()
        unpacked = unpack(fetch(archive["url"]), destination, archive["sha3_256"])
        if kind == "src":
            source = unpacked
        else:
            amalgamation = unpacked

    generated = temporary / "generated"
    generated.mkdir()
    tclsh = shutil.which("tclsh")
    if not tclsh:
        raise ValueError("tclsh is required when updating SQLite")
    make = shutil.which("make")
    if not make:
        raise ValueError("make is required when updating SQLite")
    with (temporary / "generate.log").open("w") as log:
        run(["sh", str(source / "configure"), "--disable-amalgamation", "--disable-tcl"],
            generated, log)
        # Match the bundled library's feature flags, rather than configure's
        # defaults for SQLite's standalone distribution.
        make_flags = [f"B.tclsh={tclsh}", "OPT_FEATURE_FLAGS=", "OPTS=", "OPTIONS="]
        run([make, ".target_source", *make_flags], generated, log)
        listing = generated / "flb-sources.mk"
        listing.write_text(".PHONY: flb-source-list\nflb-source-list:\n\t@echo $(LIBOBJS0)\n")
        objects = subprocess.check_output(
            [make, "--no-print-directory", "-s", "-f", "Makefile", "-f", str(listing),
             "flb-source-list", *make_flags], cwd=generated, text=True).split()

    if not objects or any(not re.fullmatch(r"\w+\.o", name) for name in objects):
        raise ValueError("SQLite's LIBOBJS0 source list has changed unexpectedly")
    names = sorted({name[:-2] + ".c" for name in objects})
    if len(names) != len(objects):
        raise ValueError("duplicate objects in SQLite's source list")
    staged_sources = generated / "tsrc"
    for name in names:
        if not (staged_sources / name).is_file():
            raise ValueError(f"missing prepared SQLite source: {name}")
    for name in ("sqlite3.h", "sqlite3ext.h"):
        if (staged_sources / name).read_bytes() != (amalgamation / name).read_bytes():
            raise ValueError(f"generated {name} differs from the release amalgamation")

    header = (amalgamation / "sqlite3.h").read_text()
    version = re.search(r'^#define SQLITE_VERSION\s+"([^"]+)"', header, re.M)
    source_id = re.search(r'^#define SQLITE_SOURCE_ID\s+"([^"]+)"', header, re.M)
    if not version or version[1] != metadata["version"] or not source_id:
        raise ValueError("release header version does not match the requested version")
    if source_id[1].split()[-1] != (source / "manifest.uuid").read_text().strip():
        raise ValueError("canonical sources and amalgamation have different source IDs")

    result = temporary / "bundle"
    (result / "src").mkdir(parents=True)
    # sqlite_cfg.h describes the maintenance host, not the build target. Like
    # the amalgamation, our library uses SQLite's portable defaults instead.
    for item in staged_sources.iterdir():
        if (item.suffix == ".h" or item.name in names) and item.name not in (
                "sqlite3.h", "sqlite3ext.h", "sqlite_cfg.h"):
            shutil.copyfile(item, result / "src" / item.name)
    for name in ("sqlite3.c", "sqlite3.h", "sqlite3ext.h"):
        shutil.copyfile(amalgamation / name, result / name)
    shutil.copyfile(source / "LICENSE.md", result / "LICENSE.md")
    source_list = ["# Generated by tools/update-sqlite.py; do not edit.",
                   "set(flb_sqlite_sources"]
    source_list += [f'  "${{CMAKE_CURRENT_LIST_DIR}}/src/{name}"' for name in names]
    source_list += [")", ""]
    (result / "sources.cmake").write_text("\n".join(source_list))
    metadata = dict(metadata, source_id=source_id[1], generation_feature_flags=[],
                    update_command=f"python3 tools/update-sqlite.py {version[1]}")
    (result / "SOURCE.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return result


def differences(expected, actual):
    def files(root):
        return {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    old, new = files(expected), files(actual)
    return sorted(str(p) for p in old.keys() | new.keys() if old.get(p) != new.get(p))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("version", nargs="?")
    parser.add_argument("--check", action="store_true",
                        help="regenerate the recorded bundle and compare without writing")
    args = parser.parse_args()
    recorded = None
    if (BUNDLE / "SOURCE.json").exists():
        recorded = json.loads((BUNDLE / "SOURCE.json").read_text())
    version = args.version or (recorded["version"] if args.check and recorded else None)
    if not version:
        parser.error("specify a version, or use --check with an existing bundle")
    version_number(version)
    metadata = recorded if recorded and recorded["version"] == version else release_metadata(version)
    with tempfile.TemporaryDirectory(prefix="flb-sqlite-update-") as directory:
        temporary = Path(directory)
        try:
            prepared = prepare(metadata, temporary)
        except (subprocess.CalledProcessError, ValueError):
            log = temporary / "generate.log"
            if log.exists():
                print(log.read_text(), file=sys.stderr)
            raise
        if args.check:
            changed = differences(BUNDLE, prepared)
            if changed:
                raise ValueError("bundle differs from regenerated sources:\n" + "\n".join(changed))
            print(f"SQLite {version}: committed sources reproduce exactly")
        else:
            # Generate and validate the complete replacement before touching
            # the checkout. Keep a backup until the replacement is installed.
            replacement = BUNDLE.with_name("sqlite.new")
            backup = BUNDLE.with_name("sqlite.old")
            if replacement.exists() or backup.exists():
                raise ValueError("lib/sqlite.new or lib/sqlite.old already exists")
            shutil.copytree(prepared, replacement)
            if BUNDLE.exists():
                BUNDLE.rename(backup)
            try:
                replacement.rename(BUNDLE)
            except OSError:
                if backup.exists():
                    backup.rename(BUNDLE)
                raise
            if backup.exists():
                shutil.rmtree(backup)
            print(f"Prepared SQLite {version} in {BUNDLE}; review and commit the generated diff")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
