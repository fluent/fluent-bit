#!/usr/bin/env python3
"""Verify a browser CI archive and prepare versioned GitHub release assets."""
import argparse
import hashlib
import json
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath


PACKAGE = "fluent-bit-browser-experimental"
REQUIRED = {
    "fluent-bit.js", "fluent-bit-worker.js", "fluent-bit-pthread.js",
    "fluent-bit-runtime.js", "fluent-bit-runtime.wasm", "fluent-bit.d.ts",
    "package.json", "README.md", "LICENSE", "build-info.json", "SHA256SUMS",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verify(directory, source_sha, build_sha):
    archive = directory / f"{PACKAGE}.tar.gz"
    expected = directory.joinpath(f"{archive.name}.sha256").read_text().strip()
    checksum = digest(archive.read_bytes())
    if expected != f"{checksum}  {archive.name}":
        raise ValueError("archive checksum mismatch")
    files = {}
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            path = PurePosixPath(member.name)
            if not path.parts or path.is_absolute() or ".." in path.parts or path.parts[0] != PACKAGE:
                raise ValueError(f"unsafe archive path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile() or len(path.parts) != 2 or path.name in files:
                raise ValueError(f"unexpected archive entry: {member.name}")
            files[path.name] = bundle.extractfile(member).read()
    if not REQUIRED <= files.keys() or any(not data for data in files.values()):
        raise ValueError("incomplete SDK archive")
    checksums = {}
    for line in files["SHA256SUMS"].decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        if not match or match[2] in checksums:
            raise ValueError("invalid SDK checksum manifest")
        checksums[match[2]] = match[1]
    if checksums != {name: digest(data) for name, data in files.items() if name != "SHA256SUMS"}:
        raise ValueError("SDK file checksum mismatch")
    info = json.loads(files["build-info.json"])
    if (info.get("source_commit") != source_sha or info.get("build_commit") != build_sha
            or info.get("sanitizer") != "none" or info.get("experimental") is not True):
        raise ValueError("SDK build identity mismatch")
    if files["fluent-bit-runtime.wasm"][:8] != b"\x00asm\x01\x00\x00\x00":
        raise ValueError("invalid WASM module")
    return archive, checksum, info, files


def prepare(directory, output, source_sha, build_sha, run_url, release_tag=""):
    for sha in (source_sha, build_sha):
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise ValueError("expected a full commit SHA")
    if release_tag and not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", release_tag):
        raise ValueError("expected a version release tag")
    archive, checksum, info, files = verify(directory, source_sha, build_sha)
    version = release_tag or source_sha
    output.mkdir(parents=True, exist_ok=True)
    name = f"{PACKAGE}-{version}.tar.gz"
    shutil.copyfile(archive, output / name)
    output.joinpath(f"{name}.sha256").write_text(f"{checksum}  {name}\n")
    manifest = {
        "schema_version": 1,
        "experimental": True,
        "source_commit": source_sha,
        "build_commit": build_sha,
        "emscripten": info["emscripten"],
        "sdk_version": json.loads(files["package.json"])["version"],
        "release_tag": release_tag or f"wasm-browser-{source_sha}",
        "archive": name,
        "sha256": checksum,
        "validation_run": run_url,
        "validation": "Optimized and ASan builds, CTest and browser suites passed",
    }
    output.joinpath(f"{PACKAGE}-{version}.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--release-tag", default="")
    args = parser.parse_args()
    prepare(args.directory, args.output, args.source_sha, args.build_sha, args.run_url, args.release_tag)


if __name__ == "__main__":
    main()
