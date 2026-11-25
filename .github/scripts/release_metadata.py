#!/usr/bin/env python3
"""Validate Fluent Bit -J metadata and verify anonymous public downloads."""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

PUBLIC_URL = "https://packages.fluentbit.io"


def release_version(value):
    """Strip exactly one optional v; reject unsafe paths and branch names."""
    if not isinstance(value, str) or not re.fullmatch(r"v?\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", value):
        raise ValueError(f"expected a release version with optional v prefix, got {value!r}")
    return value.removeprefix("v")


def filenames(version):
    version = release_version(version)
    return (f"fluent-bit-schema-{version}.json", f"fluent-bit-schema-pretty-{version}.json")


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def invalid_constant(value):
    raise ValueError(f"invalid JSON constant: {value}")


def validate(data, version):
    if not data.strip():
        raise ValueError("empty metadata file")
    doc = json.loads(data, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    if not isinstance(doc, dict) or not isinstance(doc.get("fluent-bit"), dict):
        raise ValueError("missing fluent-bit metadata object")
    meta = doc["fluent-bit"]
    actual = release_version(meta.get("version"))
    if version is not None and actual != release_version(version):
        raise ValueError(f"version mismatch: expected {version}, found {actual}")
    for field in ("schema_version", "os"):
        if not isinstance(meta.get(field), str) or not meta[field].strip():
            raise ValueError(f"missing fluent-bit.{field} string")
    catalogs = {"customs": "custom", "inputs": "input", "filters": "filter", "outputs": "output"}
    # 2.x/3.x -J has five root keys; the processor catalog was added in 4.0.
    if int(actual.split(".")[0]) >= 4 or "processors" in doc:
        catalogs["processors"] = "processor"
    for catalog, kind in catalogs.items():
        entries = doc.get(catalog)
        if not isinstance(entries, list):
            raise ValueError(f"missing {catalog} plugin array")
        if catalog in ("inputs", "filters", "outputs") and not entries:
            raise ValueError(f"empty {catalog} plugin catalog")
        names = set()
        for plugin in entries:
            if not isinstance(plugin, dict) or plugin.get("type") != kind:
                raise ValueError(f"invalid {catalog} plugin type")
            name = plugin.get("name")
            if not isinstance(name, str) or not name.strip() or name in names:
                raise ValueError(f"invalid or duplicate {catalog} plugin name: {name!r}")
            names.add(name)
            if not isinstance(plugin.get("description"), str) or not isinstance(plugin.get("properties"), dict):
                raise ValueError(f"invalid {catalog}/{name} description or properties")
    return doc


def validate_pair(directory, version):
    docs = []
    for name in filenames(version):
        path = Path(directory) / name
        try:
            docs.append(validate(path.read_bytes(), version))
        except (OSError, ValueError) as error:
            raise ValueError(f"{path}: {error}") from error
    if docs[0] != docs[1]:
        raise ValueError("regular and pretty metadata variants differ")
    return docs[0]


def fetch(url):
    # Disable curlrc so developer/runner authentication settings cannot leak into
    # this check. No AWS credentials, cookies, netrc or Authorization headers.
    result = subprocess.run([
        "curl", "--disable", "--fail", "--silent", "--show-error", "--location",
        "--proto", "=https,http", "--proto-redir", "=https", "--connect-timeout", "10",
        "--max-time", "30", "--header", "Cache-Control: no-cache",
        "--write-out", "\n%{http_code}", url,
    ], capture_output=True, timeout=35)
    if result.returncode:
        raise ValueError(result.stderr.decode(errors="replace").strip())
    data, _, status = result.stdout.rpartition(b"\n")
    if not status.isdigit() or not 200 <= int(status) < 300:
        raise ValueError(f"unsuccessful public HTTP response: {status.decode(errors='replace')}")
    return data


def verify(directory, version, base_url=PUBLIC_URL, attempts=75, delay=60, release_assets=False):
    expected = validate_pair(directory, version)
    version = release_version(version)
    for attempt in range(1, attempts + 1):
        failures = []
        # Re-fetch both on every attempt; success requires both in this pass.
        for name in filenames(version):
            url = f"{base_url.rstrip('/')}/{'v' if release_assets else ''}{version}/{name}"
            try:
                data = fetch(url)
                if validate(data, version) != expected:
                    raise ValueError("public content differs from generated artifact")
                if data != (Path(directory) / name).read_bytes():
                    raise ValueError("public bytes differ from generated artifact")
            except (ValueError, OSError, subprocess.SubprocessError) as error:
                failures.append(f"{url}: {error}")
        if not failures:
            print(f"Verified both public metadata files for {version}")
            return
        print(f"Public metadata attempt {attempt}/{attempts}: " + "; ".join(failures), flush=True)
        if attempt < attempts:
            time.sleep(delay)
    raise ValueError("Public metadata unavailable after bounded retries. Check exact S3 keys, "
                     "packages-server sync/CDN routing and access rules; rerun publication after "
                     "repair. Do not mark the release successful. " + "; ".join(failures))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("generate", "validate", "compare", "verify"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", default=".")
    parser.add_argument("--reference-directory")
    parser.add_argument("--image", help="immutable registry/repository@sha256:digest")
    parser.add_argument("--development", action="store_true", help="allow non-release artifact labels during generation only")
    parser.add_argument("--base-url", default=PUBLIC_URL)
    parser.add_argument("--github-repository", help="verify GitHub release assets instead (owner/repository)")
    parser.add_argument("--attempts", type=int, default=75)
    parser.add_argument("--delay", type=float, default=60)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            if not args.image or not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.image):
                raise ValueError("generation requires an immutable image digest")
            version = args.version
            if args.development:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+", version):
                    raise ValueError("unsafe development artifact label")
                expected_version = None
                names = (f"fluent-bit-schema-{version}.json", f"fluent-bit-schema-pretty-{version}.json")
            else:
                version = release_version(version)
                expected_version = version
                names = filenames(version)
            data = subprocess.check_output(["docker", "run", "--rm", "--platform", "linux/amd64", args.image, "-J"])
            doc = validate(data, expected_version)
            directory = Path(args.directory)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / names[0]).write_bytes(data)
            pretty = json.dumps(doc, indent=2, ensure_ascii=False).encode() + b"\n"
            (directory / names[1]).write_bytes(pretty)
            if validate(pretty, expected_version) != doc:
                raise ValueError("pretty variant differs")
        elif args.command == "validate":
            validate_pair(args.directory, args.version)
        elif args.command == "compare":
            if not args.reference_directory:
                raise ValueError("compare requires --reference-directory")
            if validate_pair(args.directory, args.version) != validate_pair(args.reference_directory, args.version):
                raise ValueError("staged metadata differs from the exact release image")
        else:
            if args.github_repository:
                if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.github_repository):
                    raise ValueError("invalid GitHub owner/repository")
                args.base_url = f"https://github.com/{args.github_repository}/releases/download"
            url = urlsplit(args.base_url)
            if url.scheme != "https" or not url.netloc or url.username or url.password or url.query or url.fragment:
                raise ValueError("public base URL must be anonymous HTTPS")
            if args.attempts < 1 or not 0 <= args.delay <= 60:
                raise ValueError("attempts must be positive and delay must be between 0 and 60 seconds")
            verify(args.directory, args.version, args.base_url, args.attempts, args.delay,
                   release_assets=bool(args.github_repository))
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Release metadata check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
