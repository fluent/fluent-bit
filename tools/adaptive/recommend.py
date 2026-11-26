#!/usr/bin/env python3
"""Turn an adaptive processor report into a policy file.

This is a reference controller for the feedback loop of the ``adaptive``
processor. It reads the pattern report written by ``report_file``, combines it
with a usage signal (how often each pattern is actually read downstream) and
writes the JSON document expected by ``policy_file``.

The usage file is JSON: ``{"<template or pattern id>": <lines read>, ...}``.
A backend that knows which patterns its users query can produce it; without
one, an operator can list the templates worth keeping.

Drop rates follow the read ratio of a pattern, lines read divided by lines
produced:

    never read          -> --never  (default 0.90)
    read up to 1%       -> --rarely (default 0.50)
    read up to 40%      -> --sometimes (default 0.10)
    read more than that -> 0.0, the pattern is exempt

Patterns that are small, or made only of protected records, get no rule and
keep the automatic behaviour of the processor.

When the processor runs with ``group_by``, every pattern in the report names
its group and the rule written for it only applies to that group.
"""

import argparse
import json
import os
import sys
import tempfile


def read_ratio(pattern, usage):
    """Lines read per line produced, None when the pattern has no usage entry."""
    read = usage.get(pattern["template"])
    if read is None:
        read = usage.get(pattern["id"])
    if read is None:
        return None
    if pattern["count"] <= 0:
        return 0.0
    return float(read) / float(pattern["count"])


def drop_rate(ratio, never, rarely, sometimes):
    if ratio is None or ratio <= 0.0:
        return never
    if ratio <= 0.01:
        return rarely
    if ratio <= 0.40:
        return sometimes
    return 0.0


def recommend(report, usage, *, min_share=0.001, never=0.90, rarely=0.50,
              sometimes=0.10):
    """Return (policy, rows). Rows describe every decision for display."""
    total_bytes = sum(p["bytes"] for p in report.get("patterns", []))
    rules = []
    rows = []

    for pattern in report.get("patterns", []):
        share = pattern["bytes"] / total_bytes if total_bytes else 0.0
        ratio = read_ratio(pattern, usage)
        row = {"id": pattern["id"], "template": pattern["template"],
               "share": share, "read_ratio": ratio, "drop_rate": None,
               "saved_bytes": 0, "reason": ""}
        rows.append(row)

        if pattern["count"] > 0 and pattern["protected"] >= pattern["count"]:
            row["reason"] = "protected"
            continue
        if share < min_share and ratio is None:
            row["reason"] = "below min share"
            continue

        rate = drop_rate(ratio, never, rarely, sometimes)
        row["drop_rate"] = rate
        row["reason"] = "never read" if not ratio else "read ratio"
        unprotected = 1.0 - pattern["protected"] / pattern["count"]
        row["saved_bytes"] = int(pattern["bytes"] * unprotected * rate)
        rule = {"template": pattern["template"], "drop_rate": rate}
        # with group_by, the same template can deserve a different rate per group
        if pattern.get("group"):
            rule["group"] = pattern["group"]
        rules.append(rule)

    return {"version": 1, "patterns": rules}, rows


def write_atomic(path, document):
    directory = os.path.dirname(os.path.abspath(path))
    handle, tmp_path = tempfile.mkstemp(dir=directory, prefix=".policy-")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(document, stream, indent=1)
            stream.write("\n")
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def parse_rate(text):
    value = float(text)
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError("rates are between 0 and 1")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--report", required=True, help="report_file of the processor")
    parser.add_argument("--usage", help="JSON map of template or id to lines read")
    parser.add_argument("--out", required=True, help="policy file to write")
    parser.add_argument("--min-share", type=parse_rate, default=0.001,
                        help="ignore unlisted patterns below this share of bytes")
    parser.add_argument("--never", type=parse_rate, default=0.90)
    parser.add_argument("--rarely", type=parse_rate, default=0.50)
    parser.add_argument("--sometimes", type=parse_rate, default=0.10)
    args = parser.parse_args(argv)

    with open(args.report, encoding="utf-8", errors="replace") as stream:
        report = json.load(stream)
    usage = {}
    if args.usage:
        with open(args.usage, encoding="utf-8") as stream:
            usage = json.load(stream)
        if not isinstance(usage, dict):
            parser.error("--usage must be a JSON object")

    policy, rows = recommend(report, usage, min_share=args.min_share,
                             never=args.never, rarely=args.rarely,
                             sometimes=args.sometimes)
    write_atomic(args.out, policy)

    total = sum(p["bytes"] for p in report.get("patterns", []))
    saved = sum(row["saved_bytes"] for row in rows)
    for row in rows:
        rate = "-" if row["drop_rate"] is None else f"{row['drop_rate']:.2f}"
        print(f"{row['share'] * 100:6.2f}%  drop {rate:>4}  {row['reason']:<16} "
              f"{row['template'][:90]}")
    share = saved / total * 100 if total else 0.0
    print(f"{len(policy['patterns'])} rules, projected saving {saved} of {total} "
          f"bytes ({share:.1f}%)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
