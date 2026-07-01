#!/usr/bin/env python3

#
# Copyright (C) 2019 Intel Corporation.  All rights reserved.
# SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
#

import json
import sys
import os
import requests


def fetch_dismissed_alerts(repo_name, github_token):
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json",
    }
    url = (
        f"https://api.github.com/repos/{repo_name}/code-scanning/alerts?state=dismissed"
    )
    response = requests.get(url, headers=headers)
    return response.json()  # This assumes a successful API call


def parse_location(location):
    path = location.get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
    start_line = location.get("physicalLocation", {}).get("region", {}).get("startLine")
    column_range = (
        location.get("physicalLocation", {}).get("region", {}).get("startColumn"),
        location.get("physicalLocation", {}).get("region", {}).get("endColumn"),
    )
    return (path, start_line, column_range)


def is_dismissed(rule_id, path, start_line, column_range, dismissed_alerts):
    for alert in dismissed_alerts:
        alert_rule_id = alert.get("rule", {}).get("id")
        alert_path = alert.get("location", {}).get("path")
        alert_start_line = alert.get("location", {}).get("start_line")
        alert_column_range = (
            alert.get("location", {}).get("start_column"),
            alert.get("location", {}).get("end_column"),
        )

        if (
            rule_id == alert_rule_id
            and path == alert_path
            and start_line == alert_start_line
            and column_range == alert_column_range
        ):
            return True
    return False


# Return whether SARIF file contains error-level results
def codeql_sarif_contain_error(filename, dismissed_alerts):
    has_error = False

    with open(filename, "r") as f:
        s = json.load(f)

    for run in s.get("runs", []):
        rules_metadata = run["tool"]["driver"]["rules"]
        if not rules_metadata:
            rules_metadata = run["tool"]["extensions"][0]["rules"]

        for res in run.get("results", []):
            if "ruleIndex" in res:
                rule_index = res["ruleIndex"]
            elif "rule" in res and "index" in res["rule"]:
                rule_index = res["rule"]["index"]
            else:
                continue

            # check whether it's dismissed before
            rule_id = res["ruleId"]
            path, start_line, column_range = parse_location(res["locations"][0])
            # the source code is from dependencies
            if "_deps" in path:
                continue
            if is_dismissed(rule_id, path, start_line, column_range, dismissed_alerts):
                print(
                    f"====== Finding a dismissed entry: {rule_id} at {path}:{start_line} is dismissed.======"
                )
                print(res)
                continue

            try:
                rule_level = rules_metadata[rule_index]["defaultConfiguration"]["level"]
            except IndexError as e:
                print(e, rule_index, len(rules_metadata))
            else:
                if rule_level == "error":
                    # very likely to be an actual error
                    if rules_metadata[rule_index]["properties"].get("precision") in [
                        "high",
                        "very-high",
                    ]:
                        # the security severity is above medium(Common Vulnerability Scoring System (CVSS) >= 4.0)
                        if "security-severity" in rules_metadata[rule_index][
                            "properties"
                        ] and (
                            float(
                                rules_metadata[rule_index]["properties"][
                                    "security-severity"
                                ]
                            )
                            > 4.0
                        ):
                            print("====== Finding a likely error. ======")
                            print(res)
                            has_error = True

    return has_error


if __name__ == "__main__":
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
    dismissed_alerts = fetch_dismissed_alerts(GITHUB_REPOSITORY, GITHUB_TOKEN)

    if codeql_sarif_contain_error(sys.argv[1], dismissed_alerts):
        sys.exit(1)
