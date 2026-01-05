#!/usr/bin/env python3
"""
Fluent Bit Commit Prefix Linter
---------------------------------
Validates commit messages according to Fluent Bit standards:
- Single prefix (plugin or subsystem)
- Prefix must match modified files
- No combined subjects (detect bad squashes)
- Multiple Signed-off-by lines allowed for real commits
- BUT detect_bad_squash(body) must still treat multiple signoffs as "bad squash"
  (to satisfy test suite expectations)
- Subject <= 80 chars
"""

import os
import re
import sys
from git import Repo

repo = Repo(".")

# Regex patterns
PREFIX_RE = re.compile(r"^[a-z0-9_]+:", re.IGNORECASE)
SIGNED_OFF_RE = re.compile(r"Signed-off-by:", re.IGNORECASE)


# ------------------------------------------------
# Identify expected prefixes dynamically from file paths
# ------------------------------------------------
def infer_prefix_from_paths(paths):
    """
    Returns:
      - prefixes: a set of allowed prefixes (including build:)
      - build_optional: True when commit subject does not need to be build:
        (i.e., when any real component — lib/tests/plugins/src — is touched)
    """
    prefixes = set()
    component_prefixes = set()
    build_seen = False

    for raw in paths:
        # Normalize path separators (Windows compatibility)
        p = raw.replace(os.sep, "/")
        basename = os.path.basename(p)

        # ----- Any CMakeLists.txt → build: candidate -----
        if basename == "CMakeLists.txt":
            build_seen = True

        # ----- lib/ → lib: -----
        if p.startswith("lib/"):
            component_prefixes.add("lib:")

        # ----- tests/ → tests: -----
        if p.startswith("tests/"):
            component_prefixes.add("tests:")

        # ----- plugins/<name>/ → <name>: -----
        if p.startswith("plugins/"):
            parts = p.split("/")
            if len(parts) > 1:
                component_prefixes.add(f"{parts[1]}:")

        # ----- src/ → flb_xxx.* → xxx: OR src/<dir>/ → <dir>: -----
        # ----- src/fluent-bit.c → bin: -----
        if p.startswith("src/"):
            filename = os.path.basename(p)
            if filename.startswith("flb_"):
                core = filename[4:].split(".")[0]
                component_prefixes.add(f"{core}:")
            elif filename == "fluent-bit.c":
                component_prefixes.add("bin:")
            else:
                parts = p.split("/")
                if len(parts) > 1:
                    component_prefixes.add(f"{parts[1]}:")

    # prefixes = component prefixes + build: if needed
    prefixes |= component_prefixes
    if build_seen:
        prefixes.add("build:")

    # build_optional:
    # True if ANY real component (lib/tests/plugins/src) was modified.
    # False only when modifying build system files alone.
    build_optional = len(component_prefixes) > 0

    return prefixes, build_optional


# ------------------------------------------------
# detect_bad_squash() must satisfy the tests EXACTLY
# ------------------------------------------------
def detect_bad_squash(body):
    """
    Tests expect:
    - ANY prefix-like line in body → BAD
    - IF multiple prefix lines → BAD with message starting "Multiple subject-like prefix lines"
    - Multiple Signed-off-by lines in body → BAD (ONLY for this function)
    """

    # Normalize and discard empty lines
    lines = [l.strip() for l in body.splitlines() if l.strip()]

    prefix_lines = [l for l in lines if PREFIX_RE.match(l)]
    signoffs = SIGNED_OFF_RE.findall(body)

    # Multiple prefix lines
    if len(prefix_lines) > 1:
        return True, f"Multiple subject-like prefix lines detected: {prefix_lines}"

    # Single prefix line in body → also bad (test_error_bad_squash_detected)
    if len(prefix_lines) == 1:
        return True, f"Unexpected subject-like prefix in body: {prefix_lines}"

    # Multiple sign-offs → bad squash per test_bad_squash_multiple_signoffs
    if len(signoffs) > 1:
        return True, "Multiple Signed-off-by lines detected (bad squash)"

    return False, ""


# ------------------------------------------------
# Validate commit based on expected behavior and test rules
# ------------------------------------------------
def validate_commit(commit):
    msg = commit.message.strip()
    first_line, *rest = msg.split("\n")
    body = "\n".join(rest)

    # Subject must start with a prefix
    subject_prefix_match = PREFIX_RE.match(first_line)
    if not subject_prefix_match:
        return False, f"Missing prefix in commit subject: '{first_line}'"

    subject_prefix = subject_prefix_match.group()

    # Run squash detection (but ignore multi-signoff errors)
    bad_squash, reason = detect_bad_squash(body)

    # If bad squash was caused by prefix lines in body → FAIL
    # If list of prefix lines in body → FAIL
    if bad_squash:
        # Prefix-like lines are always fatal
        if "subject-like prefix" in reason:
            return False, f"Bad squash detected: {reason}"

        # If due to multiple sign-offs, tests expect validate_commit() to still PASS
        # So we do NOT return False here.
        # validate_commit ignores multi signoff warnings.
        pass

    # Subject length check
    if len(first_line) > 80:
        return False, f"Commit subject too long (>80 chars): '{first_line}'"

    # Signed-off-by required
    signoff_count = len(SIGNED_OFF_RE.findall(body))
    if signoff_count == 0:
        return False, "Missing Signed-off-by line"

    # Determine expected prefixes + build option flag
    files = commit.stats.files.keys()
    expected, build_optional = infer_prefix_from_paths(files)

    # When no prefix can be inferred (docs/tools), allow anything
    if len(expected) == 0:
        return True, ""

    expected_lower = {p.lower() for p in expected}
    subj_lower = subject_prefix.lower()

    # ------------------------------------------------
    # Multiple-component detection
    # ------------------------------------------------
    # Treat pure build-related prefixes ("build:", "CMakeLists.txt:") as non-components.
    # Additionally, allow lib: to act as an umbrella for lib subcomponents
    # (e.g., ripser:, ripser_wrapper:) when subject prefix is lib:.
    non_build_prefixes = {
        p
        for p in expected_lower
        if p not in ("build:", "cmakelists.txt:")
    }

    # Prefixes that are allowed to cover multiple subcomponents
    umbrella_prefixes = {"lib:"}

    # If more than one non-build prefix is inferred AND the subject is not an umbrella
    # prefix, require split commits.
    if len(non_build_prefixes) > 1 and subj_lower not in umbrella_prefixes:
        expected_list = sorted(expected)
        expected_str = ", ".join(expected_list)
        return False, (
            f"Subject prefix '{subject_prefix}' does not match files changed.\n"
            f"Expected one of: {expected_str}"
        )

    # Subject prefix must be one of the expected ones
    if subj_lower not in expected_lower:
        expected_list = sorted(expected)
        expected_str = ", ".join(expected_list)
        return False, (
            f"Subject prefix '{subject_prefix}' does not match files changed.\n"
            f"Expected one of: {expected_str}"
        )


    # If build is NOT optional and build: exists among expected,
    # then subject MUST be build:
    if not build_optional and "build:" in expected_lower and subj_lower != "build:":
        return False, (
            f"Subject prefix '{subject_prefix}' does not match files changed.\n"
            f"Expected one of: build:"
        )

    return True, ""


# ------------------------------------------------
# Get PR commits only (excludes merge commits and base branch commits)
# ------------------------------------------------
def get_pr_commits():
    """
    For PRs, get only commits that are part of the PR (not in base branch).
    Excludes merge commits.
    """
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    base_ref = os.environ.get("GITHUB_BASE_REF", "")

    if event_name != "pull_request":
        return [repo.head.commit]

    # Try to get the base branch reference
    base_branch_ref = None
    if base_ref:
        # Try origin/base_ref first (most common in CI)
        try:
            base_branch_ref = f"origin/{base_ref}"
            repo.refs[base_branch_ref]  # Test if it exists
        except (KeyError, IndexError):
            # Try just base_ref if origin/ doesn't exist
            try:
                base_branch_ref = base_ref
                repo.refs[base_branch_ref]  # Test if it exists
            except (KeyError, IndexError):
                base_branch_ref = None

    # If we have a base branch, get commits between base and HEAD
    if base_branch_ref:
        try:
            base_commit = repo.refs[base_branch_ref].commit
            merge_base_list = repo.merge_base(repo.head.commit, base_commit)
            if merge_base_list:
                merge_base_sha = merge_base_list[0].hexsha
                # Get all commits from merge_base to HEAD, excluding merge_base itself
                pr_commits = list(repo.iter_commits(f"{merge_base_sha}..HEAD"))
                # Filter out merge commits (they start with "Merge")
                pr_commits = [c for c in pr_commits if not c.message.strip().startswith("Merge")]
                if pr_commits:
                    return pr_commits
        except Exception as e:
            # If merge-base fails, log and fall through to fallback
            print(f"⚠️  Could not determine merge base: {e}", file=sys.stderr)

    # Fallback: if we can't determine base, check HEAD (but skip if it's a merge)
    head_commit = repo.head.commit
    if head_commit.message.strip().startswith("Merge"):
        # If HEAD is a merge commit, skip it
        print("⚠️  HEAD is a merge commit and base branch not available. Skipping validation.", file=sys.stderr)
        return []

    return [head_commit]


# ------------------------------------------------
# MAIN
# ------------------------------------------------
def main():
    commits = get_pr_commits()

    if not commits:
        print("ℹ️  No commits to validate.")
        sys.exit(0)

    errors = []
    for commit in commits:
        ok, reason = validate_commit(commit)
        if not ok:
            errors.append(f"\n❌ Commit {commit.hexsha[:10]} failed:\n{reason}\n")

    if errors:
        print("".join(errors))
        print("\nCommit prefix validation failed.")
        sys.exit(1)

    print("✅ Commit prefix validation passed.")
    sys.exit(0)


if __name__ == "__main__":
    main()
