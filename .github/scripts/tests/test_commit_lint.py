import pytest
import sys, os

# Add the scripts directory to the path before importing
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import MagicMock
from commit_prefix_check import (
    validate_commit,
    infer_prefix_from_paths,
    detect_bad_squash,
)

# -----------------------------------------------------------
# Helpers
# -----------------------------------------------------------

def make_commit(message, files):
    commit = MagicMock()
    commit.message = message
    commit.stats.files = {f: {} for f in files}
    commit.hexsha = "deadbeef1234"
    return commit


# -----------------------------------------------------------
# Tests: Prefix Inference
# -----------------------------------------------------------

def test_infer_prefix_plugin():
    """
    Test that plugin file paths correctly infer the plugin name as prefix.

    When a file is in plugins/<name>/, the prefix should be <name>:.
    This is the most common case for Fluent Bit commits modifying plugins.
    """
    assert infer_prefix_from_paths(["plugins/out_s3/s3.c"]) == {"out_s3:"}

def test_infer_prefix_core_file():
    """
    Test that core source files with flb_ prefix correctly infer the component name.

    Files like src/flb_router.c should produce prefix "router:" by stripping
    the "flb_" prefix and file extension. This handles core library components.
    """
    assert infer_prefix_from_paths(["src/flb_router.c"]) == {"router:"}

def test_infer_prefix_new_core_file():
    """
    Test that core files with longer names and numbers are handled correctly.

    Ensures the prefix inference works for files like flb_super_router2.c,
    extracting "super_router2:" correctly. This validates the regex handles
    underscores and numbers in component names.
    """
    assert infer_prefix_from_paths(["src/flb_super_router2.c"]) == {"super_router2:"}

def test_infer_multiple_prefixes():
    """
    Test that multiple files from different components produce multiple prefixes.

    When a commit touches files from different components (e.g., a plugin and
    a core file), the inference should return all relevant prefixes. This helps
    detect commits that mix multiple subsystems, which should be split.
    """
    assert infer_prefix_from_paths([
        "plugins/in_tail/tail.c",
        "src/flb_router.c"
    ]) == {"in_tail:", "router:"}


# -----------------------------------------------------------
# Tests: Bad Squash Detection
# -----------------------------------------------------------

def test_bad_squash_multiple_prefixes_in_body():
    """
    Test detection of multiple subject-like prefix lines in commit body.

    When a commit body contains multiple lines that look like commit subjects
    (e.g., "out_s3: fix xyz"), this indicates a bad squash where multiple
    commits were combined incorrectly. The linter should detect this pattern.
    """
    body = """
out_s3: fix xyz
out_s3: fix again
"""
    ok, reason = detect_bad_squash(body)
    assert ok is True
    assert "Multiple subject-like prefix lines" in reason


def test_bad_squash_multiple_signoffs():
    """
    Test detection of multiple Signed-off-by lines as indicator of bad squash.

    While validate_commit() allows multiple signoffs (for real co-authored commits),
    detect_bad_squash() should flag multiple signoffs as a potential bad squash.
    This helps catch cases where multiple commits were incorrectly merged.
    """
    body = """
Signed-off-by: A
Signed-off-by: B
"""
    ok, reason = detect_bad_squash(body)
    assert ok is True


def test_good_body_not_bad_squash():
    """
    Test that normal commit body text is not flagged as bad squash.

    Regular commit body text without subject-like prefixes should pass
    the bad squash detection. This ensures legitimate commit messages
    are not incorrectly flagged.
    """
    body = "Normal body\nSome text"
    ok, reason = detect_bad_squash(body)
    assert ok is False


# -----------------------------------------------------------
# Tests: validate_commit SUCCESS CASES
# -----------------------------------------------------------

def test_valid_commit_single_prefix():
    """
    Test that a properly formatted commit with matching prefix passes validation.

    A valid commit should have:
    - A prefix matching the changed files (out_s3: for plugins/out_s3/)
    - A Signed-off-by line
    - Subject under 80 characters

    This is the baseline happy path for commit validation.
    """
    commit = make_commit(
        "out_s3: fix retry logic\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


def test_valid_commit_multiple_signoffs_allowed():
    """
    Test that commits with multiple Signed-off-by lines are allowed.

    Multiple signoffs are valid for co-authored commits or commits that
    went through multiple reviewers. Unlike detect_bad_squash(), validate_commit()
    should accept these as legitimate commits.
    """
    commit = make_commit(
        "out_s3: update uploader\n\n"
        "Signed-off-by: User1\n"
        "Signed-off-by: User2",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


# -----------------------------------------------------------
# Tests: validate_commit ERROR CASES
# -----------------------------------------------------------

def test_error_missing_prefix():
    """
    Test that commits without a prefix in the subject are rejected.

    All Fluent Bit commits must have a prefix (e.g., "out_s3:", "router:")
    to identify which component is being modified. This helps with
    changelog generation and code navigation.
    """
    commit = make_commit(
        "Fix retry logic\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "Missing prefix" in msg


def test_error_incorrect_prefix():
    """
    Test that commits with a prefix that doesn't match changed files are rejected.

    The prefix must match the files being changed. For example, if you modify
    plugins/in_tail/tail.c, the prefix should be "in_tail:", not "router:".
    This ensures commit messages accurately describe what was changed.
    """
    commit = make_commit(
        "router: fix tail bug\n\nSigned-off-by: User",
        ["plugins/in_tail/tail.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "does not match files changed" in msg


def test_error_missing_signed_off():
    """
    Test that commits without a Signed-off-by line are rejected.

    The Signed-off-by line is required for DCO (Developer Certificate of Origin)
    compliance. It indicates the contributor agrees to the project's license
    and contribution terms.
    """
    commit = make_commit(
        "out_s3: fix retry\n",
        ["plugins/out_s3/s3.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "Missing Signed-off-by" in msg


def test_error_subject_too_long():
    """
    Test that commit subjects exceeding 80 characters are rejected.

    The 80-character limit is a Git best practice that ensures commit messages
    display correctly in various tools and terminals. Long subjects are hard
    to read and should be split into subject + body.
    """
    commit = make_commit(
        "out_s3: " + "x" * 200 + "\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "too long" in msg


def test_error_bad_squash_detected():
    """
    Test that commits with subject-like prefixes in the body are rejected.

    When a commit body contains lines that look like commit subjects (e.g.,
    "out_s3: second subject"), it indicates a bad squash where multiple
    commits were incorrectly combined. These should be split into separate commits.
    """
    commit = make_commit(
        "out_s3: something\n\nout_s3: second subject\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "Bad squash detected" in msg


def test_error_multiple_prefixes_inferred_from_files():
    """
    Test that commits touching multiple components are rejected.

    When a commit modifies files from different components (e.g., both a plugin
    and core code), it should be split into separate commits. This keeps
    commits focused and makes reviews easier. The error message should list
    all expected prefixes.
    """
    commit = make_commit(
        "in_tail: update handler\n\nSigned-off-by: User",
        ["plugins/in_tail/tail.c", "src/flb_router.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "Expected one of:" in msg


# -----------------------------------------------------------
# Edge Cases
# -----------------------------------------------------------

def test_docs_or_ci_changes_allowed():
    """
    Test that documentation and CI changes are allowed with generic prefixes.

    Files outside plugins/ and src/ (like docs/, .github/, etc.) don't generate
    specific prefixes. Commits modifying these files can use generic prefixes
    like "docs:", "ci:", "build:" without matching specific file paths.
    This allows flexibility for infrastructure and documentation changes.
    """
    commit = make_commit(
        "docs: update readme\n\nSigned-off-by: User",
        ["docs/README.md"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


# -----------------------------------------------------------
# Additional Tests: Prefix Inference Edge Cases
# -----------------------------------------------------------

def test_infer_prefix_empty_file_list():
    """
    Test that an empty file list returns an empty prefix set.

    Edge case: when no files are provided, the function should return
    an empty set rather than raising an error. This handles degenerate cases.
    """
    assert infer_prefix_from_paths([]) == set()

def test_infer_prefix_src_subdirectory():
    """
    Test prefix inference for files in src/ subdirectories.

    Files in src/ subdirectories (like src/stream_processor/stream.c) that
    don't have the flb_ prefix should use the subdirectory name as the prefix.
    This handles organized core code that's not in the root src/ directory.
    """
    assert infer_prefix_from_paths(["src/stream_processor/stream.c"]) == {"stream_processor:"}

def test_infer_prefix_unknown_paths():
    """
    Test that files outside plugins/ and src/ don't generate prefixes.

    Files in unknown locations (not plugins/ or src/) should not generate
    any prefix. This allows commits with only documentation, CI, or other
    non-code files to use generic prefixes.
    """
    assert infer_prefix_from_paths(["random/file.c"]) == set()

def test_infer_prefix_multiple_same_plugin():
    """
    Test that multiple files from the same plugin yield a single prefix.

    When a commit modifies multiple files within the same plugin directory
    (e.g., .c, .h, and config files), they should all produce the same prefix.
    This ensures commits modifying a plugin's internal structure are valid.
    """
    assert infer_prefix_from_paths([
        "plugins/out_s3/s3.c",
        "plugins/out_s3/s3.h",
        "plugins/out_s3/config.c"
    ]) == {"out_s3:"}

def test_infer_prefix_plugin_with_underscores():
    """
    Test that plugin names with underscores are handled correctly.

    Plugin names can contain underscores (e.g., out_http). The prefix inference
    should preserve these underscores in the generated prefix.
    """
    assert infer_prefix_from_paths(["plugins/out_http/http.c"]) == {"out_http:"}

def test_infer_prefix_core_file_with_numbers():
    """
    Test that core file names with numbers are handled correctly.

    Core files like flb_http2.c should produce "http2:" (not "http2.c:").
    This validates that numbers in component names are preserved correctly.
    """
    assert infer_prefix_from_paths(["src/flb_http2.c"]) == {"http2:"}

def test_infer_prefix_mixed_known_unknown():
    """
    Test prefix inference with a mix of known and unknown file paths.

    When a commit contains both files that generate prefixes (plugins/, src/)
    and files that don't (docs/, random files), only the known paths should
    contribute to the prefix set. Unknown paths are ignored.
    """
    result = infer_prefix_from_paths([
        "plugins/in_tail/tail.c",
        "random/file.txt"
    ])
    assert result == {"in_tail:"}


# -----------------------------------------------------------
# Additional Tests: Bad Squash Detection Edge Cases
# -----------------------------------------------------------

def test_bad_squash_single_prefix_in_body():
    """
    Test that even a single prefix-like line in the body is detected.

    A commit body should not contain subject-like lines (lines starting with
    "prefix:"). Even a single such line indicates a bad squash where a commit
    subject was accidentally placed in the body instead of being a separate commit.
    """
    body = "out_s3: fix something\nSigned-off-by: User"
    ok, reason = detect_bad_squash(body)
    assert ok is True
    assert "Unexpected subject-like prefix" in reason

def test_bad_squash_empty_body():
    """
    Test that an empty body is not flagged as bad squash.

    Commits with no body (just subject and signoff) are valid and should not
    trigger bad squash detection. Empty bodies are common for small fixes.
    """
    body = ""
    ok, reason = detect_bad_squash(body)
    assert ok is False

def test_bad_squash_whitespace_only():
    """
    Test that a body containing only whitespace is not flagged.

    Bodies with only whitespace (spaces, tabs, newlines) should be treated
    as empty and not trigger bad squash detection. This handles formatting edge cases.
    """
    body = "   \n\t  \n  "
    ok, reason = detect_bad_squash(body)
    assert ok is False

def test_bad_squash_prefix_not_at_line_start():
    """
    Test that prefix-like text not at the start of a line is ignored.

    The bad squash detector only flags lines that START with a prefix pattern.
    If "out_s3:" appears in the middle of a line (e.g., "This mentions out_s3: ..."),
    it should be ignored as it's likely part of normal prose, not a commit subject.
    """
    body = "This mentions out_s3: in the middle\nSigned-off-by: User"
    ok, reason = detect_bad_squash(body)
    assert ok is False

def test_bad_squash_single_signoff_ok():
    """
    Test that a single Signed-off-by line in the body is acceptable.

    A single signoff is normal and expected. Only multiple signoffs trigger
    the bad squash detection (as they may indicate merged commits).
    """
    body = "Normal body text\nSigned-off-by: User"
    ok, reason = detect_bad_squash(body)
    assert ok is False

def test_bad_squash_mixed_prefix_and_signoff():
    """
    Test detection when both prefix in body and multiple signoffs are present.

    When a body contains both a subject-like prefix line AND multiple signoffs,
    the prefix detection should take precedence (it's a stronger indicator of
    a bad squash than multiple signoffs alone).
    """
    body = "out_s3: fix\nSigned-off-by: A\nSigned-off-by: B"
    ok, reason = detect_bad_squash(body)
    assert ok is True  # Should detect prefix in body

def test_bad_squash_prefix_with_whitespace():
    """
    Test that prefix lines with leading whitespace are still detected.

    After stripping whitespace, lines like "  out_s3: fix" should be detected
    as subject-like prefixes. This handles cases where formatting adds indentation.
    """
    body = "  out_s3: fix\nSigned-off-by: User"
    ok, reason = detect_bad_squash(body)
    assert ok is True  # After strip, should match


# -----------------------------------------------------------
# Additional Tests: validate_commit Boundary Cases
# -----------------------------------------------------------

def test_valid_subject_exactly_80_chars():
    """
    Test that a subject exactly at the 80-character limit is accepted.

    The 80-character limit is inclusive - subjects of exactly 80 characters
    should pass validation. This tests the boundary condition to ensure
    the comparison is correct (<= 80, not < 80).
    """
    subject = "out_s3: " + "x" * 70  # 8 + 70 = 78, need 2 more
    assert len(subject) == 78
    subject = "out_s3: " + "x" * 72  # 8 + 72 = 80
    commit = make_commit(
        f"{subject}\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_error_subject_81_chars():
    """
    Test that a subject exceeding 80 characters is rejected.

    Subjects of 81 or more characters should fail validation. This ensures
    the 80-character limit is enforced and helps maintain readable commit messages.
    """
    subject = "out_s3: " + "x" * 73  # 8 + 73 = 81
    commit = make_commit(
        f"{subject}\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "too long" in msg

def test_valid_commit_no_body_just_signoff():
    """
    Test that commits with only a subject and signoff (no body) are valid.

    Not all commits need a body - simple fixes can be described in the subject
    alone. The signoff is still required, but an empty body is acceptable.
    """
    commit = make_commit(
        "out_s3: fix bug\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_commit_case_insensitive_prefix():
    """
    Test that prefix matching is case-insensitive.

    Prefixes like "OUT_S3:" should match "out_s3:" from file paths. This allows
    flexibility in commit message formatting while maintaining validation accuracy.
    The regex uses IGNORECASE flag for this purpose.
    """
    commit = make_commit(
        "OUT_S3: fix bug\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_commit_prefix_with_numbers():
    """
    Test that prefixes containing numbers are handled correctly.

    Component names can contain numbers (e.g., http2 from flb_http2.c).
    The prefix matching should work correctly with numeric characters.
    """
    commit = make_commit(
        "http2: fix bug\n\nSigned-off-by: User",
        ["src/flb_http2.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_commit_prefix_with_underscores():
    """
    Test that prefixes with underscores are handled correctly.

    Plugin names often contain underscores (e.g., out_http). The prefix matching
    should correctly handle underscores in both the commit prefix and inferred prefix.
    """
    commit = make_commit(
        "out_http: fix bug\n\nSigned-off-by: User",
        ["plugins/out_http/http.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


# -----------------------------------------------------------
# Additional Tests: validate_commit Special File Types
# -----------------------------------------------------------

def test_valid_ci_changes():
    """
    Test that CI/workflow file changes are allowed with generic prefixes.

    Changes to GitHub Actions workflows, CI configuration, and similar files
    don't generate specific prefixes. Generic prefixes like "ci:" are acceptable
    for these infrastructure changes.
    """
    commit = make_commit(
        "ci: update workflow\n\nSigned-off-by: User",
        [".github/workflows/test.yml"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_test_file_changes():
    """
    Test that test file changes are allowed with generic prefixes.

    Test files (in tests/ directory) don't generate specific component prefixes.
    Generic prefixes like "tests:" are acceptable for test-related changes.
    """
    commit = make_commit(
        "tests: add unit test\n\nSigned-off-by: User",
        ["tests/unit/test_router.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_build_file_changes():
    """
    Test that build system file changes are allowed with generic prefixes.

    Changes to build files (CMakeLists.txt, Makefile, etc.) don't generate
    specific prefixes. Generic prefixes like "build:" are acceptable for
    build system modifications.
    """
    commit = make_commit(
        "build: update cmake\n\nSigned-off-by: User",
        ["CMakeLists.txt"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_config_file_changes():
    """
    Test that configuration file changes are allowed with generic prefixes.

    Changes to configuration files (.editorconfig, .gitignore, etc.) don't
    generate specific prefixes. Generic prefixes like "config:" are acceptable
    for configuration changes.
    """
    commit = make_commit(
        "config: update settings\n\nSigned-off-by: User",
        [".editorconfig"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


# -----------------------------------------------------------
# Additional Tests: validate_commit Complex Scenarios
# -----------------------------------------------------------

def test_error_multiple_prefixes_one_matches():
    """
    Test that commits touching multiple components fail even if prefix matches one.

    When a commit modifies files from different components, it should be rejected
    even if the commit prefix matches one of the components. The error message
    should list all expected prefixes to help the developer split the commit.
    This enforces the principle of one logical change per commit.
    """
    commit = make_commit(
        "in_tail: update\n\nSigned-off-by: User",
        ["plugins/in_tail/tail.c", "src/flb_router.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "Expected one of:" in msg
    assert "in_tail:" in msg
    assert "router:" in msg

def test_error_multiple_prefixes_none_match():
    """
    Test that commits with wrong prefix for multiple components are rejected.

    When a commit touches multiple components and the prefix doesn't match any
    of them, it should be rejected with an appropriate error message indicating
    the prefix mismatch.
    """
    commit = make_commit(
        "out_s3: update\n\nSigned-off-by: User",
        ["plugins/in_tail/tail.c", "src/flb_router.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "does not match files changed" in msg

def test_valid_src_subdirectory_file():
    """
    Test that files in src/ subdirectories are validated correctly.

    Files in subdirectories of src/ (like src/stream_processor/stream.c) should
    use the subdirectory name as the prefix. Commits with matching prefixes
    should pass validation.
    """
    commit = make_commit(
        "stream_processor: fix bug\n\nSigned-off-by: User",
        ["src/stream_processor/stream.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_error_wrong_prefix_src_subdirectory():
    """
    Test that wrong prefixes for src/ subdirectory files are rejected.

    When modifying a file in a src/ subdirectory, the prefix must match the
    subdirectory name, not a different component. This ensures accurate commit
    message descriptions.
    """
    commit = make_commit(
        "router: fix stream\n\nSigned-off-by: User",
        ["src/stream_processor/stream.c"]
    )
    ok, msg = validate_commit(commit)
    assert ok is False
    assert "does not match files changed" in msg

def test_valid_commit_with_body_text():
    """
    Test that commits with detailed body text are accepted.

    Commits can have extensive body text explaining the change. The body content
    (as long as it doesn't contain subject-like prefixes) should not affect
    validation. This allows for well-documented commits.
    """
    commit = make_commit(
        "out_s3: fix retry logic\n\n"
        "This fixes an issue where retries were not working correctly.\n"
        "The problem was in the error handling code.\n\n"
        "Signed-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True

def test_valid_commit_with_coauthored_by():
    """
    Test that Co-authored-by trailers are allowed in commit messages.

    Co-authored-by is a standard Git trailer for indicating collaboration.
    Unlike multiple Signed-off-by lines (which may indicate bad squash),
    Co-authored-by is a legitimate trailer and should be allowed alongside
    a single Signed-off-by line.
    """
    commit = make_commit(
        "out_s3: fix bug\n\n"
        "Co-authored-by: Contributor\n"
        "Signed-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True


# -----------------------------------------------------------
# Additional Tests: Edge Cases for Message Parsing
# -----------------------------------------------------------

def test_error_empty_message():
    """
    Test that empty commit messages are rejected.

    An empty commit message cannot have a prefix or Signed-off-by line,
    so it should fail validation. This handles edge cases where commits
    might be created without proper messages.
    """
    commit = make_commit("", ["plugins/out_s3/s3.c"])
    ok, msg = validate_commit(commit)
    assert ok is False
    # Should fail on missing prefix or missing signoff

def test_error_whitespace_only_message():
    """
    Test that commit messages containing only whitespace are rejected.

    Messages with only whitespace (spaces, tabs, newlines) should be treated
    as empty and fail validation. This ensures commits have meaningful messages.
    """
    commit = make_commit("   \n\t  ", ["plugins/out_s3/s3.c"])
    ok, msg = validate_commit(commit)
    assert ok is False

def test_valid_commit_multiline_subject_ignored():
    """
    Test that only the first line is considered the subject for validation.

    Git commit messages can have multiple lines, but only the first line is
    the subject. Subsequent lines before the blank line are part of the body.
    The subject length check and prefix validation should only apply to
    the first line, not subsequent lines that happen to be on the same "subject line".
    """
    commit = make_commit(
        "out_s3: fix bug\nThis is not part of subject\n\nSigned-off-by: User",
        ["plugins/out_s3/s3.c"]
    )
    ok, _ = validate_commit(commit)
    assert ok is True
