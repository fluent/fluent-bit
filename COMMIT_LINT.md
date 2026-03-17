# Commit Message Linter

This document explains how to run the commit message linter locally to validate your commits before pushing.

## Overview

The commit prefix checker (`commit_prefix_check.py`) validates commit messages according to Fluent Bit standards:
- Single prefix (plugin or subsystem)
- Prefix must match modified files
- No combined subjects (detect bad squashes)
- Subject ≤ 80 characters
- Signed-off-by line required

## Prerequisites

Install the required Python dependency:

```bash
pip install gitpython
```

## Running Locally

From the repository root directory, run:

```bash
python .github/scripts/commit_prefix_check.py
```

### Behavior

- **Default**: Validates the HEAD commit only
- **Pull Request mode**: If the `GITHUB_EVENT_NAME` environment variable is set to `pull_request`, it validates only commits that are part of the PR:
  - Commits that exist in the PR branch but not in the base branch
  - Merge commits are automatically excluded
  - Requires `GITHUB_BASE_REF` environment variable to be set (automatically set in CI)
- **Exit codes**:
  - `0` if validation passes
  - `1` if validation fails

### Example Output

**Success:**
```
✅ Commit prefix validation passed.
```

**Failure:**
```
❌ Commit deadbeef12 failed:
Subject prefix 'wrong_prefix:' does not match files changed.
Expected one of: router:

Commit prefix validation failed.
```

## Running Unit Tests

The commit linter has comprehensive unit tests. To run them:

### Prerequisites

Install the test dependencies:

```bash
pip install pytest gitpython
```

### Running Tests

From the repository root directory, run:

```bash
# Run all tests
pytest .github/scripts/tests/test_commit_lint.py -v

# Run a specific test
pytest .github/scripts/tests/test_commit_lint.py::test_valid_commit_single_prefix -v

# Run with more detailed output
pytest .github/scripts/tests/test_commit_lint.py -v -s
```

Alternatively, you can run from the scripts directory:

```bash
cd .github/scripts
pytest tests/test_commit_lint.py -v
```

The test suite covers:
- Prefix inference from file paths
- Bad squash detection
- Commit validation (success and error cases)
- Edge cases and boundary conditions

## Testing Specific Commits

To test a specific commit, you can temporarily checkout that commit:

```bash
# Checkout the commit you want to test
git checkout <commit-hash>

# Run the validator
python .github/scripts/commit_prefix_check.py

# Return to your branch
git checkout <your-branch>
```

## CI Integration

This script is automatically run in CI via the `.github/workflows/commit-lint.yaml` workflow on:
- Pull requests (opened, synchronize, reopened, edited)
- Pushes to the `master` branch

## Commit Message Format

See [CONTRIBUTING.md](CONTRIBUTING.md#commit-changes) for the full commit message format requirements.

