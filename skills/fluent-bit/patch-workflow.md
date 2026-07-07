# Fluent Bit Patch and Review Workflow

Use this guide when implementing or reviewing Fluent Bit changes.

## Before Editing

- Inspect the current checkout. Do not assume a reported bug is still live.
- Search with `rg` first.
- Read the exact source path, tests, and helpers involved.
- Trace from public configuration or input surface to the failing behavior.
- Identify whether the problem belongs in a plugin, a shared helper, core
  runtime, a bundled library, or tests.
- If the fix would touch bundled library code under `lib/`, get explicit user
  confirmation before editing. Use a confirmation popup when the environment
  supports one; otherwise ask in chat.

## Implementation Rules

- Keep patches minimal and scoped.
- Use existing helpers and source-of-truth functions before adding new logic.
- When a shared helper has wrong semantics, fix the helper and update callers
  consistently.
- Preserve explicit zero values; use clear sentinels for unknown values.
- Do not downgrade real I/O, parse, or lifecycle failures just to quiet logs.
- Do not add broad refactors or formatting churn around the fix.
- Keep bundled library edits isolated from Fluent Bit glue changes and write
  them as upstreamable patches for the library's own project.
- Follow Fluent Bit C style:
  - variables at function start;
  - braces for all `if`, `else`, `while`, and `do` blocks;
  - function opening brace on the next line;
  - `snake_case` names with existing component prefixes;
  - `/* ... */` comments only where useful.

## Review Stance

Prioritize:

- bugs and behavioral regressions;
- missing tests;
- lifecycle or memory-safety risks;
- config compatibility risks;
- route, signal, storage, or retry accounting regressions.

When reviewing claims like "this enables validation" or "this caches
resolution," distinguish:

- what the current patch actually wires;
- what runtime or binding plumbing is still missing;
- whether behavior is one-shot lookup, repeated resolver use, or true cache
  semantics.

## Commit Guidance

Use component-prefix subjects consistent with local history:

```sh
git commit -s -m "component: short imperative description"
```

Common examples:

- `engine: fix flush buffer handling`
- `tests: internal: add parser regression coverage`
- `tests: integration: cover schema registry resolution`

For bundled library changes, keep the library patch in its own commit unless the
user explicitly asks otherwise. Use the prefix accepted for that path by the
repository linter, and mention the upstream project/path in the commit body when
that context is useful.

Do not invent generic prefixes when the repository linter infers a narrower
prefix. Run the linter when creating commits:

```sh
python .github/scripts/commit_prefix_check.py
```

If `gitpython` is missing:

```sh
python3 -m pip install gitpython
```

Before pushing or opening a PR, fetch the base branch and lint the PR range, not
just `HEAD`. The checker can fall back to `HEAD`-only validation if the base ref
is missing locally:

```sh
git fetch --all --prune
git fetch origin <base-branch>:origin/<base-branch>
GITHUB_EVENT_NAME=pull_request GITHUB_BASE_REF=<base-branch> \
  python .github/scripts/commit_prefix_check.py
```

Do not open issues, pull requests, or remote branches unless explicitly asked.
Do not rewrite history, amend commits, or force-push unless explicitly asked.
