# LLM Skills

This directory contains portable Markdown skill bundles for LLM agents working
in this repository. Each skill should live in its own subdirectory with a
`SKILL.md` entrypoint and any focused companion guides it needs.

## Available Skills

- Fluent Bit: [`fluent-bit/SKILL.md`](fluent-bit/SKILL.md)
  - Repository workflow, testing, patch review, pipeline architecture, and
    recurring subsystem guidance for Fluent Bit work.
  - Sub-skills:
    - [`fluent-bit/patch-workflow.md`](fluent-bit/patch-workflow.md):
      implementation, review, and commit workflow.
    - [`fluent-bit/pipeline-architecture.md`](fluent-bit/pipeline-architecture.md):
      runtime model for shared pipeline changes.
    - [`fluent-bit/subsystem-patterns.md`](fluent-bit/subsystem-patterns.md):
      recurring subsystem search routes and behavioral checks.
    - [`fluent-bit/testing.md`](fluent-bit/testing.md):
      focused CTest, integration, valgrind, and Windows runtime-test guidance.

## How to Use

Start with the skill entrypoint, then read only the companion files relevant to
the task. For Fluent Bit work, begin with:

```text
skills/fluent-bit/SKILL.md
```

## Adding Skills

When adding a new skill:

- create a new subdirectory under `skills/`;
- include a `SKILL.md` entrypoint;
- keep instructions portable and tool-agnostic when possible;
- update this index with the new skill name, entrypoint, and purpose.
