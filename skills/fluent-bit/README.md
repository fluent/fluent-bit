# Fluent Bit LLM Skills

This folder contains portable Markdown skills for agents working on the Fluent
Bit repository. They are intentionally tool-agnostic: any LLM can read these
files as instructions, then use whatever shell, editor, or CI interface it has.

## Files

- `SKILL.md`: entrypoint and operating principles.
- `testing.md`: focused CTest, integration, and valgrind expectations.
- `patch-workflow.md`: implementation, review, and commit workflow.
- `pipeline-architecture.md`: runtime model for shared pipeline changes.
- `subsystem-patterns.md`: recurring Fluent Bit subsystem routes and checks.

## Suggested Agent Prompt

```text
Before working in this repository, read skills/fluent-bit/SKILL.md.
For code changes, also read skills/fluent-bit/patch-workflow.md and
skills/fluent-bit/testing.md. For shared runtime changes, read
skills/fluent-bit/pipeline-architecture.md. For known subsystem areas, read
skills/fluent-bit/subsystem-patterns.md.
```

## Maintenance

Keep these files concise and operational. Add subsystem notes only when they
change how an agent should search, patch, test, or report work in this repo.

