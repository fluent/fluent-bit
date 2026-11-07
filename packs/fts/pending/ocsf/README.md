# Source-specific OCSF mapping

Status: **pending**.

Requires a pinned OCSF schema/class version, reviewed source field mapping, schema validator and independent conformance fixtures. Generic field renaming is not a substitute for OCSF conformance.

There is no executable block or passing fixture advertised for this policy.
Do not substitute a simulated implementation or label this production-ready.

## Requirements before use

Select one source schema and event class, pin the OCSF schema version, and define
field types, required fields, enumerations, timestamps and unknown-field handling.
Publish a versioned mapping with independent valid and invalid source fixtures.
Validate mapped events against the pinned OCSF schema as well as the real FTS
pipeline. Changes to the target class or source mapping require a compatibility
and migration decision.

## Instructions for agents

Keep this entry marked pending until a manifest, Lua implementation, documented
source contract and conformance fixtures are available. Do not add a consumer
recipe that implies schema conformance before those checks exist.

See the [catalog](../../CATALOG.md) for executable alternatives and the
[authoring guide](../../AUTHORING.md) for the pack format.
