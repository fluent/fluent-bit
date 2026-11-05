# Authenticated tenant and egress governance

Status: **pending**.

The input-to-tenant identity binding must be authenticated; this requires plus verified native routing/output enforcement. Setting a tenant field in Lua does not enforce isolation or egress authorization.

There is no executable block or passing fixture advertised for this policy.
Do not substitute a simulated implementation or label this production-ready.

## Requirements before use

Bind tenant identity to authenticated input context. Define how that context is
carried through buffering, fan-out, retries and replay, and enforce destination
authorization in routing/output boundaries. Tests must include spoofed identity,
unauthorized destinations, missing context, retries and multiple tenants.
Document failure behavior and audit evidence before exposing a consumer policy.

## Instructions for agents

Keep this entry marked pending until authentication and native egress enforcement
are verified. Lua field enrichment can label telemetry but cannot establish this
security boundary. Do not publish a runnable governance recipe using labels alone.

See the [catalog](../../CATALOG.md) for executable alternatives and the
[authoring guide](../../AUTHORING.md) for the pack format.
