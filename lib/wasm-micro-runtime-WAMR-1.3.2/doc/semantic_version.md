# WAMR uses semantic versioning

WAMR uses the _semantic versioning_ to replace the current _date versioning_ system.

There are three parts in the new version string:

- _major_. Any incompatible modification, on both ABI and APIs, will lead an increment
  in the value of _major_. APIs includes: `wasm_export.h`, `wasm_c_api.h`,
  _sections in AOT files_, and so on.
- _minor_. It represents new features. It includes not just MVP or POST-MVP features
  but also WASI features and WAMR private ones.
- _patch_. It represents patches.

## Legacy versions

All legacy versions(tags) will keep their current status. No existed releasings names
and links will be changed.

## Reference

- [Semantic Versioning 2.0.0](https://semver.org/)
