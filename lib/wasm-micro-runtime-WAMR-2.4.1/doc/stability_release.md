# Semantic Versioning

WAMR has adopted [semantic versioning](https://semver.org/) to replace the former *date versioning system*.  The new version string consists of three parts:

- *major*: Any change that is not compatible with previous versions, affecting either the ABI or APIs, will result in an increase in the major version number. APIs include: wasm_export.h, wasm_c_api.h, sections in AOT files, among others.
- *minor*: This number increases with the addition of new features. This encompasses not only MVP (Minimum Viable Product) or POST-MVP features but also WebAssembly System Interface (WASI) features and WAMR-specific features.
- *patch*: This number is incremented for patches.

## Legacy releases

All previous versions (tags) will retain their current status. There will be no changes to existing release names and links.

# Release Process

WAMR has been deployed across various devices. A frequent release cycle would strain customers' testing resources and add extra deployment work. Two factors can trigger a new WAMR release:

- Community requests, particularly following the integration of significant and new features.
- Security vulnerabilities and critical bug fixes that ensure correctness.

Patch releases will be made only to address security vulnerabilities and critical issues related to default behavior in prior releases.

Once a release decision has been made:

- Create a PR that:
  1. Modifies *build-scripts/version.cmake*.
  2. Executes cmake configuration to update the version.
  3. Updates *RELEASE_NOTES.md*.
- A checklist of the PR includes
  - [ ] *build-scripts/version.cmake*
  - [ ] *core/version.h*
  - [ ] *RELEASE_NOTES.md*
- Once the PR is merged, create a new tag.
- Initiate the release process by triggering *the binary release processes* in *Actions*.
