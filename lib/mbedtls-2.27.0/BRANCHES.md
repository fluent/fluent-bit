# Maintained branches

At any point in time, we have a number of maintained branches consisting of:

- The [`master`](https://github.com/ARMmbed/mbedtls/tree/master) branch:
  this always contains the latest release, including all publicly available
  security fixes.
- The [`development`](https://github.com/ARMmbed/mbedtls/tree/development) branch:
  this is where new features land,
  as well as bug fixes and security fixes.
- One or more long-time support (LTS) branches:
  these only get bug fixes and security fixes.

We use [Semantic Versioning](https://semver.org/). In particular, we maintain
API compatibility in the `master` branch between major version changes. We
also maintain ABI compatibility within LTS branches; see the next section for
details.

## Backwards Compatibility

We maintain API compatibility in released versions of Mbed TLS. If you have
code that's working and secure with Mbed TLS x.y.z and does not rely on
undocumented features, then you should be able to re-compile it without
modification with any later release x.y'.z' with the same major version
number, and your code will still build, be secure, and work.

There are rare exceptions: code that was relying on something that became
insecure in the meantime (for example, crypto that was found to be weak) may
need to be changed. In case security comes in conflict with backwards
compatibility, we will put security first, but always attempt to provide a
compatibility option.

For the LTS branches, additionally we try very hard to also maintain ABI
compatibility (same definition as API except with re-linking instead of
re-compiling) and to avoid any increase in code size or RAM usage, or in the
minimum version of tools needed to build the code. The only exception, as
before, is in case those goals would conflict with fixing a security issue, we
will put security first but provide a compatibility option. (So far we never
had to break ABI compatibility in an LTS branch, but we occasionally had to
increase code size for a security fix.)

For contributors, see the [Backwards Compatibility section of
CONTRIBUTING](CONTRIBUTING.md#cackwords-compatibility).

## Current Branches

The following branches are currently maintained:

- [master](https://github.com/ARMmbed/mbedtls/tree/master)
- [`development`](https://github.com/ARMmbed/mbedtls/)
- [`mbedtls-2.16`](https://github.com/ARMmbed/mbedtls/tree/mbedtls-2.16)
 maintained until at least the end of 2021, see
  <https://tls.mbed.org/tech-updates/blog/announcing-lts-branch-mbedtls-2.16>

Users are urged to always use the latest version of a maintained branch.
