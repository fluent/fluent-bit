# Fluent Bit Maintenance Policy

This document outlines the maintenance strategy and version support for Fluent Bit.

## Active Branches and Maintainers

| Branch     | Version            | Status              | Maintainer                                                  | Notes                                                              |
|------------|--------------------|---------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| `master`   | v5.0 (development) | Active development  | [Eduardo Silva](https://github.com/edsiper)                 | All new features and bug fixes land here first                     |
| `4.2`      | v4.2.x             | Stable              | [Eduardo Silva](https://github.com/edsiper) [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920) | Current stable release series. Active development and updates. May receive minor enhancements in addition to fixes.     |
| `4.1`      | v4.1.x             | Maintenance only    | [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920) | Critical fixes and safe backports only. Maintained until **February 28, 2026** |

---

## Maintenance Policy

Active development is currently on Fluent Bit **v5.0** (tracked in the `master` branch). The **v4.2** branch is the current stable release series and receives active updates. Previous release lines enter **maintenance mode** after the next major/minor release.

### Accepted Changes for Maintenance Branches

- ✅ Security patches (see [SECURITY.md](SECURITY.md) for security update timelines)
- ✅ Critical bug fixes
- ✅ Low-risk enhancements that unblock adoption (e.g., OpenTelemetry improvements, performance tuning)

> ⚠️ All changes must first be merged into `master` before being cherry-picked into maintenance branches by the maintainer.

Maintenance releases continue on an as-needed basis depending on urgency and impact.

### v4.2 Stable Series

**v4.2** is the current stable release series and receives active development, bug fixes, and security updates. This is the recommended version for production use.

### v4.1 Maintenance

**v4.1** has entered **maintenance mode**, now maintained by [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920), a long-time Fluent Bit contributor and core developer.

**v4.1** will receive security updates and critical fixes until **February 28, 2026** (as specified in [SECURITY.md](SECURITY.md)).

### v4.0 Maintenance

**v4.0** reached **End-of-Life (EOL)** on **December 23, 2025** and is no longer maintained. No further security patches or bug fixes will be provided for this version line.

---

## How to Contribute to Maintained Versions

If you're submitting a fix or feature relevant to a stable or maintenance branch (v4.2 or v4.1):

- Open your PR against the `master` branch
- Add a note in the PR or issue: `Target: v4.2` or `Target: v4.1`
- Tag the branch maintainer to request backport consideration:
  - For v4.2: [@edsiper](https://github.com/edsiper) [@cosmo0920](https://github.com/cosmo0920)
  - For v4.1: [@cosmo0920](https://github.com/cosmo0920)

> **Note:** v4.0 is End-of-Life and no longer accepts backports. For security-related issues, please follow the process outlined in [SECURITY.md](SECURITY.md).
