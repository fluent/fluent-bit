# Fluent Bit Maintenance Policy

This document outlines the maintenance strategy and version support for Fluent Bit.

## Active Branches and Maintainers

| Branch     | Version            | Status              | Maintainer                                                  | Notes                                                              |
|------------|--------------------|---------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| `master`   | v4.1 (development) | Active development  | [Eduardo Silva](https://github.com/edsiper)                 | All new features and bug fixes land here first                     |
| `4.0`      | v4.0.x             | Maintenance only    | [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920) | Critical fixes and safe backports only. Maintained until **Dec 31, 2025** |

---

## v4.0 Maintenance Policy

As of **July 2025**, active development has moved to Fluent Bit **v4.1** (tracked in the `master` branch).

**v4.0** has entered **maintenance mode**, now maintained by [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920), a long-time Fluent Bit contributor and core developer.

Maintenance for v4.0 will continue until **December 31, 2025**, which is three months after the official v4.1 release.

### Accepted Changes for v4.0

- ✅ Security patches
- ✅ Critical bug fixes
- ✅ Low-risk enhancements that unblock adoption (e.g., OpenTelemetry improvements, performance tuning)

> ⚠️ All changes must first be merged into `master` before being cherry-picked into the `4.0` branch by the maintainer.

v4.0 releases will continue on an as-needed basis depending on urgency and impact.

---

## How to Contribute to Maintained Versions

If you're submitting a fix or feature relevant to v4.0:

- Open your PR against the `master` branch
- Add a note in the PR or issue: `Target: v4.0`
- Tag [@cosmo0920](https://github.com/cosmo0920) to request backport consideration
