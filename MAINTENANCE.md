# Fluent Bit Maintenance Policy

This document outlines the maintenance strategy and version support for Fluent Bit.

## Active Branches and Maintainers

| Branch     | Version | Status           | Maintainer                                                  | Notes                                                              |
|------------|---------|------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| `master`   | v5.1.x  | Stable           | [Eduardo Silva](https://github.com/edsiper)                 | Current stable release series. All new features and bug fixes land here first. |
| `5.0`      | v5.0.x  | Maintenance only | [Eduardo Silva](https://github.com/edsiper) [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920) | Critical bug fixes, security fixes, and selected low-risk backports until **November 30, 2026**. |

---

## Maintenance Policy

Fluent Bit **v5.1** is the current stable release series and is tracked in the
`master` branch. The **v5.0** branch is in maintenance mode and receives bug
fixes, security updates, and selected low-risk backports until its
End-of-Maintenance date. Older release lines are End-of-Life (EOL).

### Accepted Changes for Maintenance Branches

- ✅ Security patches (see [SECURITY.md](SECURITY.md) for security update timelines)
- ✅ Critical bug fixes
- ✅ Low-risk enhancements that unblock adoption (e.g., OpenTelemetry improvements, performance tuning)

> ⚠️ All changes must first be merged into `master` before being cherry-picked into maintenance branches by the maintainer.

Maintenance releases continue on an as-needed basis depending on urgency and impact.

### v5.1 Stable Series

**v5.1** is the current stable release series and is recommended for production
use. New features and bug fixes land in `master` first.

### v5.0 Maintenance

**v5.0** is in **maintenance mode** and receives critical bug fixes, security
updates, and selected low-risk backports until **November 30, 2026** (as
specified in [SECURITY.md](SECURITY.md)).

### v4.2 End-of-Life

**v4.2** reached **End-of-Life (EOL)** on **July 30, 2026** and is no longer
maintained.

### v4.1 End-of-Life

**v4.1** reached **End-of-Life (EOL)** on **February 28, 2026** and is no longer
maintained.

### v4.0 End-of-Life

**v4.0** reached **End-of-Life (EOL)** on **December 23, 2025** and is no longer maintained. No further security patches or bug fixes will be provided for this version line.

---

## How to Contribute to Maintained Versions

If you're submitting a fix or feature relevant to a stable or maintenance
branch:

- Open your PR against the `master` branch
- For a v5.0 backport, add `Target: v5.0` to the PR or issue and tag
  [@edsiper](https://github.com/edsiper) or
  [@cosmo0920](https://github.com/cosmo0920)

> **Note:** v4.2 and earlier are End-of-Life and no longer accept backports. For
> security-related issues, follow the process outlined in
> [SECURITY.md](SECURITY.md).
