# Fluent Bit Maintenance Policy

This document outlines the maintenance strategy and version support for Fluent Bit.
For how releases, backports and container image rebuilds are carried out, see the
[Maintainers Guide](MAINTAINERS_GUIDE.md).

## Active Branches and Maintainers

| Branch     | Version | Status           | Maintainer                                                  | Notes                                                              |
|------------|---------|------------------|-------------------------------------------------------------|--------------------------------------------------------------------|
| `master`   | v6.0.x  | Development      | [Eduardo Silva](https://github.com/edsiper)                 | Planned for March 2027. All new features and bug fixes land here first. |
| `5.2`      | v5.2.x  | Stable           | [Eduardo Silva](https://github.com/edsiper)                 | Current stable release series. |
| `5.1`      | v5.1.x  | Maintenance only | [Eduardo Silva](https://github.com/edsiper)                 | Critical bug fixes, security fixes, and selected low-risk backports. |
| `5.0`      | v5.0.x  | Maintenance only | [Eduardo Silva](https://github.com/edsiper) [Hiroshi Hatake (@cosmo0920)](https://github.com/cosmo0920) | Critical bug fixes, security fixes, and selected low-risk backports until **November 30, 2026**. |

---

## Maintenance Policy

The `master` branch tracks development of **v6.0.0**. Fluent Bit **v5.2** is
the current stable release series and is tracked in the `5.2` branch. The
**v5.1** and **v5.0** branches receive critical bug fixes, security updates,
and selected low-risk backports until their End-of-Maintenance dates. Older
release lines are End-of-Life (EOL).

### Accepted Changes for Maintenance Branches

- ✅ Security patches (see [SECURITY.md](SECURITY.md) for security update timelines)
- ✅ Critical bug fixes
- ✅ Low-risk enhancements that unblock adoption (e.g., OpenTelemetry improvements, performance tuning)

> ⚠️ All changes must first be merged into `master` before being cherry-picked into maintenance branches by the maintainer.

Maintenance releases continue on an as-needed basis depending on urgency and impact.

### v6.0 Development

**v6.0.0** is under development in `master` and is planned for **March 2027**.

### v5.2 Stable Series

**v5.2** is the current stable release series and is recommended for production
use. New features and bug fixes land in `master` first.

### v5.1 Maintenance

**v5.1** receives critical bug fixes, security updates, and selected low-risk
backports. Its End-of-Maintenance date will be announced when finalized.

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
