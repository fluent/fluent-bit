# 🔒 Security Policy

Fluent Bit maintains active security support for a limited set of release lines. Security updates are provided for the versions listed below until their End-of-Maintenance (EOM) dates.

## Supported Versions

| Version   | Status     | Security Updates Until |
|-----------|------------|------------------------|
| **5.1.x** | ✅ Active  | To be announced        |
| **5.0.x** | ✅ Active  | **November 30, 2026**  |
| **4.2.x** | ❌ EOL     | **July 30, 2026**      |
| **4.1.x** | ❌ EOL     | **February 28, 2026**  |
| **4.0.x** | ❌ EOL     | **December 23, 2025**  |
| **3.2.x** | ❌ EOL     | —                      |
| **< 3.2** | ❌ EOL     | —                      |

> **Note:** 4.2 and earlier are End-of-Life (EOL) and receive no further fixes.
> The v5.1 End-of-Maintenance date will be published when it is finalized.

---

## Maintenance & Backport Policy

- We backport **critical** and **high-severity** security fixes to all **Active** branches listed above.
- Medium/low-severity fixes may be backported at the maintainers’ discretion.
- After a branch reaches **EOM**, no further patches are published for that line.
- Users are strongly encouraged to use the latest **5.1.x** release.

---

## 🐳 Container Images

The official images, `fluent/fluent-bit` on Docker Hub and `ghcr.io/fluent/fluent-bit`, ship
Fluent Bit on top of a base image: Distroless for production images and Debian for `-debug`
images. Base image packages receive security fixes on their own schedule, so a scanner can
report findings in a published image that are not vulnerabilities in Fluent Bit.

- Images of the three most recent release series are rebuilt on updated base images when a
  base image fix is available, without a new Fluent Bit release. The Fluent Bit binary is
  rebuilt from the same release tag.
- The version tag, for example `5.2.0`, moves to the newest build. Pull it again to pick up
  a rebuild.
- Every build also has a dated tag that never moves, for example `5.2.0-20261117`. Use it,
  or the image digest, to pin an exact build.

Two wiki pages are generated from the registries:

- [Container images](https://github.com/fluent/fluent-bit/wiki/Container-Images): every
  build of every maintained release, with its tags, digests and build date.
- [Container image security status](https://github.com/fluent/fluent-bit/wiki/Container-Image-Security-Status):
  known critical and high findings of the current images, split into fixable by a rebuild
  and not fixed by the base image distribution yet.

When a scanner reports a finding in a container image:

1. Compare the digest you run with the current build in the image index. If a newer build
   exists, pull the tag again.
2. Check the security status page. A finding listed as not fixed yet has no fixed package
   available, so a rebuild cannot remove it.
3. If a fix is available and the current build does not include it, open a
   [GitHub issue](https://github.com/fluent/fluent-bit/issues) asking for an image rebuild
   and include the image tag, digest and CVE identifier. These findings are already public,
   so they do not need a private report.

Vulnerabilities in Fluent Bit itself follow the private process below.

---

## 📣 Reporting a Vulnerability

Please report suspected vulnerabilities **privately**:

- Email: **fluentbit-security@googlegroups.com**
- Include: affected versions, environment, clear reproduction steps, logs/traces, and impact assessment if known.

**Please do not** file public GitHub issues for security reports.

**Response targets** (best effort):
- **Acknowledgement:** within 72 hours
- **Initial assessment:** within 7 days
- **Fix/Advisory:** coordinated with reporter; timing depends on severity and scope

---

## 🔐 Coordinated Disclosure

- We work with reporters to validate issues, develop fixes, and publish coordinated advisories.
- Public disclosure occurs once a fix or acceptable mitigation is available, or by mutual agreement.

---

## 📢 Security Announcements

- Security advisories and related notices are shared via:
  - GitHub **Security Advisories** on the Fluent Bit repo
  - GitHub **Discussions**: <https://github.com/fluent/fluent-bit/discussions>

For third-party CVEs that may impact Fluent Bit, we will post an assessment and any required guidance through the channels above.

---

_Last updated: November 17, 2026_
