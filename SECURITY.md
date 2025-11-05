# 🔒 Security Policy

Fluent Bit maintains active security support for a limited set of release lines. Security updates are provided for the versions listed below until their End-of-Maintenance (EOM) dates.

## Supported Versions

| Version   | Status     | Security Updates Until |
|-----------|------------|------------------------|
| **4.2.x** | ✅ Active  | **June 30, 2026**      |
| **4.1.x** | ✅ Active  | **March 31, 2026**     |
| **4.0.x** | ✅ Active  | **December 31, 2025**  |
| **3.2.x** | ❌ EOL     | —                      |
| **< 3.2** | ❌ EOL     | —                      |

> **Note:** 3.2 and earlier are End-of-Life (EOL) and receive no further fixes.

---

## Maintenance & Backport Policy

- We backport **critical** and **high-severity** security fixes to all **Active** branches listed above.
- Medium/low-severity fixes may be backported at the maintainers’ discretion.
- After a branch reaches **EOM**, no further patches are published for that line.
- Users are strongly encouraged to keep current with the latest **4.x** release line.

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

_Last updated: October 17, 2025_