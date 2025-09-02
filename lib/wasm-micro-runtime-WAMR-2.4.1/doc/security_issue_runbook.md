# Security Issue Runbook

This runbook provides step-by-step guidance on handling a security advisory. Typically, it begins with a draft security advisory when we initiate the process outlined in this runbook. The draft security advisory is created by a contributor or a maintainer.

For information on what types of issues are considered security vulnerabilities and require a security advisory for resolution, please refer to [identifying a security issue](./security_need_to_know.md#identifying-a-security-issue).

## Step 1: Initial Response to Security Advisory

- Receive Security Advisory: When a new security advisory is received, the Incident Manager, typically the maintainer who opened the advisory, becomes the first responder. If the advisory was opened by someone else, a maintainer should take on the role of Incident Manager. The Incident Manager can hand off this role to another maintainer if necessary.
- Acknowledge Receipt: The Incident Manager should promptly acknowledge receipt of the advisory and communicate that the investigation will begin immediately. Security issues are the highest priority.

## Step 2: Investigating the Vulnerability

- Identify the Vulnerability: Reproduce the issue to understand the vulnerability. Determine which versions and platforms are affected. Fill out the advisory details with this information.
- Accept the Report: Accept the security report and create a temporary private fork to collaborate on a fix. Invite necessary helpers and stakeholders to this fork, as their input can be valuable.

## Step 3: Communication and Collaboration

- Use Non-Public Channels: Communicate through non-public channels, preferably email, during the resolution process. Avoid filing issues or pull requests on third-party repositories if they are involved.
- Workaround for Third-Party Dependencies: If third-party dependencies are involved, consider a workaround to patch the issue quickly unless the third party can release a fix promptly.

## Step 4: Finalizing and Preparing for Release

- Finalize Details: Once a fix is developed and the vulnerability is fully understood, finalize the advisory details and prepare for public release. Ensure the security issues are resolved in the private fork.
- Request CVE: Use the Big Green Button on the advisory to request a CVE number from GitHub staff.
- Advanced Disclosure Email: Decide on a disclosure date, typically within a week, and send an email to sec-announce@bytecodealliance.org about the upcoming security release. Other ways are also available to communicate the disclosure date.

## Step 5: Preparing and Testing Patch Releases

- Prepare PRs for Patch Releases: Create pull requests in the private fork for each version being patched. Ensure each PR is ready to apply cleanly and includes release notes for each release branch.
- Run Full Test Suite: Run the full test suite locally for the main branch. Attempt to run as much of the CI matrix locally as possible.

## Step 6: Public Release and Communication

- Open Version Bump PRs: Open version bump pull requests on the public repository without including patch notes or release notes for the fix.
- Manually Make PRs from Private Fork: Transfer the necessary pull requests from the private fork to the public repository.
- Merge and Trigger Releases: Merge the version bump PRs and trigger the release process.
- Publish GitHub Advisories: Delete the private forks and use the Big Green Button to publish the advisory.
- Send Security Release Email: Send a follow-up email to sec-announce@bytecodealliance.org describing the security release. Other communication channels can also be used to inform users about the security release.

By following these steps, you can effectively manage and resolve security issues for your open source project, ensuring timely communication and collaboration while maintaining the integrity and security of your software.

## References

- [Vulnerability Response Runbook](https://github.com/bytecodealliance/rfcs/blob/main/accepted/vulnerability-response-runbook.md)
- [Wasmtime Security Vulnerability Runbook](https://docs.wasmtime.dev/security-vulnerability-runbook.html)
