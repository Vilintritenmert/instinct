# Security policy

instinct is experimental. Its scanner produces review signals and can miss malicious content;
neither a clean scan nor an agent's SAFE verdict is a security guarantee. See the
[limitations](README.md#-limitations) and [coverage contract](skills/how-deep-the-rabbit-hole-goes/references/coverage.md).

## Supported versions

Security fixes target the latest package version on the default branch, currently **0.11.0**.
Older versions have no promised backports. Update before checking whether a problem is still present,
and retain the version/commit and scanned target hash with your report.

## Reporting a vulnerability privately

For vulnerabilities in instinct, sensitive scanner bypasses, unintended execution, or exposure of
credentials or target data, use GitHub's private
[Report a vulnerability form](https://github.com/Vilintritenmert/instinct/security/advisories/new).
Sign in to GitHub; the form is available only when the repository's private vulnerability reporting
setting is enabled.

If the form is unavailable, open a minimal
[issue](https://github.com/Vilintritenmert/instinct/issues) asking the maintainer to enable private
reporting or provide a private contact. Include no exploit details, payloads, credentials or target
data in that public request. Wait for a private channel before sharing sensitive evidence.

Include in the private report:

- Package version or commit, operating system, and PowerShell version.
- The scanner command/options or agent audit steps that reproduce the issue.
- Expected versus actual behavior and the potential impact.
- A minimal inert reproduction using `example.invalid` or reserved documentation IPs.
- Relevant `RuleId`, severity, `ScanComplete` and `CoverageIssues` values, if applicable.

Sanitize reports and attachments: scanner output can contain file paths, domains, evidence quoted
from targets and file inventory metadata. Do not send real secrets or run a harmful payload to
demonstrate the problem. There is no guaranteed response or fix timeline.

## Ordinary detection reports

False positives and missed patterns that can be demonstrated entirely with harmless synthetic text
may be reported in public [issues](https://github.com/Vilintritenmert/instinct/issues). Use the private
route when a report includes sensitive target details or a consequential exploit. Vulnerabilities in
a third-party target belong with that target's maintainer; do not publish its private data here.

## Maintainer release check

Before public release, enable GitHub private vulnerability reporting and verify the report form.
This policy does not enable repository settings; until that check is complete, use the fallback above.
