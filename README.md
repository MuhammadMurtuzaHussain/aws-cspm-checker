# aws-cspm-checker

A read-only cloud security posture checker for AWS. It drives the AWS CLI, evaluates ten common misconfigurations across all enabled regions, and produces console, JSON, Markdown and HTML reports with each finding mapped to CIS, ISO/IEC 27001:2022 and NIS2 Article 21 references.

It is deliberately small: Python standard library only, no SDK, no agents, no write calls. Every check is a short function you can read in a minute.

## Try it without an AWS account

```bash
./aws-posture-check --demo
```

This scans a bundled, fictional account (`fixtures/demo-account.json`) that is misconfigured on purpose. A rendered example is in [`docs/sample-report.html`](docs/sample-report.html) and [`docs/sample-report.md`](docs/sample-report.md).

## Run it against a real account

Prerequisites: AWS CLI v2, Python 3.9+, and credentials for a role that has the read-only policy in [`policies/cspm-readonly-policy.json`](policies/cspm-readonly-policy.json).

```bash
aws sso login --profile audit
./aws-posture-check --profile audit --format console,html,json --output-dir reports
```

Useful options:

| Option | Purpose |
|---|---|
| `--regions eu-west-1,eu-west-2` | Limit the scan (default: every enabled region) |
| `--checks S3-001,EC2-001` / `--skip LOG-001` | Run or skip specific checks |
| `--fail-on critical\|high\|medium\|low\|none` | Severity threshold for a non-zero exit (default `high`) |
| `--max-key-age 60` | Access key age limit in days (default 90) |
| `--list-checks` | Print the ten checks |

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` usage or credential error, `3` one or more checks could not be assessed (for example access denied). A check that cannot run is reported as **not assessed**, never as a pass.

## The ten checks

| ID | Misconfiguration | Worst severity |
|---|---|---|
| S3-001 | Public S3 bucket, or Block Public Access incomplete | Critical |
| EC2-001 | Security group exposes SSH/RDP (22/3389) to `0.0.0.0/0` or `::/0` | Critical |
| EC2-002 | Security group exposes databases or legacy services to the internet | High |
| ENC-001 | Unencrypted EBS volumes or RDS instances; EBS default encryption off | High |
| RDS-001 | RDS instance publicly accessible | High |
| IAM-001 | Root account has access keys or no MFA | Critical |
| IAM-002 | Console users without MFA | High |
| IAM-003 | Access keys older than the limit | Medium |
| IAM-004 | Weak or missing password policy (length under 14, reuse under 24) | Medium |
| LOG-001 | No active multi-region CloudTrail; log file validation off | High |

Full detail, remediation and framework mappings: [`docs/checks.md`](docs/checks.md).

## Design notes

- **Effective exposure, not just configuration.** S3-001 combines account-level and bucket-level Block Public Access with the bucket policy status and ACL grants, so a bucket that is protected by an account-level block is not reported as public, and one that merely lacks the guardrails is reported as Medium rather than Critical.
- **Fail closed on visibility.** Access denied and disabled regions surface as *not assessed* with exit code 3, so a partial scan cannot look like a clean one.
- **Password policy follows current guidance.** IAM-004 checks length and reuse only. It does not demand forced rotation or composition rules, in line with NIST SP 800-63B.
- **Testable without cloud access.** The runner is pluggable. Tests use canned CLI output, and one test runs the real subprocess path and the bash wrapper against a fake `aws` executable.

## Layout

```
aws-posture-check     bash wrapper: preflight, credential and root-user warning
cspm/                 runner, context, ten checks (checks/), report renderers, CLI
fixtures/             fictional demo account
policies/             least-privilege read-only IAM policy
tools/                fixture and docs generators
tests/                25 pytest cases
```

Development: `pip install -r requirements-dev.txt`, then `make check`.

## Known limitations

- Security groups are evaluated whether or not they are attached to a resource; an unused group with an open rule is still reported.
- No check for network ACLs, VPC endpoint policies, KMS key policies, or Organizations-level controls (SCPs, delegated admin trails beyond what `describe-trails` returns).
- Calls are sequential. Accounts with thousands of buckets will be slow; parallelising per-bucket calls is the obvious next step.
- Framework mappings are indicative and should be verified against the benchmark version you audit against.

## Ideas for extension

Add checks for IAM policies with `Action: *` on `Resource: *`, unused credentials, GuardDuty and Security Hub status, and KMS key rotation. An Azure equivalent using `az` could reuse the runner, model and report layers unchanged.

## Ethics and scope

Run this only against accounts you own or are authorised to assess. It makes read-only API calls, with one exception: `iam generate-credential-report` creates a credential report, which is a harmless but logged action.

Licence: MIT.
