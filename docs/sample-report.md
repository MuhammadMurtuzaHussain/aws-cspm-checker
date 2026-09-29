# AWS cloud security posture report

Account `123456789012` · generated 2026-09-29 12:00 UTC · tool v0.1.0 · **demo data, not a real account**
Regions: eu-west-1, us-east-1

## Summary

19 findings (5 critical, 8 high, 5 medium, 1 low). 1 of 10 checks passed, 9 failed, 0 could not be assessed.

| Check | Status | Findings | Title |
|---|---|---|---|
| EC2-001 | FAIL | 3 | Security group exposes SSH/RDP to the internet |
| EC2-002 | FAIL | 2 | Security group exposes databases or legacy services to the internet |
| ENC-001 | FAIL | 4 | Unencrypted EBS volumes or RDS instances |
| IAM-001 | PASS | 0 | Root account has access keys or no MFA |
| IAM-002 | FAIL | 1 | IAM users with console access but no MFA |
| IAM-003 | FAIL | 2 | IAM access keys not rotated within the maximum age |
| IAM-004 | FAIL | 2 | Weak or missing account password policy |
| LOG-001 | FAIL | 1 | No active multi-region CloudTrail |
| RDS-001 | FAIL | 1 | RDS instance publicly accessible |
| S3-001 | FAIL | 3 | S3 bucket publicly accessible or Block Public Access incomplete |

## EC2-001: Security group exposes SSH/RDP to the internet

Mappings: CIS AWS v3.0 5.2, 5.3 · ISO/IEC 27001:2022 A.8.20, A.8.22, A.8.9 · NIS2 Art. 21(2)(e), Art. 21(2)(g)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| CRITICAL | `sg-0a1b2c3d (ssh-anywhere)` | eu-west-1 | tcp/22 open to 0.0.0.0/0: exposes SSH (22). |
| CRITICAL | `sg-0a1b2c3e (rdp-ipv6)` | eu-west-1 | tcp/3389 open to ::/0: exposes RDP (3389). |
| CRITICAL | `sg-0b9c8d7e (default)` | us-east-1 | all traffic open to 0.0.0.0/0: exposes SSH (22), RDP (3389). |

**Remediation:** Restrict the source to a corporate CIDR or remove the rule; use SSM Session Manager or EC2 Instance Connect Endpoint instead of inbound admin ports.

## EC2-002: Security group exposes databases or legacy services to the internet

Mappings: CIS AWS v3.0 5.2 · ISO/IEC 27001:2022 A.8.20, A.8.22, A.8.3 · NIS2 Art. 21(2)(e), Art. 21(2)(i)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| HIGH | `sg-0a1b2c40 (orders-db-open)` | eu-west-1 | tcp/3306 open to 0.0.0.0/0: exposes MySQL (3306). |
| HIGH | `sg-0b9c8d7f (redis-cache)` | us-east-1 | tcp/6379 open to 0.0.0.0/0: exposes Redis (6379). |

**Remediation:** Move the service into a private subnet and allow only application security groups as the source. Never publish data stores directly.

## ENC-001: Unencrypted EBS volumes or RDS instances

Mappings: CIS AWS v3.0 2.2.1, 2.3.1 · ISO/IEC 27001:2022 A.8.24, A.5.34 · NIS2 Art. 21(2)(h)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| HIGH | `orders-prod` | eu-west-1 | RDS instance (mysql) has no storage encryption. |
| HIGH | `vol-0aa1` | eu-west-1 | EBS volume is not encrypted (attached to i-0123456789abcdef0). |
| HIGH | `vol-0bb1` | us-east-1 | EBS volume is not encrypted (unattached). |
| LOW | `account/eu-west-1` | eu-west-1 | EBS encryption by default is disabled. |

**Remediation:** Enable EBS encryption by default in every region (`aws ec2 enable-ebs-encryption-by-default`). Migrate existing volumes and databases via encrypted snapshot copy and restore, using a customer-managed KMS key where key control matters.

## IAM-002: IAM users with console access but no MFA

Mappings: CIS AWS v3.0 1.10 · ISO/IEC 27001:2022 A.8.5 · NIS2 Art. 21(2)(j)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| HIGH | `bob` | global | Console password enabled but no MFA device registered. |

**Remediation:** Require MFA through a policy condition (`aws:MultiFactorAuthPresent`) or, better, federate humans through IAM Identity Center and remove IAM user passwords.

## IAM-003: IAM access keys not rotated within the maximum age

Mappings: CIS AWS v3.0 1.14 · ISO/IEC 27001:2022 A.5.17, A.8.5 · NIS2 Art. 21(2)(g), Art. 21(2)(i)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| MEDIUM | `bob/key1` | global | Active access key is 330 days old (limit 90). |
| MEDIUM | `ci-deployer/key1` | global | Active access key is 622 days old (limit 90). |

**Remediation:** Rotate or delete stale keys. Prefer short-lived credentials (roles, OIDC federation for CI/CD) over static keys.

## IAM-004: Weak or missing account password policy

Mappings: CIS AWS v3.0 1.8, 1.9 · ISO/IEC 27001:2022 A.5.17 · NIS2 Art. 21(2)(g)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| MEDIUM | `account` | global | Minimum password length is 8; 14 or more is expected. |
| MEDIUM | `account` | global | Password reuse prevention remembers 0 passwords; 24 is expected. |

**Remediation:** `aws iam update-account-password-policy --minimum-password-length 14 --password-reuse-prevention 24`.

## LOG-001: No active multi-region CloudTrail

Mappings: CIS AWS v3.0 3.1, 3.2 · ISO/IEC 27001:2022 A.8.15, A.8.16 · NIS2 Art. 21(2)(b)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| HIGH | `account` | global | No CloudTrail trails exist. |

**Remediation:** Create an organisation or multi-region trail with log file validation, delivered to a dedicated, access-restricted S3 bucket (`aws cloudtrail create-trail --is-multi-region-trail --enable-log-file-validation`) and start logging.

## RDS-001: RDS instance publicly accessible

Mappings: CIS AWS v3.0 2.3.3 · ISO/IEC 27001:2022 A.8.20, A.8.3 · NIS2 Art. 21(2)(e), Art. 21(2)(i)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| HIGH | `orders-prod` | eu-west-1 | RDS instance is publicly accessible (orders-prod.abc123.eu-west-1.rds.amazonaws.com). |

**Remediation:** Set `--no-publicly-accessible` (`aws rds modify-db-instance`), place the instance in private subnets and reach it via the application tier, a bastion-free SSM tunnel or VPN.

## S3-001: S3 bucket publicly accessible or Block Public Access incomplete

Mappings: CIS AWS v3.0 2.1.4 · ISO/IEC 27001:2022 A.5.15, A.8.3, A.8.20 · NIS2 Art. 21(2)(i)

| Severity | Resource | Region | Finding |
|---|---|---|---|
| CRITICAL | `acme-legacy-uploads` | global | Publicly accessible: ACL grants AllUsers:READ. |
| CRITICAL | `acme-public-assets` | global | Publicly accessible: bucket policy grants public access. |
| MEDIUM | `acme-app-logs` | global | Not currently public, but Block Public Access is missing: IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets. |

**Remediation:** Enable all four Block Public Access settings at account level (`aws s3control put-public-access-block`) and per bucket; remove public ACL grants and wildcard principals; serve public content through CloudFront with Origin Access Control.
