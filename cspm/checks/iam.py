"""IAM-001..004: root account, MFA, key age, password policy."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from ..model import CheckMeta
from .registry import check

IAM_001 = CheckMeta(
    id="IAM-001",
    title="Root account has access keys or no MFA",
    service="IAM",
    severity="CRITICAL",
    description=(
        "The root user cannot be constrained by IAM policy. Long-lived root access keys, or root "
        "without MFA, make credential theft equivalent to full account takeover."
    ),
    remediation=(
        "Delete root access keys, register a hardware or passkey MFA device for root, store the "
        "credentials offline, and use IAM Identity Center roles for daily work."
    ),
    cis=("1.4", "1.5"),
    iso27001=("A.8.2", "A.8.5"),
    nis2=("Art. 21(2)(j)", "Art. 21(2)(i)"),
)

IAM_002 = CheckMeta(
    id="IAM-002",
    title="IAM users with console access but no MFA",
    service="IAM",
    severity="HIGH",
    description="Console passwords without a second factor fall to phishing and password reuse.",
    remediation=(
        "Require MFA through a policy condition (`aws:MultiFactorAuthPresent`) or, better, "
        "federate humans through IAM Identity Center and remove IAM user passwords."
    ),
    cis=("1.10",),
    iso27001=("A.8.5",),
    nis2=("Art. 21(2)(j)",),
)

IAM_003 = CheckMeta(
    id="IAM-003",
    title="IAM access keys not rotated within the maximum age",
    service="IAM",
    severity="MEDIUM",
    description="Active access keys older than the threshold (default 90 days) widen the window for misuse of leaked keys.",
    remediation=(
        "Rotate or delete stale keys. Prefer short-lived credentials (roles, OIDC federation for "
        "CI/CD) over static keys."
    ),
    cis=("1.14",),
    iso27001=("A.5.17", "A.8.5"),
    nis2=("Art. 21(2)(g)", "Art. 21(2)(i)"),
)

IAM_004 = CheckMeta(
    id="IAM-004",
    title="Weak or missing account password policy",
    service="IAM",
    severity="MEDIUM",
    description=(
        "Checks for a minimum length of 14 and password reuse prevention of 24, following the CIS "
        "benchmark. Forced periodic expiry and composition rules are deliberately not required, "
        "in line with current NIST SP 800-63B guidance."
    ),
    remediation=(
        "`aws iam update-account-password-policy --minimum-password-length 14 "
        "--password-reuse-prevention 24`."
    ),
    cis=("1.8", "1.9"),
    iso27001=("A.5.17",),
    nis2=("Art. 21(2)(g)",),
)


def _parse(ts: str) -> Optional[datetime]:
    if not ts or ts in ("N/A", "not_supported", "no_information"):
        return None
    return datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)


@check(IAM_001)
def root_account(ctx, out):
    summary = ctx.run("iam", "get-account-summary")["SummaryMap"]
    out.evaluated += 1
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        out.add("CRITICAL", "root", "Root account has active access keys.")
    if not summary.get("AccountMFAEnabled", 0):
        out.add("CRITICAL", "root", "MFA is not enabled on the root account.")


@check(IAM_002)
def users_without_mfa(ctx, out):
    for row in ctx.credential_report():
        if row["user"] == "<root_account>":
            continue
        out.evaluated += 1
        if row.get("password_enabled") == "true" and row.get("mfa_active") != "true":
            out.add("HIGH", row["user"], "Console password enabled but no MFA device registered.")


@check(IAM_003)
def stale_access_keys(ctx, out):
    limit = ctx.max_key_age_days
    for row in ctx.credential_report():
        if row["user"] == "<root_account>":
            continue
        out.evaluated += 1
        for n in ("1", "2"):
            if row.get(f"access_key_{n}_active") != "true":
                continue
            rotated = _parse(row.get(f"access_key_{n}_last_rotated", ""))
            if rotated is None:
                continue
            age = (ctx.now - rotated).days
            if age > limit:
                out.add("MEDIUM", f"{row['user']}/key{n}",
                        f"Active access key is {age} days old (limit {limit}).")


@check(IAM_004)
def password_policy(ctx, out):
    out.evaluated += 1
    data = ctx.run("iam", "get-account-password-policy", ignore=("NoSuchEntity",))
    if data is None:
        out.add("MEDIUM", "account", "No custom password policy is set (AWS defaults apply).")
        return
    policy = data["PasswordPolicy"]
    length = policy.get("MinimumPasswordLength", 0)
    if length < 14:
        out.add("MEDIUM", "account", f"Minimum password length is {length}; 14 or more is expected.")
    reuse = policy.get("PasswordReusePrevention", 0)
    if reuse < 24:
        out.add("MEDIUM", "account",
                f"Password reuse prevention remembers {reuse} passwords; 24 is expected.")
