"""S3-001: publicly accessible buckets."""

from __future__ import annotations

from ..model import CheckMeta
from ..runner import AwsError
from .registry import check

META = CheckMeta(
    id="S3-001",
    title="S3 bucket publicly accessible or Block Public Access incomplete",
    service="S3",
    severity="CRITICAL",
    description=(
        "A bucket is public if its policy or ACL grants access to everyone (or any AWS account) "
        "and S3 Block Public Access does not override it. Buckets without all four Block Public "
        "Access settings are one policy change away from exposure."
    ),
    remediation=(
        "Enable all four Block Public Access settings at account level "
        "(`aws s3control put-public-access-block`) and per bucket; remove public ACL grants and "
        "wildcard principals; serve public content through CloudFront with Origin Access Control."
    ),
    cis=("2.1.4",),
    iso27001=("A.5.15", "A.8.3", "A.8.20"),
    nis2=("Art. 21(2)(i)",),
)

PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GROUPS = ("AllUsers", "AuthenticatedUsers")
NO_PAB = ("NoSuchPublicAccessBlockConfiguration",)


def _pab(data) -> dict:
    return (data or {}).get("PublicAccessBlockConfiguration", {}) or {}


@check(META)
def s3_public_buckets(ctx, out):
    account_pab = _pab(ctx.run("s3control", "get-public-access-block",
                               "--account-id", ctx.account_id(), ignore=NO_PAB))
    for bucket in (ctx.run("s3api", "list-buckets") or {}).get("Buckets", []):
        name = bucket["Name"]
        out.evaluated += 1
        try:
            bucket_pab = _pab(ctx.run("s3api", "get-public-access-block", "--bucket", name,
                                      ignore=NO_PAB))
            eff = {k: bool(account_pab.get(k) or bucket_pab.get(k)) for k in PAB_KEYS}
            status = ctx.run("s3api", "get-bucket-policy-status", "--bucket", name,
                             ignore=("NoSuchBucketPolicy",))
            policy_public = bool(((status or {}).get("PolicyStatus") or {}).get("IsPublic"))
            acl = ctx.run("s3api", "get-bucket-acl", "--bucket", name) or {}
        except AwsError as exc:
            out.error(f"{name}: {exc}")
            continue

        acl_grants = sorted(
            f"{g['Grantee']['URI'].rsplit('/', 1)[-1]}:{g['Permission']}"
            for g in acl.get("Grants", [])
            if g.get("Grantee", {}).get("URI", "").rsplit("/", 1)[-1] in PUBLIC_GROUPS
        )
        via_policy = policy_public and not eff["RestrictPublicBuckets"]
        via_acl = bool(acl_grants) and not eff["IgnorePublicAcls"]

        if via_policy or via_acl:
            how = []
            if via_policy:
                how.append("bucket policy grants public access")
            if via_acl:
                how.append("ACL grants " + ", ".join(acl_grants))
            out.add("CRITICAL", name, "Publicly accessible: " + "; ".join(how) + ".")
        else:
            missing = [k for k in PAB_KEYS if not eff[k]]
            if missing:
                out.add("MEDIUM", name,
                        "Not currently public, but Block Public Access is missing: "
                        + ", ".join(missing) + ".")
