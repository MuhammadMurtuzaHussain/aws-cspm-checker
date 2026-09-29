"""Regenerates fixtures/demo-account.json: a fictional, deliberately misconfigured AWS account.

Every value is invented. Account ID 123456789012 is AWS's documentation placeholder.
"""
import base64
import csv
import io
import json
from pathlib import Path

ACCT = "123456789012"
R1, R2 = "eu-west-1", "us-east-1"


def key(region, *args):
    return f"{region or '*'}|{' '.join(args)}"


def sg(gid, name, perms):
    return {"GroupId": gid, "GroupName": name, "IpPermissions": perms}


def perm(proto, lo, hi, v4=None, v6=None):
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in (v4 or [])],
         "Ipv6Ranges": [{"CidrIpv6": c} for c in (v6 or [])]}
    if proto != "-1":
        p["FromPort"], p["ToPort"] = lo, hi
    return p


def bucket_calls(name, pab, policy_public, acl_uris):
    r = {}
    r[key(None, "s3api", "get-public-access-block", "--bucket", name)] = (
        {"PublicAccessBlockConfiguration": pab} if pab is not None
        else {"__error__": "NoSuchPublicAccessBlockConfiguration"})
    r[key(None, "s3api", "get-bucket-policy-status", "--bucket", name)] = (
        {"PolicyStatus": {"IsPublic": True}} if policy_public else {"__error__": "NoSuchBucketPolicy"})
    grants = [{"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/" + u},
               "Permission": "READ"} for u in acl_uris]
    grants.append({"Grantee": {"Type": "CanonicalUser", "ID": "owner"}, "Permission": "FULL_CONTROL"})
    r[key(None, "s3api", "get-bucket-acl", "--bucket", name)] = {"Grants": grants}
    return r


def cred_report():
    cols = ["user", "arn", "user_creation_time", "password_enabled", "password_last_used",
            "mfa_active", "access_key_1_active", "access_key_1_last_rotated",
            "access_key_2_active", "access_key_2_last_rotated"]
    rows = [
        ["<root_account>", f"arn:aws:iam::{ACCT}:root", "2022-03-01T09:00:00+00:00", "not_supported",
         "2026-09-01T10:00:00+00:00", "false", "false", "N/A", "false", "N/A"],
        ["alice", f"arn:aws:iam::{ACCT}:user/alice", "2024-01-10T09:00:00+00:00", "true",
         "2026-09-28T08:00:00+00:00", "true", "true", "2026-08-01T09:00:00+00:00", "false", "N/A"],
        ["bob", f"arn:aws:iam::{ACCT}:user/bob", "2024-05-02T09:00:00+00:00", "true",
         "2026-09-20T08:00:00+00:00", "false", "true", "2025-11-03T09:00:00+00:00", "false", "N/A"],
        ["ci-deployer", f"arn:aws:iam::{ACCT}:user/ci-deployer", "2023-06-15T09:00:00+00:00", "false",
         "N/A", "false", "true", "2025-01-15T09:00:00+00:00", "true", "2026-09-01T09:00:00+00:00"],
    ]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    w.writerows(rows)
    return base64.b64encode(buf.getvalue().encode()).decode()


r = {}
r[key(None, "sts", "get-caller-identity")] = {
    "Account": ACCT, "Arn": f"arn:aws:iam::{ACCT}:user/demo-auditor", "UserId": "AIDAEXAMPLE"}
r[key(None, "ec2", "describe-regions")] = {"Regions": [{"RegionName": R1}, {"RegionName": R2}]}

# S3
buckets = ["acme-public-assets", "acme-legacy-uploads", "acme-app-logs", "acme-secure-data"]
r[key(None, "s3control", "get-public-access-block", "--account-id", ACCT)] = {
    "__error__": "NoSuchPublicAccessBlockConfiguration"}
r[key(None, "s3api", "list-buckets")] = {"Buckets": [{"Name": b} for b in buckets]}
r.update(bucket_calls("acme-public-assets", None, True, []))
r.update(bucket_calls("acme-legacy-uploads", None, False, ["AllUsers"]))
r.update(bucket_calls("acme-app-logs", {"BlockPublicAcls": True, "IgnorePublicAcls": False,
                                        "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
                      False, []))
r.update(bucket_calls("acme-secure-data", {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                           "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
                      False, []))

# Security groups
r[key(R1, "ec2", "describe-security-groups")] = {"SecurityGroups": [
    sg("sg-0a1b2c3d", "ssh-anywhere", [perm("tcp", 22, 22, ["0.0.0.0/0"])]),
    sg("sg-0a1b2c3e", "rdp-ipv6", [perm("tcp", 3389, 3389, v6=["::/0"])]),
    sg("sg-0a1b2c3f", "public-web", [perm("tcp", 80, 80, ["0.0.0.0/0"]), perm("tcp", 443, 443, ["0.0.0.0/0"])]),
    sg("sg-0a1b2c40", "orders-db-open", [perm("tcp", 3306, 3306, ["0.0.0.0/0"])]),
    sg("sg-0a1b2c41", "internal-ssh", [perm("tcp", 22, 22, ["10.0.0.0/8"])]),
]}
r[key(R2, "ec2", "describe-security-groups")] = {"SecurityGroups": [
    sg("sg-0b9c8d7e", "default", [perm("-1", None, None, ["0.0.0.0/0"])]),
    sg("sg-0b9c8d7f", "redis-cache", [perm("tcp", 6379, 6379, ["0.0.0.0/0"])]),
]}

# EBS / RDS
r[key(R1, "ec2", "get-ebs-encryption-by-default")] = {"EbsEncryptionByDefault": False}
r[key(R2, "ec2", "get-ebs-encryption-by-default")] = {"EbsEncryptionByDefault": True}
r[key(R1, "ec2", "describe-volumes")] = {"Volumes": [
    {"VolumeId": "vol-0aa1", "Encrypted": False, "Attachments": [{"InstanceId": "i-0123456789abcdef0"}]},
    {"VolumeId": "vol-0aa2", "Encrypted": True, "Attachments": []}]}
r[key(R2, "ec2", "describe-volumes")] = {"Volumes": [
    {"VolumeId": "vol-0bb1", "Encrypted": False, "Attachments": []}]}
r[key(R1, "rds", "describe-db-instances")] = {"DBInstances": [
    {"DBInstanceIdentifier": "orders-prod", "Engine": "mysql", "StorageEncrypted": False,
     "PubliclyAccessible": True, "Endpoint": {"Address": "orders-prod.abc123.eu-west-1.rds.amazonaws.com"}},
    {"DBInstanceIdentifier": "reporting", "Engine": "postgres", "StorageEncrypted": True,
     "PubliclyAccessible": False, "Endpoint": {"Address": "reporting.abc123.eu-west-1.rds.amazonaws.com"}}]}
r[key(R2, "rds", "describe-db-instances")] = {"DBInstances": []}

# IAM
r[key(None, "iam", "get-account-summary")] = {"SummaryMap": {
    "AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0, "Users": 3}}
r[key(None, "iam", "get-credential-report")] = {"Content": cred_report(), "ReportFormat": "text/csv"}
r[key(None, "iam", "get-account-password-policy")] = {"PasswordPolicy": {
    "MinimumPasswordLength": 8, "RequireSymbols": False, "RequireNumbers": True,
    "RequireUppercaseCharacters": False, "RequireLowercaseCharacters": True, "ExpirePasswords": False}}

# CloudTrail
r[key(None, "cloudtrail", "describe-trails", "--include-shadow-trails")] = {"trailList": []}

out = {"meta": {"description": "Fictional demo account. All data is invented.", "now": "2026-09-29T12:00:00+00:00"},
       "responses": r}
path = Path(__file__).resolve().parent.parent / "fixtures" / "demo-account.json"
path.write_text(json.dumps(out, indent=1))
print("wrote", path)
