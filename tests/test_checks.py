import base64
import json
from datetime import datetime, timezone
from pathlib import Path

from cspm.checks import all_checks, execute
from cspm.context import Context
from cspm.runner import AwsError, FixtureRunner

FIXTURE = Path(__file__).resolve().parent.parent / "fixtures" / "demo-account.json"
NOW = datetime(2026, 9, 29, tzinfo=timezone.utc)


def run_check(check_id, responses, regions=("eu-west-1",), **kw):
    ctx = Context(FixtureRunner(responses), regions=list(regions), now=NOW, sleep=lambda s: None, **kw)
    meta, fn = next((m, f) for m, f in all_checks() if m.id == check_id)
    return execute(meta, fn, ctx)


def demo_results():
    responses = json.loads(FIXTURE.read_text())["responses"]
    ctx = Context(FixtureRunner(responses), now=NOW)
    return {m.id: execute(m, f, ctx) for m, f in all_checks()}


def test_exactly_ten_checks_with_unique_ids_and_mappings():
    checks = all_checks()
    assert len(checks) == 10
    assert len({m.id for m, _ in checks}) == 10
    for meta, _ in checks:
        assert meta.iso27001 and meta.nis2 and meta.remediation


def test_demo_account_expected_findings():
    res = demo_results()
    assert {k: len(v.findings) for k, v in res.items()} == {
        "EC2-001": 3, "EC2-002": 2, "ENC-001": 4, "IAM-001": 0, "IAM-002": 1,
        "IAM-003": 2, "IAM-004": 2, "LOG-001": 1, "RDS-001": 1, "S3-001": 3}
    assert res["IAM-001"].status == "PASS"
    assert all(r.status != "ERROR" for r in res.values())


# --- S3 ---------------------------------------------------------------------------------

def s3_fixture(pab, policy_public=False, uris=(), account_pab=None):
    grants = [{"Grantee": {"URI": "http://acs.amazonaws.com/groups/global/" + u}, "Permission": "READ"}
              for u in uris]
    return {
        "*|sts get-caller-identity": {"Account": "1"},
        "*|s3control get-public-access-block --account-id 1": (
            {"PublicAccessBlockConfiguration": account_pab} if account_pab
            else {"__error__": "NoSuchPublicAccessBlockConfiguration"}),
        "*|s3api list-buckets": {"Buckets": [{"Name": "b"}]},
        "*|s3api get-public-access-block --bucket b": (
            {"PublicAccessBlockConfiguration": pab} if pab
            else {"__error__": "NoSuchPublicAccessBlockConfiguration"}),
        "*|s3api get-bucket-policy-status --bucket b": (
            {"PolicyStatus": {"IsPublic": True}} if policy_public else {"__error__": "NoSuchBucketPolicy"}),
        "*|s3api get-bucket-acl --bucket b": {"Grants": grants},
    }


ALL_ON = dict(BlockPublicAcls=True, IgnorePublicAcls=True, BlockPublicPolicy=True, RestrictPublicBuckets=True)


def test_s3_account_level_block_overrides_public_policy():
    r = run_check("S3-001", s3_fixture(None, policy_public=True, account_pab=ALL_ON))
    assert r.status == "PASS"


def test_s3_authenticated_users_acl_is_public():
    r = run_check("S3-001", s3_fixture(None, uris=["AuthenticatedUsers"]))
    assert r.findings[0].severity == "CRITICAL"
    assert "AuthenticatedUsers:READ" in r.findings[0].message


def test_s3_ignore_public_acls_neutralises_acl():
    pab = dict(ALL_ON, BlockPublicPolicy=False)
    r = run_check("S3-001", s3_fixture(pab, uris=["AllUsers"]))
    assert [f.severity for f in r.findings] == ["MEDIUM"]


def test_s3_access_denied_is_not_reported_as_pass():
    resp = s3_fixture(ALL_ON)
    resp["*|s3api get-bucket-acl --bucket b"] = {"__error__": "AccessDenied"}
    assert run_check("S3-001", resp).status == "ERROR"


# --- Security groups --------------------------------------------------------------------

def sg_resp(perms):
    return {"eu-west-1|ec2 describe-security-groups": {"SecurityGroups": [
                {"GroupId": "sg-1", "GroupName": "t", "IpPermissions": perms}]}}


def test_sg_port_range_containing_22_is_flagged():
    perms = [{"IpProtocol": "tcp", "FromPort": 20, "ToPort": 30, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
              "Ipv6Ranges": []}]
    assert len(run_check("EC2-001", sg_resp(perms)).findings) == 1
    assert "FTP (21)" in run_check("EC2-002", sg_resp(perms)).findings[0].message


def test_sg_web_ports_and_private_cidrs_pass():
    perms = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
              "Ipv6Ranges": []},
             {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
              "Ipv6Ranges": []},
             {"IpProtocol": "icmp", "FromPort": -1, "ToPort": -1, "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
              "Ipv6Ranges": []}]
    assert run_check("EC2-001", sg_resp(perms)).status == "PASS"
    assert run_check("EC2-002", sg_resp(perms)).status == "PASS"


def test_all_traffic_rule_reported_once_by_ec2_001_not_002():
    perms = [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}]
    assert len(run_check("EC2-001", sg_resp(perms)).findings) == 1
    assert run_check("EC2-002", sg_resp(perms)).status == "PASS"


def test_disabled_region_is_recorded_not_fatal():
    resp = sg_resp([])
    resp["us-east-1|ec2 describe-security-groups"] = {"__error__": "AuthFailure"}
    r = run_check("EC2-001", resp, regions=("eu-west-1", "us-east-1"))
    assert r.status == "ERROR" and r.evaluated == 1


# --- IAM --------------------------------------------------------------------------------

def cred_resp(rows):
    header = "user,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated," \
             "access_key_2_active,access_key_2_last_rotated"
    body = "\n".join([header] + [",".join(r) for r in rows])
    return {"*|iam get-credential-report": {"Content": base64.b64encode(body.encode()).decode()}}


def test_key_age_boundary_and_custom_limit():
    rows = [["u", "false", "false", "true", "2026-07-01T00:00:00+00:00", "false", "N/A"]]  # 90 days
    assert run_check("IAM-003", cred_resp(rows)).status == "PASS"
    assert run_check("IAM-003", cred_resp(rows), max_key_age_days=30).status == "FAIL"


def test_inactive_keys_ignored():
    rows = [["u", "false", "false", "false", "2020-01-01T00:00:00+00:00", "false", "N/A"]]
    assert run_check("IAM-003", cred_resp(rows)).status == "PASS"


def test_root_row_excluded_from_user_checks():
    rows = [["<root_account>", "not_supported", "false", "false", "N/A", "false", "N/A"]]
    assert run_check("IAM-002", cred_resp(rows)).status == "PASS"


def test_credential_report_is_generated_when_missing():
    calls = []

    class Runner(FixtureRunner):
        def run(self, *args, region=None):
            calls.append(args)
            if args[1] == "get-credential-report" and calls.count(args) == 1:
                raise AwsError("ReportNotPresent", "iam get-credential-report")
            if args[1] == "generate-credential-report":
                return {"State": "STARTED"}
            return super().run(*args, region=region)

    ctx = Context(Runner(cred_resp([["u", "true", "true", "false", "N/A", "false", "N/A"]])),
                  sleep=lambda s: None)
    assert ctx.credential_report()[0]["user"] == "u"
    assert ("iam", "generate-credential-report") in calls


def test_password_policy_missing_and_strong():
    assert run_check("IAM-004", {"*|iam get-account-password-policy": {"__error__": "NoSuchEntity"}}
                     ).findings[0].message.startswith("No custom")
    strong = {"PasswordPolicy": {"MinimumPasswordLength": 14, "PasswordReusePrevention": 24}}
    assert run_check("IAM-004", {"*|iam get-account-password-policy": strong}).status == "PASS"


def test_root_keys_and_mfa():
    resp = {"*|iam get-account-summary": {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 2}}}
    assert len(run_check("IAM-001", resp).findings) == 2


# --- CloudTrail -------------------------------------------------------------------------

def trail_resp(trails, logging=True):
    return {"*|cloudtrail describe-trails --include-shadow-trails": {"trailList": trails},
            "*|cloudtrail get-trail-status --name arn:t": {"IsLogging": logging}}


def test_cloudtrail_variants():
    good = {"Name": "t", "TrailARN": "arn:t", "IsMultiRegionTrail": True, "LogFileValidationEnabled": True}
    assert run_check("LOG-001", trail_resp([good])).status == "PASS"
    assert run_check("LOG-001", trail_resp([good], logging=False)).findings[0].severity == "HIGH"
    assert run_check("LOG-001", trail_resp([dict(good, IsMultiRegionTrail=False)])).status == "FAIL"
    no_val = run_check("LOG-001", trail_resp([dict(good, LogFileValidationEnabled=False)]))
    assert [f.severity for f in no_val.findings] == ["LOW"]
