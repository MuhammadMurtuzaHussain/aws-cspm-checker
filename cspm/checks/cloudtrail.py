"""LOG-001: CloudTrail coverage."""

from __future__ import annotations

from ..model import CheckMeta
from ..runner import AwsError
from .registry import check

META = CheckMeta(
    id="LOG-001",
    title="No active multi-region CloudTrail",
    service="CloudTrail",
    severity="HIGH",
    description=(
        "Without a logging, multi-region trail, API activity in unused regions goes unrecorded and "
        "incident response has no audit trail. Trails without log file validation cannot prove "
        "their logs were not altered."
    ),
    remediation=(
        "Create an organisation or multi-region trail with log file validation, delivered to a "
        "dedicated, access-restricted S3 bucket (`aws cloudtrail create-trail --is-multi-region-trail "
        "--enable-log-file-validation`) and start logging."
    ),
    cis=("3.1", "3.2"),
    iso27001=("A.8.15", "A.8.16"),
    nis2=("Art. 21(2)(b)",),
)


@check(META)
def cloudtrail_enabled(ctx, out):
    trails = (ctx.run("cloudtrail", "describe-trails", "--include-shadow-trails") or {}).get(
        "trailList", [])
    out.evaluated += len(trails) or 1
    active_multi = []
    for trail in trails:
        try:
            status = ctx.run("cloudtrail", "get-trail-status", "--name", trail["TrailARN"])
        except AwsError as exc:
            out.error(f"{trail.get('Name')}: {exc}")
            continue
        if trail.get("IsMultiRegionTrail") and (status or {}).get("IsLogging"):
            active_multi.append(trail)
    if not active_multi:
        if not trails:
            out.add("HIGH", "account", "No CloudTrail trails exist.")
        elif not out.errors:
            out.add("HIGH", "account",
                    "No trail is both multi-region and actively logging.")
        return
    for trail in active_multi:
        if not trail.get("LogFileValidationEnabled"):
            out.add("LOW", trail["Name"], "Log file validation is disabled.",
                    trail.get("HomeRegion", "global"))
