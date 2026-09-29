"""ENC-001 (unencrypted EBS/RDS) and RDS-001 (publicly accessible RDS)."""

from __future__ import annotations

from ..model import CheckMeta
from .registry import check

ENC_001 = CheckMeta(
    id="ENC-001",
    title="Unencrypted EBS volumes or RDS instances",
    service="EBS/RDS",
    severity="HIGH",
    description=(
        "EBS volumes and RDS instances without encryption at rest expose data via snapshots, "
        "shared images and decommissioned media. Also flags regions where EBS encryption by "
        "default is off, which lets new unencrypted volumes appear."
    ),
    remediation=(
        "Enable EBS encryption by default in every region (`aws ec2 enable-ebs-encryption-by-default`). "
        "Migrate existing volumes and databases via encrypted snapshot copy and restore, using a "
        "customer-managed KMS key where key control matters."
    ),
    cis=("2.2.1", "2.3.1"),
    iso27001=("A.8.24", "A.5.34"),
    nis2=("Art. 21(2)(h)",),
)

RDS_001 = CheckMeta(
    id="RDS-001",
    title="RDS instance publicly accessible",
    service="RDS",
    severity="HIGH",
    description=(
        "PubliclyAccessible=true gives the database endpoint a public IP address. Combined with a "
        "permissive security group this exposes the database engine directly to the internet."
    ),
    remediation=(
        "Set `--no-publicly-accessible` (`aws rds modify-db-instance`), place the instance in "
        "private subnets and reach it via the application tier, a bastion-free SSM tunnel or VPN."
    ),
    cis=("2.3.3",),
    iso27001=("A.8.20", "A.8.3"),
    nis2=("Art. 21(2)(e)", "Art. 21(2)(i)"),
)


@check(ENC_001)
def unencrypted_storage(ctx, out):
    def per_region(region: str) -> None:
        default = ctx.run("ec2", "get-ebs-encryption-by-default", region=region) or {}
        if not default.get("EbsEncryptionByDefault"):
            out.add("LOW", f"account/{region}", "EBS encryption by default is disabled.", region)
        volumes = (ctx.run("ec2", "describe-volumes", region=region) or {}).get("Volumes", [])
        for vol in volumes:
            out.evaluated += 1
            if not vol.get("Encrypted"):
                attached = [a.get("InstanceId") for a in vol.get("Attachments", [])]
                note = f" (attached to {', '.join(attached)})" if attached else " (unattached)"
                out.add("HIGH", vol["VolumeId"], "EBS volume is not encrypted" + note + ".", region)
        dbs = (ctx.run("rds", "describe-db-instances", region=region) or {}).get("DBInstances", [])
        for db in dbs:
            out.evaluated += 1
            if not db.get("StorageEncrypted"):
                out.add("HIGH", db["DBInstanceIdentifier"],
                        f"RDS instance ({db.get('Engine', 'unknown')}) has no storage encryption.",
                        region)
    ctx.each_region(out, per_region)


@check(RDS_001)
def public_rds(ctx, out):
    def per_region(region: str) -> None:
        dbs = (ctx.run("rds", "describe-db-instances", region=region) or {}).get("DBInstances", [])
        for db in dbs:
            out.evaluated += 1
            if db.get("PubliclyAccessible"):
                endpoint = (db.get("Endpoint") or {}).get("Address", "no endpoint yet")
                out.add("HIGH", db["DBInstanceIdentifier"],
                        f"RDS instance is publicly accessible ({endpoint}).", region)
    ctx.each_region(out, per_region)
