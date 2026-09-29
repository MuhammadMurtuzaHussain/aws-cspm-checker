"""EC2-001 / EC2-002: security groups open to the internet."""

from __future__ import annotations

from typing import Iterator, List, Optional, Tuple

from ..model import CheckMeta
from .registry import check

ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
# Data stores and legacy/insecure services that should never face the internet.
SENSITIVE_PORTS = {
    21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
    1433: "MSSQL", 1521: "Oracle", 2049: "NFS", 3306: "MySQL", 5432: "PostgreSQL",
    5601: "Kibana", 5984: "CouchDB", 6379: "Redis", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}

EC2_001 = CheckMeta(
    id="EC2-001",
    title="Security group exposes SSH/RDP to the internet",
    service="EC2",
    severity="CRITICAL",
    description=(
        "Ingress from 0.0.0.0/0 or ::/0 to a range containing port 22 or 3389 (including "
        "all-traffic rules) exposes remote administration to internet-wide brute force and "
        "credential-stuffing."
    ),
    remediation=(
        "Restrict the source to a corporate CIDR or remove the rule; use SSM Session Manager or "
        "EC2 Instance Connect Endpoint instead of inbound admin ports."
    ),
    cis=("5.2", "5.3"),
    iso27001=("A.8.20", "A.8.22", "A.8.9"),
    nis2=("Art. 21(2)(e)", "Art. 21(2)(g)"),
)

EC2_002 = CheckMeta(
    id="EC2-002",
    title="Security group exposes databases or legacy services to the internet",
    service="EC2",
    severity="HIGH",
    description=(
        "Ingress from 0.0.0.0/0 or ::/0 to data-store or legacy service ports (e.g. MySQL, "
        "PostgreSQL, Redis, MongoDB, Elasticsearch, SMB, Telnet). Ports 80 and 443 are ignored."
    ),
    remediation=(
        "Move the service into a private subnet and allow only application security groups as "
        "the source. Never publish data stores directly."
    ),
    cis=("5.2",),
    iso27001=("A.8.20", "A.8.22", "A.8.3"),
    nis2=("Art. 21(2)(e)", "Art. 21(2)(i)"),
)


def _world_rules(sg: dict) -> Iterator[Tuple[str, Optional[int], Optional[int], str]]:
    """Yield (protocol, from_port, to_port, source) for every world-open TCP/UDP/all rule."""
    for perm in sg.get("IpPermissions", []):
        proto = str(perm.get("IpProtocol"))
        if proto not in ("-1", "tcp", "udp", "6", "17"):
            continue
        sources = [r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
        sources += [r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]
        for src in sources:
            if proto == "-1":
                yield "all", 0, 65535, src
            else:
                name = {"6": "tcp", "17": "udp"}.get(proto, proto)
                yield name, perm.get("FromPort", 0), perm.get("ToPort", 65535), src


def _describe(proto: str, lo: int, hi: int) -> str:
    if proto == "all":
        return "all traffic"
    return f"{proto}/{lo}" if lo == hi else f"{proto}/{lo}-{hi}"


def _scan(ctx, out, ports: dict, severity: str, skip_wide: bool) -> None:
    def per_region(region: str) -> None:
        groups = (ctx.run("ec2", "describe-security-groups", region=region) or {}).get(
            "SecurityGroups", [])
        for sg in groups:
            out.evaluated += 1
            for proto, lo, hi, src in _world_rules(sg):
                hits: List[str] = [f"{n} ({p})" for p, n in sorted(ports.items()) if lo <= p <= hi]
                if not hits:
                    continue
                if skip_wide and (proto == "all" or (hi - lo) > 1000):
                    continue  # wide/all-traffic rules are already reported by EC2-001
                out.add(severity, f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                        f"{_describe(proto, lo, hi)} open to {src}: exposes {', '.join(hits)}.",
                        region)
    ctx.each_region(out, per_region)


@check(EC2_001)
def sg_admin_ports(ctx, out):
    _scan(ctx, out, ADMIN_PORTS, "CRITICAL", False)


@check(EC2_002)
def sg_sensitive_ports(ctx, out):
    _scan(ctx, out, SENSITIVE_PORTS, "HIGH", True)
