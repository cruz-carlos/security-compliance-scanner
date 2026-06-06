import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3", region_name="us-east-1")
ec2 = boto3.client("ec2", region_name="us-east-1")


# ─── S3 Checks ───────────────────────────────────────────────────────────────

def check_s3_public_access():
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            if not all([
                config.get("BlockPublicAcls"),
                config.get("IgnorePublicAcls"),
                config.get("BlockPublicPolicy"),
                config.get("RestrictPublicBuckets"),
            ]):
                findings.append({
                    "resource": name,
                    "issue": "S3 bucket does not have all public access blocks enabled",
                    "severity": "HIGH",
                })
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append({
                    "resource": name,
                    "issue": "S3 bucket has no public access block configuration",
                    "severity": "HIGH",
                })

    return findings


def check_s3_encryption():
    """Check all S3 buckets for default encryption."""
    findings = []
    buckets = s3.list_buckets().get("Buckets", [])

    for bucket in buckets:
        name = bucket["Name"]
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                findings.append({
                    "resource": name,
                    "issue": "S3 bucket does not have default encryption enabled",
                    "severity": "MEDIUM",
                })

    return findings


# ─── EC2 / Security Group Checks ─────────────────────────────────────────────

def check_open_security_groups():
    """Check for security groups that allow unrestricted inbound access."""
    findings = []
    groups = ec2.describe_security_groups().get("SecurityGroups", [])

    # Ports commonly left open by mistake
    risky_ports = [22, 3389, 80, 443, 3306, 5432]

    for group in groups:
        gid = group["GroupId"]
        gname = group["GroupName"]

        for rule in group.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") == "0.0.0.0/0":
                    for port in risky_ports:
                        if from_port <= port <= to_port:
                            findings.append({
                                "resource": f"{gid} ({gname})",
                                "issue": f"Security group allows unrestricted inbound access on port {port}",
                                "severity": "HIGH" if port in [22, 3389, 3306, 5432] else "MEDIUM",
                            })

            # Also catch IPv6 open rules
            for ipv6_range in rule.get("Ipv6Ranges", []):
                if ipv6_range.get("CidrIpv6") == "::/0":
                    for port in risky_ports:
                        if from_port <= port <= to_port:
                            findings.append({
                                "resource": f"{gid} ({gname})",
                                "issue": f"Security group allows unrestricted IPv6 inbound access on port {port}",
                                "severity": "HIGH" if port in [22, 3389, 3306, 5432] else "MEDIUM",
                            })

    return findings


def check_unencrypted_ebs_volumes():
    """Check for EBS volumes that are not encrypted."""
    findings = []
    volumes = ec2.describe_volumes().get("Volumes", [])

    for vol in volumes:
        if not vol.get("Encrypted"):
            findings.append({
                "resource": vol["VolumeId"],
                "issue": "EBS volume is not encrypted",
                "severity": "MEDIUM",
            })

    return findings


# ─── IAM Checks ──────────────────────────────────────────────────────────────

def check_iam_root_access_keys():
    """Check if the root account has active access keys."""
    findings = []
    iam = boto3.client("iam", region_name="us-east-1")

    # get_account_summary returns a count of root access keys
    summary = iam.get_account_summary().get("SummaryMap", {})
    if summary.get("AccountAccessKeysPresent", 0) > 0:
        findings.append({
            "resource": "root account",
            "issue": "Root account has active access keys. Use IAM users instead.",
            "severity": "CRITICAL",
        })

    return findings


# ─── Run all checks ───────────────────────────────────────────────────────────

def run_all_checks():
    """Run every check and return a combined list of findings."""
    all_findings = []

    check_functions = [
        ("S3 Public Access",       check_s3_public_access),
        ("S3 Encryption",          check_s3_encryption),
        ("Open Security Groups",   check_open_security_groups),
        ("Unencrypted EBS",        check_unencrypted_ebs_volumes),
        ("Root Access Keys",       check_iam_root_access_keys),
    ]

    for label, fn in check_functions:
        try:
            results = fn()
            all_findings.extend(results)
        except Exception as e:
            # Log the error but keep running other checks
            all_findings.append({
                "resource": label,
                "issue": f"Check failed to run: {e}",
                "severity": "ERROR",
            })

    return all_findings