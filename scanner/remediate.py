import boto3

s3 = boto3.client("s3", region_name="us-east-1")
ec2 = boto3.client("ec2", region_name="us-east-1")


# ─── S3 Remediation ───────────────────────────────────────────────────────────

def fix_s3_public_access(bucket_name):
    try:
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        print(f"  [FIXED] Public access blocked on bucket: {bucket_name}")
        return True
    except Exception as e:
        print(f"  [FAILED] Could not fix public access on {bucket_name}: {e}")
        return False


def fix_s3_encryption(bucket_name):
    try:
        s3.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            },
        )
        print(f"  [FIXED] Default encryption enabled on bucket: {bucket_name}")
        return True
    except Exception as e:
        print(f"  [FAILED] Could not enable encryption on {bucket_name}: {e}")
        return False


# ─── EC2 Remediation ─────────────────────────────────────────────────────────

def fix_open_security_group(group_id, port):
    try:
        response = ec2.describe_security_groups(GroupIds=[group_id])
        group = response["SecurityGroups"][0]

        for rule in group.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)

            if from_port <= port <= to_port:
                open_ipv4 = [r for r in rule.get("IpRanges", []) if r.get("CidrIp") == "0.0.0.0/0"]
                open_ipv6 = [r for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") == "::/0"]

                if open_ipv4 or open_ipv6:
                    revoke_rule = {
                        "IpProtocol": rule.get("IpProtocol", "tcp"),
                        "FromPort": from_port,
                        "ToPort": to_port,
                        "IpRanges": open_ipv4,
                        "Ipv6Ranges": open_ipv6,
                    }
                    ec2.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[revoke_rule],
                    )
                    print(f"  [FIXED] Removed open inbound rule on port {port} from {group_id}")
                    return True

        print(f"  [SKIP] No open rule found for port {port} on {group_id}")
        return False

    except Exception as e:
        print(f"  [FAILED] Could not fix security group {group_id}: {e}")
        return False


# ─── Remediation runner ───────────────────────────────────────────────────────

def run_remediation(findings):
    print("\n" + "=" * 60)
    print("  Running Auto-Remediation")
    print("=" * 60 + "\n")

    fixed = 0
    skipped = 0

    for finding in findings:
        severity = finding["severity"]
        resource = finding["resource"]
        issue = finding["issue"]

        if severity not in ["CRITICAL", "HIGH"]:
            print(f"  [SKIP] {severity} finding skipped (manual review recommended): {resource}")
            skipped += 1
            continue

        if "public access block" in issue.lower():
            result = fix_s3_public_access(resource)

        elif "encryption" in issue.lower() and "s3" in issue.lower():
            result = fix_s3_encryption(resource)

        elif "security group" in issue.lower() and "port" in issue.lower():
            group_id = resource.split(" ")[0]
            port = int(issue.split("port ")[-1])
            result = fix_open_security_group(group_id, port)

        elif "root account" in resource.lower():
            print("  [MANUAL] Root access key must be removed manually in the AWS console.")
            skipped += 1
            continue

        else:
            print(f"  [SKIP] No auto-remediation available for: {issue}")
            skipped += 1
            continue

        if result:
            fixed += 1

    print(f"\n  Remediation complete. Fixed: {fixed}  Skipped: {skipped}\n")