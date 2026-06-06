import json
import datetime
from checks import run_all_checks
import remediate as rem


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "ERROR": 3}


def print_report(findings):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    print("\n" + "=" * 60)
    print("  AWS Security Compliance Report")
    print(f"  {timestamp}")
    print("=" * 60)

    if not findings:
        print("\n  No issues found. All checks passed.\n")
        return

    sorted_findings = sorted(findings, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    counts = {}
    for f in findings:
        sev = f["severity"]
        counts[sev] = counts.get(sev, 0) + 1

    print(f"\n  Total findings: {len(findings)}")
    for sev, count in counts.items():
        print(f"    {sev}: {count}")

    print("\n" + "-" * 60)

    for finding in sorted_findings:
        sev = finding["severity"]
        print(f"\n  [{sev}]")
        print(f"  Resource : {finding['resource']}")
        print(f"  Issue    : {finding['issue']}")

    print("\n" + "=" * 60 + "\n")


def save_report(findings):
    timestamp = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    filename = f"report_{timestamp}.json"

    output = {
        "generated_at": timestamp,
        "total_findings": len(findings),
        "findings": findings,
    }

    with open(filename, "w") as f:
        json.dump(output, f, indent=2)

    print(f"  Report saved to {filename}")
    return filename


def handler(event, context):
    """Lambda entry point."""
    findings = run_all_checks()
    rem.run_remediation(findings)
    return {
        "statusCode": 200,
        "body": json.dumps({
            "total_findings": len(findings),
            "findings": findings,
        }),
    }


def main():
    print("Running AWS security checks...")
    findings = run_all_checks()
    print_report(findings)
    save_report(findings)
    rem.run_remediation(findings)

    critical_or_high = [f for f in findings if f["severity"] in ["CRITICAL", "HIGH"]]
    if critical_or_high:
        exit(1)


if __name__ == "__main__":
    main()