import argparse

from .parser import parse_file
from .analyzer import analyze_events
from .detector import detect_suspicious_activity
from .reporter import generate_report, save_report


def main():

    parser = argparse.ArgumentParser(
        description="SentinelLog - Security Log Analyzer"
    )

    parser.add_argument(
        "log_file",
        help="Path to authentication log file"
    )

    parser.add_argument(
        "-o",
        "--output",
        default="reports/security_report.txt",
        help="Output report path"
    )

    args = parser.parse_args()

    events = parse_file(args.log_file)

    statistics = analyze_events(events)

    suspicious = detect_suspicious_activity(events)

    report = generate_report(
        statistics,
        suspicious,
        args.log_file
    )

    print(report)

    save_report(
        report,
        args.output
    )

    print(
        f"\nReport saved to: {args.output}"
    )


if __name__ == "__main__":
    main()