#!/usr/bin/env python3
"""
CLI script to run detection engine benchmark evaluation.
"""
import argparse
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.analyzer.benchmark.runner import DetectionBenchmarkRunner


def main():
    parser = argparse.ArgumentParser(description="TENET AI Detection Engine Benchmark Runner")
    parser.add_argument(
        "--dataset",
        type=str,
        default="data/benchmark_dataset.json",
        help="Path to labeled evaluation dataset JSON (default: data/benchmark_dataset.json)"
    )
    parser.add_argument(
        "--output-json",
        type=str,
        default="reports/benchmark_latest.json",
        help="Path to output JSON benchmark report (default: reports/benchmark_latest.json)"
    )
    parser.add_argument(
        "--output-md",
        type=str,
        default="reports/benchmark_latest.md",
        help="Path to output Markdown benchmark report (default: reports/benchmark_latest.md)"
    )
    parser.add_argument(
        "--baseline",
        type=str,
        default=None,
        help="Path to baseline benchmark JSON report to compare against for regressions"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Classification risk score threshold (default: 0.5)"
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit with non-zero status if regressions are detected"
    )
    parser.add_argument(
        "--min-f1",
        type=float,
        default=0.50,
        help="Minimum required F1 score threshold when checking regressions (default: 0.50)"
    )

    parser.add_argument(
        "--min-precision",
        type=float,
        default=0.85,
        help="Minimum required Precision threshold when checking regressions (default: 0.85)"
    )

    args = parser.parse_args()

    runner = DetectionBenchmarkRunner(dataset_path=args.dataset)
    print(f"🚀 Starting Detection Engine Benchmark using dataset: {args.dataset}")
    
    report = runner.run(threshold=args.threshold)

    # Check for regressions before writing report files to prevent baseline path collision
    regressions = runner.check_regression(
        current_report=report,
        baseline_path=args.baseline,
        min_f1=args.min_f1,
        min_precision=args.min_precision
    )

    output_json_path = Path(args.output_json)
    output_json_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    md_content = runner.generate_markdown_report(report)
    output_md_path = Path(args.output_md)
    output_md_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"✅ Benchmark report saved to JSON: {output_json_path}")
    print(f"✅ Benchmark report saved to Markdown: {output_md_path}\n")
    print(md_content)


    if regressions:
        print("⚠️ REGRESSION / QUALITY AUDIT WARNINGS DETECTED:")
        for reg in regressions:
            print(f"  - {reg}")
        if args.fail_on_regression:
            print("❌ Benchmark failed due to quality regressions!")
            sys.exit(1)
    else:
        print("🎉 Benchmark passed with no regressions!")


if __name__ == "__main__":
    main()
