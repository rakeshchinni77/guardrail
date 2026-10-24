"""Standalone runner for GuardRail Phase 9 Report Pipeline.

Generates any missing submission reports and runs the full automated
cross-report consistency validator across all 10 hackathon artifacts.
"""

import sys
from pathlib import Path

# Ensure repo root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.reporting.generators import generate_all_reports  # noqa: E402
from app.reporting.validator import (  # noqa: E402
    CrossReportValidationError,
    ReportPipelineValidator,
)


def main() -> int:
    reports_dir = REPO_ROOT / "reports"
    print(f"[Phase 9] Generating any missing reports in {reports_dir}...")
    generated = generate_all_reports(reports_dir)
    for name, path in generated.items():
        print(f"  - Generated/verified: {name} -> {path.relative_to(REPO_ROOT)}")

    print("[Phase 9] Running cross-report consistency validator across 10 artifacts...")
    validator = ReportPipelineValidator(REPO_ROOT)
    try:
        audit = validator.validate_all()
        print("\n=== PHASE 9 VALIDATION AUDIT PASSED ===")
        print(f"Status: {audit['overall_status']}")
        print(f"Artifacts Checked: {len(audit['artifacts_checked'])}")
        for art, res in audit["artifacts_checked"].items():
            print(f"  [PASS] {art}: {res}")
        scan_st = audit["secret_scan"]["status"]
        scan_cnt = audit["secret_scan"]["scanned_files_count"]
        print(f"Secret Scan: {scan_st} ({scan_cnt} files scanned, 0 unmasked canaries)")
        print(f"Cross-Report Consistency: {audit['cross_report_consistency']}")
        return 0
    except CrossReportValidationError as exc:
        print(f"\n[FAIL] Cross-Report Validation Error: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"\n[ERROR] Unexpected error during validation: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
