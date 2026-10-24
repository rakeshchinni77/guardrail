"""Generator and schema validator for reports/concurrency.json."""

import json
from pathlib import Path
from typing import Any

from app.concurrency.schemas import ConcurrencyReportSchema


class ConcurrencyReportGenerator:
    """Serializes and validates reports/concurrency.json conforming to Contract 10."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or Path("reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, report_data: ConcurrencyReportSchema | dict[str, Any]) -> Path:
        """Validate report schema and persist reports/concurrency.json."""
        if isinstance(report_data, dict):
            validated = ConcurrencyReportSchema.model_validate(report_data)
        else:
            validated = report_data

        target_path = self.output_dir / "concurrency.json"
        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(validated.model_dump(), f, indent=2)

        return target_path
