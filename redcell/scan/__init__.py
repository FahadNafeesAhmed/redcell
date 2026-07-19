"""redcell scanning: ingest -> candidates (taint) -> LLM confirm -> findings."""

from .findings import Finding
from .runner import ScanReport, scan

__all__ = ["scan", "ScanReport", "Finding"]
