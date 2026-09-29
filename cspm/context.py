"""Shared state for a scan: runner, options, call cache, region list."""

from __future__ import annotations

import base64
import csv
import io
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence

from .model import Outcome
from .runner import AwsError


class Context:
    def __init__(self, runner, regions: Optional[Sequence[str]] = None,
                 max_key_age_days: int = 90, now: Optional[datetime] = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.runner = runner
        self._regions = list(regions) if regions else None
        self.max_key_age_days = max_key_age_days
        self.now = now or datetime.now(timezone.utc)
        self.sleep = sleep
        self._cache: Dict[Any, Any] = {}

    def run(self, *args: str, region: Optional[str] = None, ignore: Sequence[str] = ()) -> Any:
        """Cached CLI call. Error codes listed in `ignore` return None instead of raising."""
        key = (region, args)
        if key in self._cache:
            return self._cache[key]
        try:
            result = self.runner.run(*args, region=region)
        except AwsError as exc:
            if exc.code in ignore:
                return None
            raise
        self._cache[key] = result
        return result

    def account_id(self) -> str:
        return self.run("sts", "get-caller-identity")["Account"]

    def regions(self) -> List[str]:
        if self._regions is None:
            try:
                data = self.run("ec2", "describe-regions")
                self._regions = sorted(r["RegionName"] for r in data["Regions"])
            except AwsError:
                self._regions = [getattr(self.runner, "default_region", None) or "us-east-1"]
        return self._regions

    def each_region(self, out: Outcome, fn: Callable[[str], None]) -> None:
        """Run fn(region) per region; a failing region is recorded, not fatal."""
        for region in self.regions():
            try:
                fn(region)
            except AwsError as exc:
                out.error(f"{region}: {exc}")

    def credential_report(self) -> List[Dict[str, str]]:
        if "credreport" in self._cache:
            return self._cache["credreport"]
        data = None
        for attempt in range(6):
            try:
                data = self.run("iam", "get-credential-report")
                break
            except AwsError as exc:
                if exc.code not in ("ReportNotPresent", "ReportInProgress", "ReportExpired"):
                    raise
                self.run("iam", "generate-credential-report")
                self.sleep(2)
        if not data:
            raise AwsError("ReportInProgress", "iam get-credential-report",
                           "credential report was not ready in time")
        text = base64.b64decode(data["Content"]).decode("utf-8")
        rows = list(csv.DictReader(io.StringIO(text)))
        self._cache["credreport"] = rows
        return rows
