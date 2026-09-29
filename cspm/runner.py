"""Thin wrapper around the AWS CLI, plus a fixture-backed runner for demos and tests."""

from __future__ import annotations

import json
import os
import re
import subprocess
from typing import Any, Dict, Optional

ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "UnauthorizedAccess",
}


class AwsError(Exception):
    def __init__(self, code: str, command: str, detail: str = ""):
        self.code = code
        self.command = command
        self.detail = detail
        super().__init__(f"{code} on `aws {command}`")

    @property
    def access_denied(self) -> bool:
        return self.code in ACCESS_DENIED_CODES


def _error_code(stderr: str) -> str:
    m = re.search(r"An error occurred \((\w+)\)", stderr)
    return m.group(1) if m else "Unknown"


class AwsRunner:
    """Runs `aws ... --output json` and returns parsed JSON (or None for empty output)."""

    def __init__(self, profile: Optional[str] = None, default_region: Optional[str] = None,
                 aws_bin: str = "aws", timeout: int = 60):
        self.profile = profile
        self.default_region = default_region
        self.aws_bin = aws_bin
        self.timeout = timeout

    def run(self, *args: str, region: Optional[str] = None) -> Any:
        cmd = [self.aws_bin, *args, "--output", "json", "--no-cli-pager"]
        if self.profile:
            cmd += ["--profile", self.profile]
        use_region = region or self.default_region
        if use_region:
            cmd += ["--region", use_region]
        env = dict(os.environ, AWS_PAGER="")
        label = " ".join(args)
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=self.timeout, env=env)
        except FileNotFoundError:
            raise AwsError("AwsCliNotFound", label, "the `aws` executable is not on PATH")
        except subprocess.TimeoutExpired:
            raise AwsError("Timeout", label, f"no response after {self.timeout}s")
        if proc.returncode != 0:
            raise AwsError(_error_code(proc.stderr), label, proc.stderr.strip())
        out = proc.stdout.strip()
        return json.loads(out) if out else None


class FixtureRunner:
    """Serves canned CLI responses from a JSON file. Used by --demo and the test suite.

    Keys look like ``"<region or *>|<aws args joined by spaces>"``. A value of
    ``{"__error__": "Code"}`` makes the call raise AwsError(Code).
    """

    def __init__(self, responses: Dict[str, Any]):
        self.responses = responses

    def run(self, *args: str, region: Optional[str] = None) -> Any:
        label = " ".join(args)
        key = f"{region or '*'}|{label}"
        if key not in self.responses:
            raise AwsError("FixtureMissing", label, f"no fixture for {key!r}")
        value = self.responses[key]
        if isinstance(value, dict) and "__error__" in value:
            raise AwsError(value["__error__"], label, "fixture error")
        return value
