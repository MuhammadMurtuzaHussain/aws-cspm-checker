"""Check registry and executor."""

from __future__ import annotations

from typing import Callable, List, Tuple

from ..model import CheckMeta, CheckResult, Outcome
from ..runner import AwsError

CheckFn = Callable[..., None]
REGISTRY: List[Tuple[CheckMeta, CheckFn]] = []


def check(meta: CheckMeta) -> Callable[[CheckFn], CheckFn]:
    def deco(fn: CheckFn) -> CheckFn:
        REGISTRY.append((meta, fn))
        return fn
    return deco


def execute(meta: CheckMeta, fn: CheckFn, ctx) -> CheckResult:
    out = Outcome(_check_id=meta.id)
    try:
        fn(ctx, out)
    except AwsError as exc:
        out.error(str(exc) + (" (access denied: check the IAM policy in policies/)"
                              if exc.access_denied else ""))
    return CheckResult(meta, out.findings, out.evaluated, out.errors)
