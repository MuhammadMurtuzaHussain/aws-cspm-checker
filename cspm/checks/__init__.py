"""Importing this package registers all checks."""

from . import cloudtrail, ec2, iam, s3, storage  # noqa: F401
from .registry import REGISTRY, execute  # noqa: F401


def all_checks():
    return sorted(REGISTRY, key=lambda pair: pair[0].id)
