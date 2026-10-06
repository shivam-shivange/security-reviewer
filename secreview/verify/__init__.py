"""Verify stage: prove a patch by running the oracle + regression tests in a sandbox."""

from .engine import run_verify

__all__ = ["run_verify"]
