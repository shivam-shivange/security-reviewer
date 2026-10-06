"""Self-Verifying AI Security Reviewer: Detect -> Ground -> Patch -> Verify."""

from pathlib import Path

__version__ = "0.1.0"

# Repository root: holds rules/, harness/, docker/, config/ and tools/.
ROOT = Path(__file__).resolve().parent.parent
