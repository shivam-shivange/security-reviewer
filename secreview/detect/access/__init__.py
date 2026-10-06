"""Endpoint inventory (API surface) + access-control and API-leakage analysis.

Framework parsers (express.py, python_web.py, spring.py) produce `Endpoint`s plus
`HandlerFacts` (what each handler body does). `rules.py` turns those into findings:
open endpoints, missing/inconsistent role checks, IDOR/BOLA, missing rate limiting on login routes,
sensitive-data exposure. All findings are heuristic => status `needs_review`.
"""

from .analyzer import analyze_access

__all__ = ["analyze_access"]
