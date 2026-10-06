from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache

import yaml

from ... import ROOT

MARKERS_FILE = ROOT / "rules" / "auth_markers.yaml"


@dataclass
class Markers:
    auth: re.Pattern
    role: re.Pattern
    rate_limit: re.Pattern
    public: re.Pattern
    sensitive: re.Pattern
    privileged: re.Pattern
    login: re.Pattern
    owner_check: re.Pattern
    role_check: re.Pattern
    sensitive_fields: re.Pattern


def _rx(value: str) -> re.Pattern:
    return re.compile(re.sub(r"\s+", "", value), re.I)


@lru_cache(maxsize=1)
def load_markers(extra_json: str = "") -> Markers:
    data = yaml.safe_load(MARKERS_FILE.read_text(encoding="utf-8"))
    return Markers(
        auth=_rx(data["auth_markers"]), role=_rx(data["role_markers"]),
        rate_limit=_rx(data["rate_limit_markers"]), public=_rx(data["public_paths"]),
        sensitive=_rx(data["sensitive_paths"]), privileged=_rx(data["privileged_paths"]),
        login=_rx(data["login_paths"]), owner_check=_rx(data["owner_check_markers"]),
        role_check=_rx(data["role_check_markers"]), sensitive_fields=_rx(data["sensitive_fields"]),
    )


@dataclass
class HandlerFacts:
    """What a route handler's body does (filled by framework parsers)."""
    uses_path_id: bool = False          # reads an id from the path (req.params.id, <int:id>, @PathVariable)
    id_lookup: bool = False             # looks an object up by that id (findById, get(id), repo.findById)
    owner_check: bool = False           # references the current user / ownership
    role_check: bool = False            # checks a role inside the handler body
    returns_models: list[str] = field(default_factory=list)   # model names returned unfiltered
    filters_fields: bool = False        # .select('-password'), DTO, serializer fields, etc.
    body_text: str = ""
