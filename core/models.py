from dataclasses import dataclass
from typing import List, Optional

@dataclass(frozen=True)
class Component:
    name: str
    version: str
    vendor: Optional[str] = None
    path: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None

@dataclass(frozen=True)
class Vulnerability:
    cve_id: str
    severity: str
    description: str
    affected_versions: List[str]

@dataclass(frozen=True)
class MappingResult:
    component: Component
    vulnerabilities: List[Vulnerability]
