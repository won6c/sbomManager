from dataclasses import dataclass
from typing import Optional, List

@dataclass
class Component:
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None

@dataclass
class Vulnerability:
    cve_id: str
    severity: str
    description: str

@dataclass
class MappingResult:
    component: Component
    vulnerabilities: List[Vulnerability]
