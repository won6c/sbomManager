from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class PrivilegeLevel(str, Enum):
    ROOT = "ROOT"
    USER = "USER"
    PRIVILEGE_RESTRICTED = "PRIVILEGE_RESTRICTED"

class SbomRiskResult(BaseModel):
    score: float
    level: str
    impact: int
    feasibility: int
    reason: str

class Component(BaseModel):
    name: str
    version: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    vendor: Optional[str] = None
    other_metadata: Dict[str, Any] = Field(default_factory=dict)
    is_active_on_system: bool = False 
    linked_binaries: List[str] = Field(default_factory=list) 
    linked_daemons: List[int] = Field(default_factory=list)   

class Vulnerability(BaseModel):
    cve_id: str
    severity: str
    cvss_score: Optional[float] = None
    description: str
    affected_versions: List[str] = Field(default_factory=list)
    exploits: List[Dict[str, Any]] = Field(default_factory=list)
    fixed_in: Optional[str] = None

class CPERequest(BaseModel):
    name: str
    version: str

class CPEResponse(BaseModel):
    name: str
    version: str
    cpe: str
    source: str
    confidence: float

class CVERequest(BaseModel):
    cpe: str
    limit: int = 10
    offset: int = 0
    min_severity: Optional[str] = None
    sort_by: str = "severity"

class CVEResponse(BaseModel):
    cpe: str
    vulnerabilities: List[Vulnerability]
    total_count: int
    limit: int
    offset: int

class MappingResult(BaseModel):
    component: Component
    vulnerabilities: List[Vulnerability]


class PackageAsset(BaseModel):
    name: str
    version: Optional[str] = None
    ecosystem: str = "unknown"
    package_manager: str = "unknown"
    source: str = "unknown"
    path: Optional[str] = None
    purl: Optional[str] = None
    cpe: Optional[str] = None
    vendor: Optional[str] = None
    license: Optional[str] = None
    is_runtime_reachable: bool = False
    linked_paths: List[str] = Field(default_factory=list)
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    risk: Optional[SbomRiskResult] = None
    other_metadata: Dict[str, Any] = Field(default_factory=dict)

class RemediationRecommendation(BaseModel):
    recommendation_id: str
    target_type: str
    target: str
    priority: str
    action: str
    rationale: str
    evidence: List[str] = Field(default_factory=list)
    status: str = "Open"

class KernelState(BaseModel):
    version: str
    config: Dict[str, str]
    is_root: bool

class BinaryAsset(BaseModel):
    path: str
    sha256: str
    permissions: str
    is_setuid: bool
    is_setgid: bool
    mitigations: Dict[str, Any]
    privilege_level: PrivilegeLevel
    purl: Optional[str] = None
    cpe: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    risk: Optional[SbomRiskResult] = None
    is_reachable: bool = False
    memory_regions: List[Any] = Field(default_factory=list)

class DaemonAsset(BaseModel):
    port: Optional[int]
    protocol: Optional[str]
    address: str
    exposure: str
    pid: Optional[int]
    binary_path: str
    user: str
    privilege_level: PrivilegeLevel = PrivilegeLevel.USER
    description: Optional[str] = None
    cpe: Optional[str] = None
    version: Optional[str] = None
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    risk: Optional[SbomRiskResult] = None
    is_reachable: bool = False
    memory_regions: List[Any] = Field(default_factory=list)

class FullSystemScanResult(BaseModel):
    kernel: KernelState
    daemons: List[DaemonAsset]
    binaries: List[BinaryAsset]
    packages: List[PackageAsset] = Field(default_factory=list)
    remediation: List[RemediationRecommendation] = Field(default_factory=list)
    scan_id: Optional[str] = None
    overall_risk_score: float = 0.0
    overall_risk_level: str = "Low"
    timestamp: str
