from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

class PrivilegeLevel(str, Enum):
    ROOT = "ROOT"
    USER = "USER"
    PRIVILEGE_RESTRICTED = "PRIVILEGE_RESTRICTED"

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
    description: str
    affected_versions: List[str] = Field(default_factory=list)
    exploits: List[Dict[str, Any]] = Field(default_factory=list)

class MappingResult(BaseModel):
    component: Component
    vulnerabilities: List[Vulnerability]

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
    vulnerabilities: List[Any] = Field(default_factory=list)

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
    vulnerabilities: List[Any] = Field(default_factory=list)

class FullSystemScanResult(BaseModel):
    kernel: KernelState
    daemons: List[DaemonAsset]
    binaries: List[BinaryAsset]
    timestamp: str
