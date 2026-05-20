from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Set, Any, Tuple
from enum import Enum
from pydantic import BaseModel, Field, validator
from pathlib import Path
import datetime
import asyncio

# --- [고도화] 데이터 모델 정의 ---

class Ecosystem(str, Enum):
    PYPI = "pypi"
    DEBIAN = "debian"
    RPM = "rpm"
    NPM = "npm"
    CARGO = "cargo"
    GENERIC = "generic"

class PURL(BaseModel):
    """Package URL (PURL) 표준 포맷 정의: pkg:ecosystem/name@version"""
    ecosystem: Ecosystem
    name: str
    version: str
    qualifier: Optional[str] = None

    def __str__(self) -> str:
        return f"pkg:{self.ecosystem.value}/{self.name}@{self.version}"

class Package(BaseModel):
    """분석 대상 패키지의 정교한 정의"""
    purl: PURL
    dependencies: Set[str] = Field(default_factory=set)
    path_on_disk: Optional[Path] = None
    is_privileged_data: bool = False
    last_seen: datetime.datetime = Field(default_factory=datetime.datetime.now)

    @validator('purl')
    def validate_purl(cls, v):
        if not v.name or not v.version:
            raise ValueError("PURL must contain both name and version")
        return v

class Vulnerability(BaseModel):
    """취약점 상세 및 도달 가능성 분석 데이터"""
    cve_id: str
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    # 단순 리스트 대신 버전 범위 표현식(e.g., ">=1.0.0, <1.2.0")을 지원하도록 정의
    affected_version_ranges: List[str] = Field(default_factory=list)
    vulnerable_functions: List[str] = Field(default_factory=list)
    fixed_in: Optional[str] = None
    reachability_level: str = "UNKNOWN" # UNKNOWN -> LOADED -> EXECUTABLE -> REACHABLE

class AnalysisResult(BaseModel):
    """정량적 분석 결과 리포트"""
    package: Package
    vulnerabilities: List[Vulnerability] = []
    runtime_status: str = "NOT_LOADED"
    risk_score: float = 0.0
    evidence: List[str] = Field(default_factory=list)

# --- [고도화] 추상 인터페이스 정의 ---

class SBOMParser(ABC):
    """SBOM 포맷 파싱 및 데이터 정제(Sanitization) 인터페이스"""
    @abstractmethod
    def parse(self, source: Path) -> List[Package]:
        """SBOM 파일을 읽고 유효성을 검증하여 Package 리스트로 반환"""
        pass

    @abstractmethod
    def sanitize(self, raw_data: Any) -> Dict[str, Package]:
        """누락된 필드 처리 및 데이터 정규화 수행 (내부 ID를 키로 하는 맵 반환)"""
        pass

    def _parse_purl(self, purl_str: Optional[str], name: Optional[str], version: str) -> Optional[PURL]:
        """
        PURL 문자열을 분석하여 PURL 모델로 변환하는 공통 로직.
        문자열이 없을 경우 제공된 name/version으로 추론하여 생성.
        """
        if purl_str:
            try:
                # pkg:ecosystem/name@version 형태 분석
                parts = purl_str.replace("pkg:", "").split("/")
                ecosystem_val = parts[0]
                rest = parts[1].split("@")
                name_val = rest[0]
                version_val = rest[1] if len(rest) > 1 else version

                return PURL(
                    ecosystem=Ecosystem(ecosystem_val) if ecosystem_val in Ecosystem.__members__ else Ecosystem.GENERIC,
                    name=name_val,
                    version=version_val
                )
            except Exception:
                pass # 파싱 실패 시 추론 로직으로 이동

        if name:
            return PURL(
                ecosystem=Ecosystem.GENERIC,
                name=name,
                version=version
            )

        return None

class CVEProvider(ABC):
    """비동기 취약점 DB 연동 인터페이스"""
    @abstractmethod
    async def fetch_vulnerabilities(self, purl: PURL) -> List[Vulnerability]:
        """비동기적으로 PURL 기반 취약점 및 취약 함수 목록 조회"""
        pass

class ReachabilityAnalyzer(ABC):
    """심볼 및 권한 기반의 정밀 런타임 분석 인터페이스"""
    @abstractmethod
    def check_memory_load(self, package: Package) -> Tuple[bool, List[Tuple[str, str]]]:
        """
        단순 로드 여부와 함께 (메모리주소, 권한(r-xp)) 튜플 리스트 반환
        정확한 path_on_disk 매칭 및 실행 권한(x) 검증 필요
        """
        pass

    @abstractmethod
    def verify_symbol_existence(self, vuln_functions: List[str], memory_regions: List[Tuple[str, str]]) -> List[str]:
        """실행 권한이 있는 메모리 영역 내에서 취약 함수 심볼 실제 존재 여부 검증"""
        pass

class RiskScorer(ABC):
    """정량적 위험 점수 계산 엔진 인터페이스"""
    @abstractmethod
    def calculate_score(self, vuln: Vulnerability, reachability: str, privilege: bool) -> float:
        """가중치 기반 점수 계산: Score = CVSS * Reachability_Weight * Priv_Multiplier"""
        pass

class DependencyGraphManager(ABC):
    """순환 참조 및 깊이 제한이 적용된 의존성 분석 인터페이스"""
    @abstractmethod
    def build_graph(self, packages: List[Package], max_depth: int = 10) -> Any:
        """순환 참조를 감지하고 최대 깊이가 제한된 DiGraph 구축"""
        pass

    @abstractmethod
    def get_impact_chain(self, vulnerable_package: str) -> List[str]:
        """취약한 패키지를 의존하는 상위 경로 추적"""
        pass

class AnalysisCache(ABC):
    """증분 분석 및 Rate Limit 대응을 위한 캐싱 인터페이스"""
    @abstractmethod
    async def get_cached_vulns(self, purl: PURL) -> Optional[List[Vulnerability]]:
        pass

    @abstractmethod
    async def set_cached_vulns(self, purl: PURL, vulns: List[Vulnerability]):
        pass

class VersionMatcher(ABC):
    """Semantic Versioning 기반의 범위 매칭 인터페이스"""
    @abstractmethod
    def is_vulnerable(self, current_version: str, version_ranges: List[str]) -> bool:
        """현재 버전이 취약 범위(e.g., ">=1.0, <1.5")에 포함되는지 판별"""
        pass
