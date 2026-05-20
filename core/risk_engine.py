import logging
from typing import List, Optional
from core.models import BinaryAsset, DaemonAsset, Vulnerability, PrivilegeLevel, SbomRiskResult, FullSystemScanResult

logger = logging.getLogger(__name__)

class RiskScoringEngine:
    """
    TARA-based Risk Scoring Engine for PC/Server environments.
    Risk = Impact * Feasibility
    """
    
    def __init__(self):
        self.risk_levels = {
            (12, 16): "Critical",
            (8, 11): "High",
            (4, 7): "Medium",
            (1, 3): "Low"
        }

    def _get_level(self, score: int) -> str:
        for (low, high), level in self.risk_levels.items():
            if low <= score <= high:
                return level
        return "Unknown"

    def calculate_impact(self, asset, vulnerabilities: List[Vulnerability]) -> int:
        """
        Calculates Impact (1-4) based on Privilege Level and Max CVSS Score.
        """
        # 1. Base impact from privilege
        if asset.privilege_level == PrivilegeLevel.ROOT:
            base_impact = 4
        else:
            base_impact = 2
        
        # 2. Refine based on highest CVSS score
        max_cvss = 0.0
        for v in vulnerabilities:
            if v.cvss_score and v.cvss_score > max_cvss:
                max_cvss = v.cvss_score
        
        if max_cvss >= 9.0:
            return max(base_impact, 4) # Critical
        elif max_cvss >= 7.0:
            return max(base_impact, 3) # High
        elif max_cvss >= 4.0:
            return max(base_impact, 2) # Medium
        
        return max(base_impact, 1) # Low

    def calculate_feasibility(self, asset, vulnerabilities: List[Vulnerability]) -> int:
        """
        Calculates Feasibility (1-4) based on Exposure, Mitigations, and Exploit availability.
        """
        # Default feasibility
        feasibility = 2 
        
        # 1. Exposure Factor
        exposure = getattr(asset, 'exposure', 'Internal')
        if exposure == "External":
            feasibility += 1
        elif exposure == "Unknown":
            feasibility += 0
            
        # 2. Exploit availability
        has_public_exploit = False
        for v in vulnerabilities:
            if v.exploits:
                has_public_exploit = True
                break
        if has_public_exploit:
            feasibility += 1
            
        # 3. Mitigations Factor (Negative)
        mitigations = getattr(asset, 'mitigations', {})
        if mitigations:
            # If Full RELRO, PIE, and NX are all present, significantly reduce feasibility
            if mitigations.get("nx") and mitigations.get("pie") and mitigations.get("relro") == "full":
                feasibility -= 2
            elif mitigations.get("nx") or mitigations.get("pie"):
                feasibility -= 1
        
        return max(1, min(4, feasibility))

    def score_asset(self, asset) -> SbomRiskResult:
        """
        Calculates final risk for a single asset.
        """
        vulnerabilities = asset.vulnerabilities or []
        
        impact = self.calculate_impact(asset, vulnerabilities)
        feasibility = self.calculate_feasibility(asset, vulnerabilities)
        score = impact * feasibility
        
        level = self._get_level(score)
        
        reason = f"Impact {impact} (Priv:{asset.privilege_level}) * Feasibility {feasibility} (Exp:{getattr(asset, 'exposure', 'N/A')})"
        
        return SbomRiskResult(
            score=float(score),
            level=level,
            impact=impact,
            feasibility=feasibility,
            reason=reason
        )

    def analyze_system(self, result: FullSystemScanResult) -> FullSystemScanResult:
        """
        Scores all assets and calculates the overall system risk.
        """
        max_score = 0.0
        
        for daemon in result.daemons:
            daemon.risk = self.score_asset(daemon)
            max_score = max(max_score, daemon.risk.score)
            
        for binary in result.binaries:
            binary.risk = self.score_asset(binary)
            max_score = max(max_score, binary.risk.score)
            
        result.overall_risk_score = max_score
        result.overall_risk_level = self._get_level(int(max_score))
        
        return result
