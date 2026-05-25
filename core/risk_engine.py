import logging
from typing import List, Dict, Any, Optional
from core.models import (
    FullSystemScanResult,
    BinaryAsset,
    DaemonAsset,
    SbomRiskResult,
    PrivilegeLevel,
    Vulnerability
)

logger = logging.getLogger(__name__)

class RiskScoringEngine:
    '''
    Implements TARA-inspired risk scoring: Risk = Impact x Feasibility.
    Tailored for real-world exploitability in PC/Server environments.
    '''

    def __init__(self):
        # Impact Matrix: Privilege Level x CVSS Severity
        self.IMPACT_MATRIX = {
            PrivilegeLevel.ROOT: {
                "CRITICAL": 10,
                "HIGH": 8,
                "MEDIUM": 5,
                "LOW": 2,
                "UNKNOWN": 3
            },
            PrivilegeLevel.USER: {
                "CRITICAL": 7,
                "HIGH": 5,
                "MEDIUM": 3,
                "LOW": 1,
                "UNKNOWN": 2
            }
        }

    def _calculate_impact(self, asset_privilege: PrivilegeLevel, vulnerabilities: List[Vulnerability]) -> int:
        if not vulnerabilities:
            return 0
        
        # Use the highest severity among associated vulnerabilities
        max_score = -1.0
        max_severity = "UNKNOWN"
        
        for v in vulnerabilities:
            if v.cvss_score is not None and v.cvss_score > max_score:
                max_score = v.cvss_score
                max_severity = v.severity if v.severity else "UNKNOWN"
        
        # Map CVSS score to severity if severity is missing/unknown
        if max_severity == "UNKNOWN" and max_score != -1.0:
            if max_score >= 9.0: max_severity = "CRITICAL"
            elif max_score >= 7.0: max_severity = "HIGH"
            elif max_score >= 4.0: max_severity = "MEDIUM"
            else: max_severity = "LOW"
            
        return self.IMPACT_MATRIX.get(asset_privilege, self.IMPACT_MATRIX[PrivilegeLevel.USER]).get(max_severity, 3)

    def _calculate_feasibility(self, asset: Any) -> int:
        '''
        Feasibility is determined by exposure and mitigations using weighted factors.
        Base score is 5 (Moderate).
        '''
        feasibility = 5
        
        # 1. Exposure Weight (Daemon only)
        if isinstance(asset, DaemonAsset):
            if asset.exposure == "External":
                feasibility += 3
            elif asset.exposure == "Internal":
                feasibility += 1
        
        # 2. Mitigation Weights (Binary only)
        if isinstance(asset, BinaryAsset):
            mitigations = asset.mitigations or {}
            
            # Define weights for each mitigation: (Active_Penalty, Inactive_Bonus)
            # Format: { "MitigationName": (subtract_if_true, add_if_false) }
            weights = {
                "NX": (2, 3),    # NX is critical; absence is a huge win for attackers
                "PIE": (1, 2),    # PIE makes ROP/Shellcode harder
                "RELRO": (1, 1), # Full RELRO prevents GOT overwrite
            }

            for mit, (penalty, bonus) in weights.items():
                is_active = mitigations.get(mit)
                if is_active is True:
                    feasibility -= penalty
                elif is_active is False:
                    feasibility += bonus
            
            # Setuid/Setgid is a strong indicator of target interest
            if asset.is_setuid or asset.is_setgid:
                feasibility += 2
        
        # Clamp result between 1 and 10
        return max(1, min(10, feasibility))

    def _get_risk_level(self, score: float) -> str:
        if score >= 70: return "CRITICAL"
        if score >= 40: return "HIGH"
        if score >= 20: return "MEDIUM"
        return "LOW"

    def analyze_asset(self, asset: Any) -> SbomRiskResult:
        vulnerabilities = getattr(asset, 'vulnerabilities', [])
        if not vulnerabilities:
            return SbomRiskResult(score=0.0, level="None", impact=0, feasibility=0, reason="No vulnerabilities found.")

        impact = self._calculate_impact(asset.privilege_level, vulnerabilities)
        feasibility = self._calculate_feasibility(asset)
        
        # Final Risk Score: Impact * Feasibility (Max 100)
        score = float(impact * feasibility)
        level = self._get_risk_level(score)
        
        reason = f"Impact {impact} based on {asset.privilege_level} and highest CVE severity; " \
                 f"Feasibility {feasibility} based on system exposure/mitigations."
        
        return SbomRiskResult(
            score=score,
            level=level,
            impact=impact,
            feasibility=feasibility,
            reason=reason
        )

    def analyze_system(self, scan_result: FullSystemScanResult) -> FullSystemScanResult:
        '''
        Iterates through all assets and calculates their individual and collective risk.
        '''
        total_risk_sum = 0.0
        asset_count = 0

        # Analyze Daemons
        for daemon in scan_result.daemons:
            daemon.risk = self.analyze_asset(daemon)
            total_risk_sum += daemon.risk.score
            asset_count += 1

        # Analyze Binaries
        for binary in scan_result.binaries:
            binary.risk = self.analyze_asset(binary)
            total_risk_sum += binary.risk.score
            asset_count += 1

        # Overall System Risk
        avg_score = total_risk_sum / asset_count if asset_count > 0 else 0.0
        
        scan_result.overall_risk_score = avg_score
        scan_result.overall_risk_level = self._get_risk_level(avg_score)
        
        logger.info(f"Risk analysis complete. Overall System Score: {avg_score:.2f} ({scan_result.overall_risk_level})")
        
        return scan_result
