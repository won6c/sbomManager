from __future__ import annotations

from typing import Iterable, List

from core.models import (
    BinaryAsset,
    DaemonAsset,
    FullSystemScanResult,
    PackageAsset,
    RemediationRecommendation,
)


class RemediationEngine:
    """Transforms risk/reachability signals into concrete remediation guidance."""

    def recommend(self, scan: FullSystemScanResult) -> List[RemediationRecommendation]:
        recommendations: List[RemediationRecommendation] = []
        recommendations.extend(self._daemon_recommendations(scan.daemons))
        recommendations.extend(self._binary_recommendations(scan.binaries))
        recommendations.extend(self._package_recommendations(scan.packages))
        return sorted(recommendations, key=lambda item: self._priority_rank(item.priority), reverse=True)

    def _daemon_recommendations(self, daemons: Iterable[DaemonAsset]) -> List[RemediationRecommendation]:
        output: List[RemediationRecommendation] = []
        for daemon in daemons:
            risk_level = (daemon.risk.level if daemon.risk else "Low").upper()
            vuln_count = len(daemon.vulnerabilities)
            evidence = [
                f"exposure={daemon.exposure}",
                f"port={daemon.port}/{daemon.protocol}",
                f"binary={daemon.binary_path}",
                f"vulnerabilities={vuln_count}",
            ]
            if daemon.exposure == "External" and (risk_level in {"CRITICAL", "HIGH"} or vuln_count > 0):
                output.append(RemediationRecommendation(
                    recommendation_id=f"remed-daemon-{daemon.port or 'unknown'}",
                    target_type="daemon",
                    target=daemon.description or daemon.binary_path,
                    priority="P0" if risk_level == "CRITICAL" else "P1",
                    action="Patch or isolate the externally reachable service; restrict bind address/firewall before patching if immediate upgrade is not possible.",
                    rationale="Externally exposed daemons with CVEs or high TARA feasibility create reachable attack paths.",
                    evidence=evidence,
                ))
        return output

    def _binary_recommendations(self, binaries: Iterable[BinaryAsset]) -> List[RemediationRecommendation]:
        output: List[RemediationRecommendation] = []
        for binary in binaries:
            gaps = [name for name, enabled in binary.mitigations.items() if enabled in {False, "False", "No", "Disabled"}]
            if binary.is_setuid or binary.is_setgid or gaps:
                priority = "P1" if binary.is_setuid or binary.is_setgid else "P2"
                output.append(RemediationRecommendation(
                    recommendation_id=f"remed-binary-{abs(hash(binary.path))}",
                    target_type="binary",
                    target=binary.path,
                    priority=priority,
                    action="Review privilege bits and rebuild or replace binaries missing exploit mitigations such as PIE/NX/RELRO.",
                    rationale="Privileged or weakly mitigated binaries increase local exploit feasibility.",
                    evidence=[
                        f"setuid={binary.is_setuid}",
                        f"setgid={binary.is_setgid}",
                        f"mitigation_gaps={','.join(gaps) if gaps else 'none'}",
                    ],
                ))
        return output

    def _package_recommendations(self, packages: Iterable[PackageAsset]) -> List[RemediationRecommendation]:
        output: List[RemediationRecommendation] = []
        for package in packages:
            if not package.vulnerabilities:
                continue
            max_cvss = max((v.cvss_score or 0.0 for v in package.vulnerabilities), default=0.0)
            output.append(RemediationRecommendation(
                recommendation_id=f"remed-package-{package.package_manager}-{package.name}",
                target_type="package",
                target=f"{package.name}@{package.version or 'unknown'}",
                priority="P0" if max_cvss >= 9.0 else "P1" if max_cvss >= 7.0 else "P2",
                action="Upgrade to a fixed version, remove unused package, or mark as delayed/false-positive with evidence in the status workflow.",
                rationale="Package vulnerabilities should be prioritized by CVSS, runtime reachability, and exposure context.",
                evidence=[
                    f"ecosystem={package.ecosystem}",
                    f"package_manager={package.package_manager}",
                    f"purl={package.purl}",
                    f"vulnerabilities={len(package.vulnerabilities)}",
                    f"max_cvss={max_cvss}",
                ],
            ))
        return output

    def _priority_rank(self, priority: str) -> int:
        return {"P0": 3, "P1": 2, "P2": 1}.get(priority, 0)
