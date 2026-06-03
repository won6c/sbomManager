from core.models import (
    BinaryAsset,
    DaemonAsset,
    FullSystemScanResult,
    KernelState,
    PackageAsset,
    PrivilegeLevel,
    SbomRiskResult,
    Vulnerability,
)
from core.remediation import RemediationEngine
from core.scan_history import ScanHistoryStore
from plugins.packages.probe import PackageProbe


def test_package_probe_parses_python_dist_info(tmp_path):
    dist_info = tmp_path / "demo_pkg-1.2.3.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text(
        "Name: demo-pkg\nVersion: 1.2.3\nLicense: MIT\nAuthor: Example Vendor\n",
        encoding="utf-8",
    )

    packages = PackageProbe().execute([str(tmp_path)], limit=10)

    assert any(pkg.name == "demo-pkg" and pkg.version == "1.2.3" for pkg in packages)
    matched = next(pkg for pkg in packages if pkg.name == "demo-pkg")
    assert matched.ecosystem == "pypi"
    assert matched.purl == "pkg:pypi/demo-pkg@1.2.3"


def test_remediation_engine_prioritizes_external_vulnerable_daemon():
    vuln = Vulnerability(
        cve_id="CVE-2099-0001",
        severity="CRITICAL",
        cvss_score=9.8,
        description="demo",
    )
    daemon = DaemonAsset(
        port=443,
        protocol="tcp",
        address="0.0.0.0",
        exposure="External",
        pid=100,
        binary_path="/usr/sbin/demo",
        user="root",
        privilege_level=PrivilegeLevel.ROOT,
        description="demo-daemon",
        vulnerabilities=[vuln],
        risk=SbomRiskResult(score=90, level="CRITICAL", impact=10, feasibility=9, reason="test"),
    )
    scan = FullSystemScanResult(
        kernel=KernelState(version="test", config={}, is_root=False),
        daemons=[daemon],
        binaries=[],
        packages=[],
        timestamp="2026-06-03T00:00:00",
    )

    recommendations = RemediationEngine().recommend(scan)

    assert recommendations
    assert recommendations[0].priority == "P0"
    assert recommendations[0].target_type == "daemon"
    assert "externally" in recommendations[0].rationale.lower()


def test_scan_history_store_saves_and_compares(tmp_path):
    store = ScanHistoryStore(root=str(tmp_path))
    base = FullSystemScanResult(
        kernel=KernelState(version="test", config={}, is_root=False),
        daemons=[],
        binaries=[],
        packages=[PackageAsset(name="a", version="1", package_manager="dpkg")],
        timestamp="2026-06-03T00:00:00",
        overall_risk_score=1.0,
    )
    target = FullSystemScanResult(
        kernel=KernelState(version="test", config={}, is_root=False),
        daemons=[],
        binaries=[BinaryAsset(path="/bin/demo", sha256="x", permissions="755", is_setuid=False, is_setgid=False, mitigations={}, privilege_level=PrivilegeLevel.USER)],
        packages=[PackageAsset(name="a", version="2", package_manager="dpkg")],
        timestamp="2026-06-03T00:01:00",
        overall_risk_score=3.0,
    )

    base_summary = store.save(base)
    target_summary = store.save(target)
    comparison = store.compare(base_summary["scan_id"], target_summary["scan_id"])

    assert len(store.list()) == 2
    assert comparison is not None
    assert comparison["overall_risk_delta"] == 2.0
    assert comparison["binary_delta"] == 1
    assert comparison["new_packages"] == ["dpkg:a@2"]
