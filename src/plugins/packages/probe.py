import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import quote

from core.models import PackageAsset

logger = logging.getLogger(__name__)


class PackageProbe:
    """
    High-precision package inventory collector.

    The probe prefers package-manager metadata over string scraping so that
    package identity, version, package manager, and path evidence are stable
    enough for CVE/OSV enrichment and TARA risk scoring.
    """

    def execute(self, scan_paths: Optional[List[str]] = None, limit: Optional[int] = None) -> List[PackageAsset]:
        packages: List[PackageAsset] = []
        packages.extend(self.collect_dpkg(limit=limit))
        packages.extend(self.collect_python(scan_paths or [], limit=limit))
        return self._dedupe(packages)

    def collect_dpkg(self, limit: Optional[int] = None) -> List[PackageAsset]:
        if not self._command_exists("dpkg-query"):
            return []
        try:
            proc = subprocess.run(
                ["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Maintainer}\t${Architecture}\n"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            logger.debug("dpkg package collection failed: %s", exc)
            return []

        assets: List[PackageAsset] = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            name = parts[0].strip() if len(parts) > 0 else ""
            version = parts[1].strip() if len(parts) > 1 else None
            vendor = parts[2].strip() if len(parts) > 2 else None
            arch = parts[3].strip() if len(parts) > 3 else None
            if not name:
                continue
            assets.append(PackageAsset(
                name=name,
                version=version,
                ecosystem="deb",
                package_manager="dpkg",
                source="dpkg-query",
                purl=self._purl("deb", name, version),
                vendor=vendor,
                other_metadata={"architecture": arch} if arch else {},
            ))
            if limit and len(assets) >= limit:
                break
        return assets

    def collect_python(self, scan_paths: List[str], limit: Optional[int] = None) -> List[PackageAsset]:
        assets: List[PackageAsset] = []
        for root in scan_paths:
            path = Path(root)
            if not path.exists():
                continue
            metadata_files = list(path.rglob("*.dist-info/METADATA"))[: limit or None]
            for metadata in metadata_files:
                parsed = self._parse_python_metadata(metadata)
                if parsed:
                    assets.append(parsed)
                    if limit and len(assets) >= limit:
                        return assets
        return assets

    def _parse_python_metadata(self, metadata_path: Path) -> Optional[PackageAsset]:
        values: Dict[str, str] = {}
        try:
            for line in metadata_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                if key in {"Name", "Version", "License", "Author", "Home-page"}:
                    values[key] = value.strip()
        except OSError as exc:
            logger.debug("Failed to read Python metadata %s: %s", metadata_path, exc)
            return None

        name = values.get("Name")
        version = values.get("Version")
        if not name:
            return None
        return PackageAsset(
            name=name,
            version=version,
            ecosystem="pypi",
            package_manager="python-dist-info",
            source="dist-info/METADATA",
            path=str(metadata_path),
            purl=self._purl("pypi", name, version),
            vendor=values.get("Author"),
            license=values.get("License"),
            other_metadata={"home_page": values.get("Home-page")} if values.get("Home-page") else {},
        )

    def _purl(self, ecosystem: str, name: str, version: Optional[str]) -> str:
        safe_name = quote(name)
        if version:
            return f"pkg:{ecosystem}/{safe_name}@{quote(version)}"
        return f"pkg:{ecosystem}/{safe_name}"

    def _dedupe(self, packages: List[PackageAsset]) -> List[PackageAsset]:
        seen = set()
        unique: List[PackageAsset] = []
        for package in packages:
            key = (package.package_manager, package.name.lower(), package.version or "")
            if key in seen:
                continue
            seen.add(key)
            unique.append(package)
        return unique

    def _command_exists(self, command: str) -> bool:
        try:
            subprocess.run(["which", command], capture_output=True, check=True, timeout=5)
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False
