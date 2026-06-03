from __future__ import annotations

import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import FullSystemScanResult


class ScanHistoryStore:
    """Filesystem-backed scan history for local development and demos."""

    def __init__(self, root: str = "memory/data/scan_history"):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, scan: FullSystemScanResult) -> Dict[str, Any]:
        scan_id = scan.scan_id or str(uuid.uuid4())
        scan.scan_id = scan_id
        payload = scan.model_dump(mode="json")
        payload["scan_id"] = scan_id
        payload["saved_at"] = datetime.utcnow().isoformat()
        target = self.root / f"{scan_id}.json"
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return self._summary(payload)

    def list(self) -> List[Dict[str, Any]]:
        summaries = []
        for path in sorted(self.root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                summaries.append(self._summary(json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError):
                continue
        return summaries

    def get(self, scan_id: str) -> Optional[Dict[str, Any]]:
        path = self.root / f"{scan_id}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def compare(self, base_scan_id: str, target_scan_id: str) -> Optional[Dict[str, Any]]:
        base = self.get(base_scan_id)
        target = self.get(target_scan_id)
        if base is None or target is None:
            return None
        return {
            "base_scan_id": base_scan_id,
            "target_scan_id": target_scan_id,
            "overall_risk_delta": (target.get("overall_risk_score") or 0) - (base.get("overall_risk_score") or 0),
            "daemon_delta": len(target.get("daemons", [])) - len(base.get("daemons", [])),
            "binary_delta": len(target.get("binaries", [])) - len(base.get("binaries", [])),
            "package_delta": len(target.get("packages", [])) - len(base.get("packages", [])),
            "remediation_delta": len(target.get("remediation", [])) - len(base.get("remediation", [])),
            "new_packages": sorted(self._package_keys(target) - self._package_keys(base)),
            "removed_packages": sorted(self._package_keys(base) - self._package_keys(target)),
        }

    def _summary(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "scan_id": payload.get("scan_id"),
            "timestamp": payload.get("timestamp"),
            "saved_at": payload.get("saved_at"),
            "overall_risk_score": payload.get("overall_risk_score", 0.0),
            "overall_risk_level": payload.get("overall_risk_level", "Low"),
            "counts": {
                "daemons": len(payload.get("daemons", [])),
                "binaries": len(payload.get("binaries", [])),
                "packages": len(payload.get("packages", [])),
                "remediation": len(payload.get("remediation", [])),
            },
        }

    def _package_keys(self, payload: Dict[str, Any]) -> set[str]:
        return {
            f"{pkg.get('package_manager')}:{pkg.get('name')}@{pkg.get('version')}"
            for pkg in payload.get("packages", [])
        }
