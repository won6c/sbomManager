import subprocess
import logging
import json
from pathlib import Path
from typing import Optional, Dict, List
from core.models import Component

logger = logging.getLogger(__name__)

class PackageResolver:
    """
    Resolves system binaries to OS packages using dpkg.
    """
    def __init__(self):
        self._has_dpkg = self._check_dpkg()

    def _check_dpkg(self) -> bool:
        try:
            # Check if dpkg is available and functional
            subprocess.run(['dpkg', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def resolve_binary(self, binary_path: str) -> Optional[Dict[str, str]]:
        """
        Given a binary path, returns package name and version if found.
        """
        if not self._has_dpkg or not binary_path or binary_path.startswith('PRIVILEGE'):
            return None

        try:
            # 1. Find package name for the file
            # Output format: "package-name: /path/to/file"
            result = subprocess.run(
                ['dpkg', '-S', binary_path],
                capture_output=True, text=True, check=True
            )
            package_name = result.stdout.split(':')[0].strip()

            # 2. Query package details
            # Output format: "package-name\tversion\tmaintainer"
            query_result = subprocess.run(
                ['dpkg-query', '-W', '-f=${Package}\t${Version}\t${Maintainer}\n', package_name],
                capture_output=True, text=True, check=True
            )
            
            parts = query_result.stdout.strip().split('\t')
            if len(parts) >= 2:
                return {
                    "package": parts[0],
                    "version": parts[1],
                    "vendor": parts[2] if len(parts) > 2 else "Unknown",
                    "source": "dpkg"
                }
        except subprocess.CalledProcessError:
            # File not owned by any package
            return None
        except Exception as e:
            logger.debug(f"dpkg resolution failed for {binary_path}: {e}")
            return None
        
        return None

class CycloneDXParser:
    """
    Parser for CycloneDX JSON SBOMs.
    """
    def parse(self, file_path: Path) -> List[Component]:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            components = data.get("components", [])
            result = []
            for comp in components:
                result.append(Component(
                    name=comp.get("name"),
                    version=comp.get("version"),
                    purl=comp.get("purl"),
                    cpe=comp.get("cpe")
                ))
            return result
        except Exception as e:
            logger.error(f"Failed to parse CycloneDX SBOM {file_path}: {e}")
            return []
