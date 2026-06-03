import json
from core.models import Component

class CycloneDXParserPlugin:
    """
    Plugin for parsing CycloneDX JSON SBOMs.
    """
    def execute(self, sbom_data: str):
        try:
            data = json.loads(sbom_data)
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
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON: {e}")
            return []
