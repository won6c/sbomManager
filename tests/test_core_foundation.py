import pytest
from typing import List, Optional, Any
from core.models import Component, Vulnerability, MappingResult
from core.exceptions import SBOMManagerError, PluginError
from core.base import BasePlugin

class MockPlugin(BasePlugin):
    @property
    def name(self) -> str: return "mock-plugin"
    @property
    def version(self) -> str: return "1.0.0"
    @property
    def plugin_type(self) -> str: return "SBOM_PARSER"
    def validate_config(self, config) -> bool: return True
    def execute(self, data) -> Any: return data

def test_component_creation():
    comp = Component(name="test-pkg", version="1.2.3", vendor="TestCorp")
    assert comp.name == "test-pkg"
    assert comp.version == "1.2.3"
    assert comp.vendor == "TestCorp"

def test_vulnerability_creation():
    vuln = Vulnerability(cve_id="CVE-2024-0001", severity="High", description="Test Vuln", affected_versions=["1.2.3"])
    assert vuln.cve_id == "CVE-2024-0001"
    assert "1.2.3" in vuln.affected_versions

def test_mapping_result_creation():
    comp = Component(name="test", version="1")
    vuln = Vulnerability(cve_id="CVE-1", severity="Low", description="Desc", affected_versions=["1"])
    result = MappingResult(component=comp, vulnerabilities=[vuln])
    assert result.component == comp
    assert result.vulnerabilities[0] == vuln

def test_exception_hierarchy():
    with pytest.raises(SBOMManagerError):
        raise PluginError("Plugin failed")

def test_base_plugin_abstract():
    with pytest.raises(TypeError):
        # Cannot instantiate ABC
        BasePlugin()
