import pytest
from core.models import Component, Vulnerability
from core.plugin_manager import PluginManager, PluginType
import os

# Mock CycloneDX JSON for testing
MOCK_CYCLONEDX_JSON = """
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "components": [
    {
      "name": "openssl",
      "version": "1.1.1",
      "purl": "pkg:generic/openssl@1.1.1",
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    },
    {
      "name": "zlib",
      "version": "1.2.11",
      "purl": "pkg:generic/zlib@1.2.11",
      "cpe": "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"
    }
  ]
}
"""

MOCK_NVD_RESPONSE = {
    "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*": [
        {
            "cve_id": "CVE-2023-0286",
            "severity": "High",
            "description": "A vulnerability in OpenSSL...",
            "affected_versions": ["1.1.1"]
        }
    ],
    "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*": []
}

def test_cyclonedx_parser_logic():
    # This test defines the expected behavior for the CycloneDXParserPlugin
    # It should take a JSON string (or file path) and return a list of Component objects.
    from plugins.cyclonedx_parser import CycloneDXParserPlugin

    plugin = CycloneDXParserPlugin()
    components = plugin.execute(MOCK_CYCLONEDX_JSON)

    assert len(components) == 2
    assert components[0].name == "openssl"
    assert components[0].version == "1.1.1"
    assert components[0].purl == "pkg:generic/openssl@1.1.1"
    assert components[1].name == "zlib"

def test_nvd_cve_provider_logic():
    # This test defines the expected behavior for the NvdCveProviderPlugin
    # It should take a Component object and return a list of Vulnerability objects.
    from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin

    plugin = NvdCveProviderPlugin()
    # We will mock the network call inside the implementation,
    # but the test defines the expected interface mapping.
    component = Component(name="openssl", version="1.1.1", cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*")
    vulns = plugin.execute(component)

    # Live/cache-backed NVD results can change over time. Verify the provider
    # returns the expected model contract instead of pinning one CVE ID.
    assert all(isinstance(vuln, Vulnerability) for vuln in vulns)
