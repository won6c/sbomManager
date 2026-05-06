import sys
import os

# Ensure current directory is in path for imports
sys.path.append(os.getcwd())

from core.models import Component, Vulnerability
from plugins.cyclonedx_parser import CycloneDXParserPlugin
from plugins.nvd_cve_provider import NvdCveProviderPlugin

def run_test(name, func):
    print(f"Running {name}...", end=" ")
    try:
        func()
        print("PASSED ✅")
    except Exception as e:
        print(f"FAILED ❌\nError: {e}")

# --- SBOM Parser Tests (Based on test_design.md) ---

def test_parser_happy_path():
    """Test Case 1.1: Happy Path (Standard SBOM)"""
    mock_json = """
    {
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
    plugin = CycloneDXParserPlugin()
    components = plugin.execute(mock_json)
    assert len(components) == 2
    assert components[0].name == "openssl"
    assert components[0].version == "1.1.1"
    assert components[0].purl == "pkg:generic/openssl@1.1.1"
    assert components[0].cpe == "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    assert components[1].name == "zlib"

def test_parser_missing_fields():
    """Test Case 1.2: Missing Optional Fields"""
    mock_json = """
    {
      "components": [
        {
          "name": "minimal-pkg",
          "version": "1.0"
        }
      ]
    }
    """
    plugin = CycloneDXParserPlugin()
    components = plugin.execute(mock_json)
    assert len(components) == 1
    assert components[0].name == "minimal-pkg"
    assert components[0].purl is None
    assert components[0].cpe is None

def test_parser_invalid_json():
    """Test Case 1.3: Invalid JSON Input"""
    invalid_json = '{"components": [{"name": "fail"}' # Missing closing brace
    plugin = CycloneDXParserPlugin()
    components = plugin.execute(invalid_json)
    assert isinstance(components, list)
    assert len(components) == 0

# --- CVE Provider Tests (Based on test_design.md) ---

def test_provider_happy_path():
    """Test Case 2.1: Happy Path (Known Vulnerable Component)"""
    plugin = NvdCveProviderPlugin()
    component = Component(
        name="openssl",
        version="1.1.1",
        cpe="cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    )
    vulns = plugin.execute(component)
    assert len(vulns) > 0
    assert isinstance(vulns[0], Vulnerability)
    assert vulns[0].cve_id == "CVE-2023-0286"

def test_provider_clean_component():
    """Test Case 2.2: Clean Component (No Vulnerabilities)"""
    plugin = NvdCveProviderPlugin()
    component = Component(
        name="safe-pkg",
        version="1.0",
        cpe="cpe:2.3:a:safe:pkg:1.0:*:*:*:*:*:*:*"
    )
    vulns = plugin.execute(component)
    assert len(vulns) == 0

def test_provider_invalid_cpe():
    """Test Case 2.3: Invalid/Malformed CPE"""
    plugin = NvdCveProviderPlugin()
    component = Component(name="bad-cpe", cpe="NOT_A_CPE")
    vulns = plugin.execute(component)
    assert len(vulns) == 0

if __name__ == "__main__":
    print("--- Starting Plugin Design Verification ---")
    run_test("Parser: Happy Path", test_parser_happy_path)
    run_test("Parser: Missing Fields", test_parser_missing_fields)
    run_test("Parser: Invalid JSON", test_parser_invalid_json)
    run_test("Provider: Happy Path", test_provider_happy_path)
    run_test("Provider: Clean Component", test_provider_clean_component)
    run_test("Provider: Invalid CPE", test_provider_invalid_cpe)
    print("--- Verification Complete ---")
