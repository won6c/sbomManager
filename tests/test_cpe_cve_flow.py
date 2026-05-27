import pytest
from core.models import Component, Vulnerability, MappingResult
from core.pipeline import Pipeline, PipelineStage
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
from plugins.intelligence.metasploit_provider import MetasploitProviderPlugin

def test_end_to_end_cpe_cve_flow():
    # 1. Setup components (without CPEs)
    components = [
        Component(name="openssl", version="1.1.1"),
        Component(name="zlib", version="1.2.11"),
        Component(name="unknown", version="1.0.0")
    ]

    # 2. Initialize plugins
    cpe_resolver = CPEResolverPlugin()
    cve_provider = NvdCveProviderPlugin()
    msf_provider = MetasploitProviderPlugin()

    # 3. Setup Pipeline
    pipeline = Pipeline()

    # Define a handler for ENRICH that uses the CPEResolver
    def enrich_handler(data):
        return [cpe_resolver.execute(comp) for comp in data]

    # Define a handler for MAP that uses NVD and Metasploit
    def map_handler(data):
        results = []
        for comp in data:
            # Get vulnerabilities
            vulns = cve_provider.execute(comp)
            # Enrich vulnerabilities with Metasploit exploits
            msf_provider.execute(vulns)
            results.append(MappingResult(component=comp, vulnerabilities=vulns))
        return results

    pipeline.add_stage(PipelineStage.ENRICH, enrich_handler)
    pipeline.add_stage(PipelineStage.MAP, map_handler)

    # 4. Run pipeline
    final_results = pipeline.run(components)

    # 5. Assertions
    # Check OpenSSL: Should have CPE and then CVE and exploits
    openssl_res = next(r for r in final_results if r.component.name == "openssl")
    assert openssl_res.component.cpe == "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*"
    assert len(openssl_res.vulnerabilities) > 0
    # Any valid CVE ID is fine since we are using live data
    assert openssl_res.vulnerabilities[0].cve_id.startswith("CVE-")
    
    # Verify Metasploit integration
    has_exploits = any(len(v.exploits) > 0 for v in openssl_res.vulnerabilities)
    assert has_exploits is True

    # Check Zlib: Should have CPE and now has CVEs in live data
    zlib_res = next(r for r in final_results if r.component.name == "zlib")
    assert zlib_res.component.cpe == "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"
    assert len(zlib_res.vulnerabilities) > 0

    # Check Unknown: Should not have CPE and no CVE
    unknown_res = next(r for r in final_results if r.component.name == "unknown")
    assert unknown_res.component.cpe is None
    assert len(unknown_res.vulnerabilities) == 0

if __name__ == "__main__":
    pytest.main([__file__])
