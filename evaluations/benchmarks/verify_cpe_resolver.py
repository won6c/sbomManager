from core.models import Component
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
import os
import shutil

def test_cpe_resolver():
    # 1. Setup
    cache_dir = "memory/data/test_cpe_cache"
    # Clean previous cache
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir)
    
    # We inject a custom cache_dir to avoid polluting real data
    resolver = CPEResolverPlugin()
    resolver.cache.cache_dir = cache_dir
    os.makedirs(cache_dir, exist_ok=True)

    test_cases = [
        {"name": "ssh", "version": "8.9p1", "expected_vendor": "openbsd", "expected_prod": "openssh"},
        {"name": "mysql", "version": "8.0.30", "expected_vendor": "mysql", "expected_prod": "mysql"},
        {"name": "unknown_service", "version": "1.0", "expected_vendor": "unknown_service", "expected_prod": "unknown_service"},
    ]

    print(f"--- Starting CPE Resolver Integration Test ---")
    
    for case in test_cases:
        comp = Component(name=case["name"], version=case["version"])
        
        # First run (Resolver)
        print(f"Testing {case['name']}@{case['version']}...")
        result = resolver.execute(comp)
        
        if result.cpe:
            print(f"  [+] Resolved CPE: {result.cpe}")
            assert "cpe:2.3:a" in result.cpe
            if case["expected_vendor"] != "unknown_service":
                assert case["expected_vendor"] in result.cpe
        else:
            print(f"  [-] Failed to resolve CPE for {case['name']}")

        # Second run (Cache check)
        print(f"  Testing Cache for {case['name']}...")
        comp_cache = Component(name=case["name"], version=case["version"])
        # Simple way to check cache: manually verify file exists
        key = f"{case['name']}@{case['version']}".replace(" ", "_").replace("/", "_")
        cache_file = os.path.join(cache_dir, f"{key}.json")
        assert os.path.exists(cache_file), f"Cache file {cache_file} should exist"
        
        result_cache = resolver.execute(comp_cache)
        assert result_cache.cpe == result.cpe, "Cached CPE should match original"
        print(f"  [+] Cache Verified.")

    print(f"--- All Tests Passed Successfully ---")

if __name__ == "__main__":
    try:
        test_cpe_resolver()
    except Exception as e:
        print(f"TEST FAILED: {e}")
        exit(1)
