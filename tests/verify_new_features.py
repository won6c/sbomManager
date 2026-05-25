import sys
import os
from pathlib import Path

# Force project root to be the primary search path
project_root = os.path.abspath(os.getcwd())
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import asyncio
import logging

# Check imports manually to provide cleaner error messages
try:
    from plugins.packages.reachability import ProcMapsReachabilityAnalyzer
    from plugins.packages.osv import OSVCVEProvider
    from plugins.packages.parsers import CycloneDXParser
    from core.models import Component
except ImportError as e:
    print(f"❌ Import failed: {e}")
    print("\nAttempting to diagnose...")
    print(f"Current Working Directory: {os.getcwd()}")
    print(f"System Path: {sys.path}")
    print("Checking for __init__.py files...")
    for root, dirs, files in os.walk('.'):
        for file in files:
            if file == '__init__.py':
                print(f"Found: {os.path.join(root, file)}")
    sys.exit(1)

async def test_reachability():
    print("\n--- [Test 1] Reachability Analysis ---")
    analyzer = ProcMapsReachabilityAnalyzer()
    
    libc_paths = ["/lib/x86_64-linux-gnu/libc.so.6", "/lib64/libc.so.6", "/lib/libc.so.6"]
    found_any = False
    for path in libc_paths:
        is_loaded, regions = analyzer.check_memory_load(path)
        if is_loaded:
            exec_perm = analyzer.verify_executable_region(regions)
            print(f"✅ FOUND: {path} | Loaded: {is_loaded} | Executable: {exec_perm}")
            found_any = True
            break
    
    if not found_any:
        print("❌ NOT FOUND: Could not find any common libc path loaded in memory.")

    is_loaded, _ = analyzer.check_memory_load("/tmp/non_existent_lib_12345.so")
    print(f"✅ NEGATIVE TEST: /tmp/non_existent... | Loaded: {is_loaded} (Expected: False)")

async def test_osv():
    print("\n--- [Test 2] OSV Provider Analysis ---")
    provider = OSVCVEProvider()
    test_purl = "pkg:npm/lodash@4.17.20"
    try:
        vulns = await provider.fetch_vulnerabilities(test_purl)
        if vulns:
            print(f"✅ SUCCESS: Found {len(vulns)} vulnerabilities for {test_purl}")
            for v in vulns[:2]:
                print(f"  - {v['cve_id']} | Severity: {v['severity']} | Score: {v['cvss_score']}")
        else:
            print(f"❌ FAILURE: No vulnerabilities found for {test_purl}")
    except Exception as e:
        print(f"❌ ERROR: OSV query failed: {e}")

async def test_sbom_parsing():
    print("\n--- [Test 3] SBOM Parsing Analysis ---")
    parser = CycloneDXParser()
    file_path = Path("test_sbom.json")
    
    if not file_path.exists():
        print("❌ ERROR: test_sbom.json not found.")
        return

    try:
        packages = parser.parse(file_path)
        print(f"✅ SUCCESS: Parsed {len(packages)} packages from SBOM.")
        for pkg in packages:
            print(f"  - {pkg['name']} (v{pkg['version']}) | PURL: {pkg['purl']}")
        
        names = [p.get('name') for p in packages]
        if "log4j-core" in names and "lodash" in names:
            print("✅ VERIFIED: Both log4j-core and lodash were correctly parsed.")
        else:
            print("❌ FAILURE: Some expected packages are missing.")
            
    except Exception as e:
        print(f"❌ ERROR: SBOM parsing failed: {e}")

async def main():
    await test_reachability()
    await test_osv()
    await test_sbom_parsing()

if __name__ == "__main__":
    asyncio.run(main())
