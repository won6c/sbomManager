import sys
import os
import time

# Add project root to path manually for reliable import
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.abspath(os.path.join(project_root, '..')))

try:
    from core.models import Component
    from plugins.intelligence.nvd_cve_provider import NvdCveProviderPlugin
    import logging
    logging.basicConfig(level=logging.INFO)
    print("✅ Imports successful")
except ImportError as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

def test_nvd_cache():
    provider = NvdCveProviderPlugin()
    component = Component(name="postgresql", version="15", cpe="cpe:2.3:a:postgresql:postgresql:15:*:*:*:*:*:*:*")
    
    print("\n--- Round 1: First Request (API call) ---")
    start_time = time.time()
    res1 = provider.execute(component)
    end_time = time.time()
    print(f"Duration: {end_time - start_time:.2f}s, Results: {len(res1)}")

    print("\n--- Round 2: Second Request (Cache hit) ---")
    start_time = time.time()
    res2 = provider.execute(component)
    end_time = time.time()
    print(f"Duration: {end_time - start_time:.4f}s, Results: {len(res2)}")

    if len(res1) == len(res2) and (end_time - start_time) < 0.1:
        print("\n✅ SUCCESS: Cache is working as expected!")
    else:
        print("\n❌ FAILURE: Cache not working or results mismatch.")

if __name__ == '__main__':
    test_nvd_cache()
