from core.models import Component
from plugins.intelligence.cpe_resolver import CPEResolverPlugin
import os

def test_pipeline_integration():
    print("--- [Integration Test] Daemon -> CPE Resolver Pipeline ---")
    
    # 1. Mock Data: Daemon Probe가 발견한 결과라고 가정
    mock_daemons = [
        {"name": "ssh", "version": "8.9p1"},
        {"name": "mysql", "version": "8.0.30"},
        {"name": "some-unknown-app", "version": "1.2.3"},
    ]
    
    # 2. Resolver 초기화
    resolver = CPEResolverPlugin()
    
    results = []
    for daemon in mock_daemons:
        # 모델 변환 (BinaryAsset/DaemonAsset -> Component)
        comp = Component(name=daemon["name"], version=daemon["version"])
        
        # CPE 변환 수행
        resolved_comp = resolver.execute(comp)
        results.append(resolved_comp)
        print(f"Input: {daemon['name']}@{daemon['version']} -> Result CPE: {resolved_comp.cpe}")

    # 3. 검증
    assert len(results) == 3
    assert results[0].cpe is not None  # ssh should resolve
    assert "openbsd" in results[0].cpe
    assert results[2].cpe is not None  # unknown should fallback to synthetic CPE
    
    print("\n--- [SUCCESS] Integration pipeline verified ---")

if __name__ == "__main__":
    try:
        test_pipeline_integration()
    except Exception as e:
        print(f"\n[!] Integration Test Failed: {e}")
        exit(1)
