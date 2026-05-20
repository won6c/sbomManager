from plugins.packages.service import PackageAnalysisService
from pathlib import Path

def test_package_pipeline():
    print("🚀 Starting Package Analysis Integration Test...\n")

    service = PackageAnalysisService(parser_type="cyclonedx")
    sbom_path = "test_sbom.json"

    try:
        # 테스트 실행
        packages = service.get_packages_from_sbom(sbom_path)

        print(f"\n✅ Total packages extracted: {len(packages)}")

        for pkg in packages:
            print(f"- Package: {pkg.purl.name} | Version: {pkg.purl.version} | PURL: {str(pkg.purl)}")

        # 검증: 4개 중 name이 누락된 1개는 제외되고 3개만 남아야 함
        assert len(packages) == 3, f"Expected 3 packages, but got {len(packages)}"

        # 검증: PURL 자동 생성 확인 (django)
        django_pkg = next((p for p in packages if p.purl.name == "django"), None)
        assert django_pkg is not None, "Django package should be present"
        assert str(django_pkg.purl) == "pkg:generic/django@4.2.1", f"Wrong PURL: {str(django_pkg.purl)}"

        print("\n✨ All integration tests passed successfully!")

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        exit(1)

if __name__ == "__main__":
    test_package_pipeline()
