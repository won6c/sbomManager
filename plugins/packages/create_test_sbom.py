import json

test_sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "name": "openssl",
            "version": "1.1.1t",
            "purl": "pkg:generic/openssl@1.1.1t",
            "dependencies": []
        },
        {
            "name": "django",
            "version": "4.2.1",
            # purl 누락 $\rightarrow$ 서비스가 자동 생성해야 함
            "dependencies": []
        },
        {
            # name 누락 $\rightarrow$ sanitize에서 스킵되어야 함
            "version": "1.0.0",
            "purl": "pkg:generic/unknown@1.0.0",
            "dependencies": []
        },
        {
            "name": "requests",
            "version": "2.28.1",
            "purl": "pkg:pypi/requests@2.28.1",
            "dependencies": []
        }
    ]
}

with open("test_sbom.json", "w") as f:
    json.dump(test_sbom, f)
