import pytest
import os
from pathlib import Path
from plugins.binaries.probe import BinaryProbePlugin

def test_binary_probe_discovery():
    # Use standard linux paths
    probe = BinaryProbePlugin()
    config = {"scan_paths": ["/bin", "/usr/bin"]}
    
    results = probe.execute(config)
    assert isinstance(results, list)
    assert len(results) > 0
    
    # Check a known binary like 'ls'
    ls_result = next((r for r in results if "ls" in r["path"]), None)
    assert ls_result is not None
    assert "sha256" in ls_result
    assert "mitigations" in ls_result
    assert "privilege_level" in ls_result

def test_binary_probe_invalid_config():
    probe = BinaryProbePlugin()
    assert probe.validate_config({"wrong": "config"}) is False
    assert probe.validate_config({"scan_paths": "not a list"}) is False
    assert probe.validate_config({"scan_paths": ["/tmp"]}) is True

if __name__ == "__main__":
    pytest.main([__file__])
