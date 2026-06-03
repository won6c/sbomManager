import pytest
import os
import shutil
from core.plugin_manager import PluginManager, PluginType
from core.base import BasePlugin
from core.exceptions import PluginLoadError, PluginValidationError

# Create a temporary plugin for testing
def create_mock_plugin_file(plugin_dir, name):
    plugin_path = os.path.join(plugin_dir, f"{name}.py")
    with open(plugin_path, "w") as f:
        f.write(f'''
from core.base import BasePlugin
from typing import Any, Dict

class {name.capitalize()}Plugin(BasePlugin):
    @property
    def name(self) -> str: return "{name}"
    @property
    def version(self) -> str: return "1.0.0"
    @property
    def plugin_type(self) -> str: return "SBOM_PARSER"
    def validate_config(self, config: Dict) -> bool:
        return config.get("enabled", False)
    def execute(self, data: Any) -> Any:
        return f"executed {name}"
    def on_load(self) -> None:
        pass
    def on_unload(self) -> None:
        pass
''')
    return plugin_path

@pytest.fixture
def plugin_env(tmp_path):
    plugins_dir = tmp_path / "plugins"
    plugins_dir.mkdir()
    return str(plugins_dir)

def test_plugin_discovery(plugin_env):
    create_mock_plugin_file(plugin_env, "test_plugin")
    pm = PluginManager()
    discovered = pm.discover_plugins(plugin_env)
    assert "test_plugin" in discovered

def test_plugin_loading_and_registration(plugin_env):
    create_mock_plugin_file(plugin_env, "load_plugin")
    pm = PluginManager()
    # Since it's a temp dir, we need to add it to sys.path for importlib
    import sys
    sys.path.append(plugin_env)

    plugin = pm.load_plugin("load_plugin", config={"enabled": True})
    assert plugin.name == "load_plugin"
    assert plugin in pm.get_plugins(PluginType.SBOM_PARSER)

def test_plugin_invalid_config(plugin_env):
    create_mock_plugin_file(plugin_env, "config_plugin")
    pm = PluginManager()
    import sys
    sys.path.append(plugin_env)

    with pytest.raises(PluginValidationError):
        pm.load_plugin("config_plugin", config={"enabled": False})

def test_plugin_load_error(plugin_env):
    # Create a file that is not a valid BasePlugin
    plugin_path = os.path.join(plugin_env, "bad_plugin.py")
    with open(plugin_path, "w") as f:
        f.write("class BadPlugin: pass")

    pm = PluginManager()
    import sys
    sys.path.append(plugin_env)

    with pytest.raises(PluginLoadError):
        pm.load_plugin("bad_plugin")

def test_unload_all(plugin_env):
    create_mock_plugin_file(plugin_env, "unload_plugin")
    pm = PluginManager()
    import sys
    sys.path.append(plugin_env)
    pm.load_plugin("unload_plugin")

    pm.unload_all()
    assert len(pm.get_plugins(PluginType.SBOM_PARSER)) == 0
