import importlib
import os
import inspect
from enum import Enum
from typing import Dict, List, Type, Optional
from core.base import BasePlugin
from core.exceptions import PluginLoadError, PluginValidationError

class PluginType(Enum):
    SBOM_PARSER = "SBOM_PARSER"
    CVE_PROVIDER = "CVE_PROVIDER"

class PluginManager:
    """
    Manages dynamic discovery, loading, and registration of plugins.
    """
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugin_types: Dict[PluginType, List[str]] = {
            ptype: [] for ptype in PluginType
        }

    def discover_plugins(self, plugins_dir: str) -> List[str]:
        """
        Scan the plugins directory for Python modules.
        """
        discovered = []
        if not os.path.exists(plugins_dir):
            return discovered

        for entry in os.scandir(plugins_dir):
            if entry.is_dir() and os.path.exists(os.path.join(entry.path, "__init__.py")):
                discovered.append(entry.name)
            elif entry.is_file() and entry.name.endswith(".py") and entry.name != "__init__.py":
                discovered.append(entry.name[:-3])

        return discovered

    def load_plugin(self, module_path: str, config: Optional[Dict] = None) -> BasePlugin:
        """
        Import a plugin module, instantiate the BasePlugin subclass, and register it.
        """
        try:
            module = importlib.import_module(module_path)

            # Find the class that inherits from BasePlugin
            plugin_class = None
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj is not BasePlugin:
                    plugin_class = obj
                    break

            if not plugin_class:
                raise PluginLoadError(f"No BasePlugin implementation found in {module_path}")

            plugin_instance = plugin_class()

            if config and not plugin_instance.validate_config(config):
                raise PluginValidationError(f"Invalid configuration for plugin {plugin_instance.name}")

            plugin_instance.on_load()
            self.register_plugin(plugin_instance)
            return plugin_instance

        except Exception as e:
            if isinstance(e, (PluginLoadError, PluginValidationError)):
                raise e
            raise PluginLoadError(f"Failed to load plugin {module_path}: {str(e)}") from e

    def register_plugin(self, plugin: BasePlugin) -> None:
        """
        Register an instantiated plugin.
        """
        self._plugins[plugin.name] = plugin

        # Map to PluginType enum
        try:
            ptype = PluginType(plugin.plugin_type)
            if plugin.name not in self._plugin_types[ptype]:
                self._plugin_types[ptype].append(plugin.name)
        except ValueError:
            # Handle cases where plugin_type string doesn't match Enum exactly
            pass

    def get_plugins(self, ptype: PluginType) -> List[BasePlugin]:
        """
        Retrieve all registered plugins of a specific type.
        """
        names = self._plugin_types.get(ptype, [])
        return [self._plugins[name] for name in names]

    def unload_all(self) -> None:
        """
        Cleanup and unload all registered plugins.
        """
        for plugin in self._plugins.values():
            plugin.on_unload()
        self._plugins.clear()
        for ptype in self._plugin_types:
            self._plugin_types[ptype] = []
