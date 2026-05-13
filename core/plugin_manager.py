import os
import inspect
import importlib
import logging
from enum import Enum, auto
from typing import List, Dict, Any, Optional, Type
from core.base import BasePlugin
from core.exceptions import PluginLoadError, PluginValidationError

logger = logging.getLogger(__name__)

class PluginType(Enum):
    SBOM_PARSER = auto()
    CVE_PROVIDER = auto()
    CPE_RESOLVER = auto()
    SYSTEM_PROBE = auto()

class PluginManager:
    """
    Manages dynamic discovery, loading, and registration of plugins.
    """
    def __init__(self):
        self._plugins: Dict[str, BasePlugin] = {}
        self._plugin_types: Dict[PluginType, List[BasePlugin]] = {ptype: [] for ptype in PluginType}

    def discover_plugins(self, plugins_dir: str) -> List[str]:
        """
        Scans a directory for potential plugin files.
        """
        discovered = []
        if not os.path.exists(plugins_dir):
            return discovered

        for filename in os.listdir(plugins_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                plugin_name = filename[:-3]
                discovered.append(plugin_name)
        return discovered

    def load_plugin(self, module_path: str, config: Optional[Dict[str, Any]] = None) -> BasePlugin:
        """
        Dynamically loads a plugin from a module path.
        """
        try:
            # Handle potential absolute paths by adding to sys.path if necessary
            # (Done in tests, but here we assume it's importable)
            module = importlib.import_module(module_path)
            
            plugin_class: Optional[Type[BasePlugin]] = None
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BasePlugin) and 
                    obj is not BasePlugin):
                    plugin_class = obj
                    break
            
            if not plugin_class:
                raise PluginLoadError(f"No BasePlugin subclass found in module {module_path}")

            plugin_instance = plugin_class()
            
            # Validate configuration if provided
            if config is not None:
                if not plugin_instance.validate_config(config):
                    raise PluginValidationError(f"Invalid configuration for plugin {plugin_instance.name}")

            self.register_plugin(plugin_instance)
            return plugin_instance

        except ImportError as e:
            raise PluginLoadError(f"Failed to import plugin module {module_path}: {e}")
        except Exception as e:
            if isinstance(e, (PluginLoadError, PluginValidationError)):
                raise e
            raise PluginLoadError(f"Unexpected error loading plugin {module_path}: {e}")

    def register_plugin(self, plugin: BasePlugin) -> None:
        """
        Registers a plugin instance.
        """
        self._plugins[plugin.name] = plugin
        
        # Map string type to Enum if necessary
        ptype_str = plugin.plugin_type
        try:
            ptype = PluginType[ptype_str] if isinstance(ptype_str, str) else ptype_str
            if ptype not in self._plugin_types:
                self._plugin_types[ptype] = []
            self._plugin_types[ptype].append(plugin)
        except (KeyError, ValueError):
            # If unknown type, we still keep it in _plugins but it might not be categorized
            logger.warning(f"Plugin {plugin.name} has unknown type {ptype_str}")

    def get_plugins(self, ptype: PluginType) -> List[BasePlugin]:
        """
        Returns all registered plugins of a specific type.
        """
        return self._plugin_types.get(ptype, [])

    def unload_all(self) -> None:
        """
        Unloads and cleans up all registered plugins.
        """
        for plugin in self._plugins.values():
            plugin.on_unload()
        
        self._plugins.clear()
        for ptype in self._plugin_types:
            self._plugin_types[ptype] = []
