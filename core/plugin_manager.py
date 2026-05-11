from enum import Enum, auto

class PluginType(Enum):
    PARSER = auto()
    CVE_PROVIDER = auto()

class PluginManager:
    """
    Manages dynamic discovery, loading, and registration of plugins.
    """
    def __init__(self):
        self._plugins = {}
        self._plugin_types = {ptype: [] for ptype in PluginType}

    def discover_plugins(self, plugins_dir: str):
        return [] # Basic implementation for now

    def load_plugin(self, module_path: str, config=None):
        return None # Basic implementation for now

    def register_plugin(self, plugin):
        pass

    def get_plugins(self, ptype: PluginType):
        return []

    def unload_all(self):
        pass
