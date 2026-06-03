from abc import ABC, abstractmethod
from typing import Any, Dict

class BasePlugin(ABC):
    """
    Abstract Base Class for all SBOM Manager plugins.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """The unique name of the plugin."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """The version of the plugin."""
        pass

    @property
    @abstractmethod
    def plugin_type(self) -> str:
        """The type of plugin (e.g., 'SBOM_PARSER', 'CVE_PROVIDER')."""
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate the provided configuration.
        Returns True if valid, False otherwise.
        """
        pass

    @abstractmethod
    def execute(self, data: Any) -> Any:
        """
        Execute the plugin's main logic.
        """
        pass

    def on_load(self) -> None:
        """Lifecycle hook called when the plugin is loaded."""
        pass

    def on_unload(self) -> None:
        """Lifecycle hook called when the plugin is unloaded."""
        pass
