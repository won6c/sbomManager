class SBOMManagerError(Exception):
    """Base exception for all SBOM Manager errors."""
    pass

class PluginError(SBOMManagerError):
    """Base exception for plugin-related errors."""
    pass

class PluginLoadError(PluginError):
    """Raised when a plugin fails to load."""
    pass

class PluginValidationError(PluginError):
    """Raised when a plugin configuration is invalid."""
    pass

class PipelineError(SBOMManagerError):
    """Base exception for pipeline-related errors."""
    pass

class PipelineStageError(PipelineError):
    """Raised when a specific pipeline stage fails."""
    pass
