import pytest
from core.plugin_manager import PluginManager, PluginType
from core.pipeline import Pipeline, PipelineStage
from core.models import Component, MappingResult
from core.base import BasePlugin
from typing import Any, Dict

class MockParserPlugin(BasePlugin):
    @property
    def name(self) -> str: return "mock-parser"
    @property
    def version(self) -> str: return "1.0.0"
    @property
    def plugin_type(self) -> str: return "SBOM_PARSER"
    def validate_config(self, config: Dict) -> bool: return True
    def execute(self, data: Any) -> Any:
        # Simulate parsing a string into a Component
        return Component(name=data, version="1.0.0")
    def on_load(self) -> None: pass
    def on_unload(self) -> None: pass

class MockMapperPlugin(BasePlugin):
    @property
    def name(self) -> str: return "mock-mapper"
    @property
    def version(self) -> str: return "1.0.0"
    @property
    def plugin_type(self) -> str: return "CVE_PROVIDER"
    def validate_config(self, config: Dict) -> bool: return True
    def execute(self, data: Any) -> Any:
        # Simulate mapping a Component to a result
        return MappingResult(component=data, vulnerabilities=[])
    def on_load(self) -> None: pass
    def on_unload(self) -> None: pass

def test_core_integration_flow():
    # 1. Setup Plugin Manager and load plugins
    pm = PluginManager()
    parser = MockParserPlugin()
    mapper = MockMapperPlugin()

    pm.register_plugin(parser)
    pm.register_plugin(mapper)

    # 2. Setup Pipeline
    pipeline = Pipeline()

    # Stage handlers using plugins
    def parse_stage(data):
        parser_plugin = pm.get_plugins(PluginType.SBOM_PARSER)[0]
        return parser_plugin.execute(data)

    def map_stage(data):
        mapper_plugin = pm.get_plugins(PluginType.CVE_PROVIDER)[0]
        return mapper_plugin.execute(data)

    pipeline.add_stage(PipelineStage.PARSE, parse_stage)
    pipeline.add_stage(PipelineStage.MAP, map_stage)

    # 3. Run pipeline
    input_sbom_data = "test-package-name"
    result = pipeline.run(input_sbom_data)

    # 4. Verify results
    assert isinstance(result, MappingResult)
    assert result.component.name == "test-package-name"
    assert isinstance(result.vulnerabilities, list)
