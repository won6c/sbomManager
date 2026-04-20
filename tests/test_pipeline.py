import pytest
from core.pipeline import Pipeline, PipelineStage
from core.exceptions import PipelineError, PipelineStageError

def test_pipeline_execution_flow():
    pipeline = Pipeline()

    # Mock handlers
    def parse_handler(data): return f"parsed_{data}"
    def enrich_handler(data): return f"enriched_{data}"
    def map_handler(data): return f"mapped_{data}"
    def export_handler(data): return f"exported_{data}"

    pipeline.add_stage(PipelineStage.PARSE, parse_handler)
    pipeline.add_stage(PipelineStage.ENRICH, enrich_handler)
    pipeline.add_stage(PipelineStage.MAP, map_handler)
    pipeline.add_stage(PipelineStage.EXPORT, export_handler)

    result = pipeline.run("input")
    assert result == "exported_mapped_enriched_parsed_input"

def test_pipeline_partial_stages():
    pipeline = Pipeline()

    def parse_handler(data): return f"parsed_{data}"
    def map_handler(data): return f"mapped_{data}"

    pipeline.add_stage(PipelineStage.PARSE, parse_handler)
    pipeline.add_stage(PipelineStage.MAP, map_handler)

    # ENRICH and EXPORT are missing, should just pass through
    result = pipeline.run("input")
    assert result == "mapped_parsed_input"

def test_pipeline_state_management():
    pipeline = Pipeline()

    def stateful_handler(data):
        pipeline.set_state("processed_count", 1)
        return f"processed_{data}"

    pipeline.add_stage(PipelineStage.PARSE, stateful_handler)

    pipeline.run("input")
    assert pipeline.get_state("processed_count") == 1

def test_pipeline_error_handling():
    pipeline = Pipeline()

    def failing_handler(data):
        raise ValueError("unexpected error")

    pipeline.add_stage(PipelineStage.PARSE, failing_handler)

    with pytest.raises(PipelineStageError):
        pipeline.run("input")

def test_pipeline_custom_error():
    pipeline = Pipeline()

    def failing_handler(data):
        from core.exceptions import PipelineError
        raise PipelineError("custom pipeline error")

    pipeline.add_stage(PipelineStage.PARSE, failing_handler)

    with pytest.raises(PipelineError):
        pipeline.run("input")
