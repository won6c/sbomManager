from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from core.exceptions import PipelineError, PipelineStageError

class PipelineStage(Enum):
    PARSE = "PARSE"
    ENRICH = "ENRICH"
    MAP = "MAP"
    EXPORT = "EXPORT"

class Pipeline:
    """
    Orchestrates the flow of data through various processing stages.
    """
    def __init__(self):
        self._stages: Dict[PipelineStage, Callable[[Any], Any]] = {}
        self._state: Dict[str, Any] = {}

    def add_stage(self, stage: PipelineStage, handler: Callable[[Any], Any]) -> None:
        """
        Register a handler for a specific pipeline stage.
        """
        self._stages[stage] = handler

    def run(self, input_data: Any) -> Any:
        """
        Execute the pipeline stages in order.
        """
        current_data = input_data

        # Define the execution order
        execution_order = [
            PipelineStage.PARSE,
            PipelineStage.ENRICH,
            PipelineStage.MAP,
            PipelineStage.EXPORT
        ]

        try:
            for stage in execution_order:
                handler = self._stages.get(stage)
                if handler:
                    # print(f"Executing stage: {stage.value}")
                    current_data = handler(current_data)
                else:
                    # If a stage is missing, we just pass the data through
                    pass

            return current_data

        except Exception as e:
            # Wrap unexpected exceptions in PipelineStageError
            if isinstance(e, PipelineError):
                raise e
            raise PipelineStageError(f"Pipeline failed during execution: {str(e)}") from e

    def set_state(self, key: str, value: Any) -> None:
        """Set metadata or shared state for the pipeline."""
        self._state[key] = value

    def get_state(self, key: str) -> Optional[Any]:
        """Retrieve shared state for the pipeline."""
        return self._state.get(key)
