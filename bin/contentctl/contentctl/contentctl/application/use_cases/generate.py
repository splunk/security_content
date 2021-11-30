from dataclasses import dataclass
import abc


@dataclass(frozen=True)
class GenerateInputDto:
    input_path: str
    output_path: str


@dataclass(frozen=True)
class GenerateOutputDto:
    message: str


class GenerateOutputBoundary(abc.ABC):
    @abc.abstractmethod
    def present(self, output_dto: GenerateOutputDto) -> None:
        pass


class Generate:
    def __init__(self, output_boundary: GenerateOutputBoundary) -> None:
        self._output_boundary = output_boundary

    def execute(self, input_dto: GenerateInputDto) -> None:
        pass