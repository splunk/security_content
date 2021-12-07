import pytest
import os

from unittest.mock import Mock, patch

from contentctl.contentctl.application.use_cases.generate import Generate, GenerateInputDto, GenerateOutputDto, GenerateOutputBoundary
from contentctl_infrastructure.contentctl_infrastructure.repositories.file_security_content_repository import FileSecurityContentRepository


@pytest.fixture
def input_path() -> str:
    return os.path.join(os.path.dirname(__file__), "test_data_input")

@pytest.fixture
def output_path() -> str:
    return os.path.join(os.path.dirname(__file__), "test_data_output")

def test_generate_security_content(input_path, output_path) -> None:
    output_boundary_mock = Mock(
        spec_set=GenerateOutputBoundary
    )
    input_dto = GenerateInputDto(input_path, output_path)
    repo = FileSecurityContentRepository()
    generate = Generate(output_boundary_mock, repo)
    generate.execute(input_dto)
