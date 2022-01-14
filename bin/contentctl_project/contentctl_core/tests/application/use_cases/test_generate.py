import pytest
import os

from contentctl_core.application.use_cases.generate import Generate, GenerateInputDto, GenerateOutputDto, GenerateOutputBoundary


@pytest.fixture
def input_path() -> str:
    return os.path.join(os.path.dirname(__file__), "test_data_input")

@pytest.fixture
def output_path() -> str:
    return os.path.join(os.path.dirname(__file__), "test_data_output")

def test_generate_security_content(input_path, output_path) -> None:
    # output_boundary_mock = Mock(
    #     spec_set=GenerateOutputBoundary
    # )
    # input_dto = GenerateInputDto(input_path, output_path)
    # repo = FileSecurityContentRepository()
    # generate = Generate(output_boundary_mock, repo)
    # generate.execute(input_dto)
    pass
