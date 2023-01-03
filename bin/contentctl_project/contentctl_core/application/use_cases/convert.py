
import sys
import shutil
import os

from dataclasses import dataclass

from bin.contentctl_project.contentctl_infrastructure.builder.sigma_converter import SigmaConverter, SigmaConverterInputDto, SigmaConverterOutputDto
from bin.contentctl_project.contentctl_infrastructure.adapter.yml_output import YmlOutput


@dataclass(frozen=True)
class ConvertInputDto:
    sigma_converter_input_dto: SigmaConverterInputDto
    output_path : str


class Convert:

    def execute(self, input_dto: ConvertInputDto) -> None:
        sigma_converter_output_dto = SigmaConverterOutputDto([])
        sigma_converter = SigmaConverter(sigma_converter_output_dto)
        sigma_converter.execute(input_dto.sigma_converter_input_dto)

        yml_output = YmlOutput()
        yml_output.writeDetections(sigma_converter_output_dto.detections, input_dto.output_path)

        file_name = sigma_converter_output_dto.detections[0].file_path
        print('Converted Sigma detection to: ' + input_dto.output_path + '/' + file_name)