import pytest
import os

from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader


def test_read_detection_file():
    yml_obj = YmlReader.load_file(os.path.join(os.path.dirname(__file__), 'test_data/detection/valid.yml'))
    assert yml_obj['name'] == "Attempted Credential Dump From Registry via Reg exe"
