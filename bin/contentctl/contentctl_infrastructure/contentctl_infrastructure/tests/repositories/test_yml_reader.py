import pytest
import os

from contentctl_infrastructure.contentctl_infrastructure.repositories.yml_reader import YmlReader


def test_read_valid_yml_file():
    yml_obj = YmlReader.load_file(os.path.join(os.path.dirname(__file__), 'test_data/valid.yml'))
    assert yml_obj['name'] == "Attempted Credential Dump From Registry via Reg exe"
