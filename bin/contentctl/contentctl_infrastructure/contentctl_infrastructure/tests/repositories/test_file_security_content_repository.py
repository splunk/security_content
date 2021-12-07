import pytest
import os

from contentctl_infrastructure.contentctl_infrastructure.repositories.file_security_content_repository import FileSecurityContentRepository


def test_read_yml_into_obj():
    repo = FileSecurityContentRepository()
    detection = repo.get(os.path.join(os.path.dirname(__file__), 'test_data/valid.yml'))
    assert detection.name == "Attempted Credential Dump From Registry via Reg exe"