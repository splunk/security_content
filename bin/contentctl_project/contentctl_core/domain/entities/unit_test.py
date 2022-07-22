

from pydantic import BaseModel, validator, ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.unit_test_test import UnitTestTest

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    tests: list[UnitTestTest]
    