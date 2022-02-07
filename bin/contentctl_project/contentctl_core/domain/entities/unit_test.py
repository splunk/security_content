

from pydantic import BaseModel, validator, ValidationError

from contentctl_core.domain.entities.security_content_object import SecurityContentObject
from contentctl_core.domain.entities.unit_test_test import UnitTestTest

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    tests: list[UnitTestTest]
    