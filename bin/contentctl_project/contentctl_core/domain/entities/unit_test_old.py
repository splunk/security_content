

from pydantic import BaseModel, validator, ValidationError


from bin.contentctl_project.contentctl_core.domain.entities.unit_test import UnitTest


class UnitTestOld(BaseModel):
    name: str
    tests: list[UnitTest]
    