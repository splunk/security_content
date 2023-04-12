

from pydantic import BaseModel, validator, ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.unit_test_attack_data import UnitTestAttackData
from bin.contentctl_project.contentctl_core.domain.entities.unit_test_baseline import UnitTestBaseline

class UnitTest(BaseModel):
    name: str
    baselines: list[UnitTestBaseline] = None
    attack_data: list[UnitTestAttackData]
    