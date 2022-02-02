

from pydantic import BaseModel, validator, ValidationError

from contentctl_core.domain.entities.security_content_object import SecurityContentObject
from contentctl_core.domain.entities.unit_test_attack_data import UnitTestAttackData
from contentctl_core.domain.entities.unit_test_baseline import UnitTestBaseline

class UnitTest(BaseModel, SecurityContentObject):
    name: str
    file: str
    pass_condition: str
    earliest_time: str = None
    latest_time: str = None
    baselines: list[UnitTestBaseline] = None
    attack_data: list[UnitTestAttackData]
    