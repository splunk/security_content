

from pydantic import BaseModel, validator, ValidationError


class UnitTestAttackData(BaseModel):
    file_name: str = None
    data: str = None
    source: str = None
    sourcetype: str = None
    update_timestamp: bool = None