

from pydantic import BaseModel, validator, ValidationError


class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str = None
    update_timestamp: bool = None