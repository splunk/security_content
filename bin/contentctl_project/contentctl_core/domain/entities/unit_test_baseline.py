

from pydantic import BaseModel, validator, ValidationError


class UnitTestBaseline(BaseModel):
    name: str
    file: str
    pass_condition: str
    earliest_time: str
    latest_time: str