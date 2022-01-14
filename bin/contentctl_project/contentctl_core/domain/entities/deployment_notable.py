
from pydantic import BaseModel, validator, ValidationError


class DeploymentNotable(BaseModel):
    rule_description: str
    rule_title: str
    nes_fields: list