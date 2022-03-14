

from pydantic import BaseModel, validator, ValidationError


class DeploymentRBA(BaseModel):
    enabled: str