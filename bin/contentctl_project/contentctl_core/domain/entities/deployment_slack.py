
from pydantic import BaseModel, validator, ValidationError


class DeploymentSlack(BaseModel):
    channel: str
    message: str