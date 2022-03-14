
from pydantic import BaseModel, validator, ValidationError


class DeploymentEmail(BaseModel):
    message: str
    subject: str
    to: str