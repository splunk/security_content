
import uuid
import string

from pydantic import BaseModel, validator, ValidationError
from datetime import datetime

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.deployment_scheduling import DeploymentScheduling
from bin.contentctl_project.contentctl_core.domain.entities.deployment_email import DeploymentEmail
from bin.contentctl_project.contentctl_core.domain.entities.deployment_notable import DeploymentNotable
from bin.contentctl_project.contentctl_core.domain.entities.deployment_rba import DeploymentRBA
from bin.contentctl_project.contentctl_core.domain.entities.deployment_slack import DeploymentSlack
from bin.contentctl_project.contentctl_core.domain.entities.deployment_phantom import DeploymentPhantom

class Deployment(BaseModel, SecurityContentObject):
    name: str
    id: str
    date: str
    author: str
    description: str
    scheduling: DeploymentScheduling = None
    email: DeploymentEmail = None
    notable: DeploymentNotable = None
    rba: DeploymentRBA = None
    slack: DeploymentSlack = None
    phantom: DeploymentPhantom = None
    tags: dict
    

    @validator('name')
    def name_invalid_chars(cls, v):
        invalidChars = set(string.punctuation.replace("-", ""))
        if any(char in invalidChars for char in v):
            raise ValueError('invalid chars used in name: ' + v)
        return v

    @validator('id')
    def id_check(cls, v, values):
        try:
            uuid.UUID(str(v))
        except:
            raise ValueError('uuid is not valid: ' + values["name"])
        return v

    @validator('date')
    def date_valid(cls, v, values):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError('date is not in format YYYY-MM-DD: ' + values["name"])
        return v

    @validator('description')
    def encode_error(cls, v, values, field):
        try:
            v.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('encoding error in ' + field.name + ': ' + values["name"])
        return v