

from pydantic import BaseModel, validator, ValidationError

from contentctl_core.domain.entities.security_content_object import SecurityContentObject



class Macro(BaseModel, SecurityContentObject):
    name: str
    definition: str
    description: str
    arguments: list = None
