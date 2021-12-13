

from pydantic import BaseModel, validator, ValidationError
from datetime import datetime

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject


class Story(BaseModel, SecurityContentObject):
    name: str
    id: str
    version: int
    date: str
    author: str
    type: str
    description: str
    narrative: str
    references: list
    