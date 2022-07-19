
import uuid
import string

from pydantic import BaseModel, validator, ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.playbook_tags import PlaybookTag
from bin.contentctl_project.contentctl_core.domain.entities.link_validator import LinkValidator



class Playbook(BaseModel, SecurityContentObject):
    name: str
    id: str
    version: int
    date: str
    author: str
    type: str
    description: str
    how_to_implement: str
    playbook: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    app_list: list
    tags: PlaybookTag

    
    @validator('references')
    def references_check(cls, v, values):
        return LinkValidator.SecurityContentObject_validate_references(v, values)

