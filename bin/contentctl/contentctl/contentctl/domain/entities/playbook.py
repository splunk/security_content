
import uuid
import string

from pydantic import BaseModel, validator, ValidationError

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.domain.entities.playbook_tags import PlaybookTag



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
    references: list
    app_list: list
    tags: PlaybookTag

