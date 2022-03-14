import string
import uuid
import requests

from pydantic import BaseModel, validator, ValidationError
from datetime import datetime

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.story_tags import StoryTags

class Story(BaseModel, SecurityContentObject):
    # story spec
    name: str
    id: str
    version: int
    date: str
    author: str
    description: str
    narrative: str
    references: list
    tags: StoryTags

    # enrichments
    detection_names: list = None
    investigation_names: list = None
    baseline_names: list = None
    author_company: str = None
    author_name: str = None
    detections: list = None
    investigations: list = None
    
    
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

    @validator('description', 'narrative')
    def encode_error(cls, v, values, field):
        try:
            v.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('encoding error in ' + field.name + ': ' + values["name"])
        return v

    # @validator('references')
    # def references_check(cls, v, values):
    #     for reference in v:
    #         try:
    #             get = requests.get(reference)
    #             if not get.status_code == 200:
    #                 raise ValueError('Reference ' + reference + ' is not reachable: ' + values["name"])
    #         except requests.exceptions.RequestException as e:
    #             raise ValueError('Reference ' + reference + ' is not reachable: ' + values["name"])

    #     return v