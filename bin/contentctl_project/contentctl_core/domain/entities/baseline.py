import string
import uuid
import requests

from pydantic import BaseModel, validator, ValidationError
from dataclasses import dataclass
from datetime import datetime

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import DataModel
from bin.contentctl_project.contentctl_core.domain.entities.baseline_tags import BaselineTags
from bin.contentctl_project.contentctl_core.domain.entities.deployment import Deployment
from bin.contentctl_project.contentctl_core.domain.entities.link_validator import LinkValidator


class Baseline(BaseModel, SecurityContentObject):
    # baseline spec
    name: str
    id: str
    version: int
    date: str
    author: str
    type: str
    datamodel: list
    description: str
    search: str
    how_to_implement: str
    known_false_positives: str
    check_references: bool = False #Validation is done in order, this field must be defined first
    references: list
    tags: BaselineTags

    # enrichment
    deployment: Deployment = None


    @validator('name')
    def name_max_length(cls, v):
        if len(v) > 67:
            raise ValueError('name is longer then 67 chars: ' + v)
        return v

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

    @validator('type')
    def type_valid(cls, v, values):
        if v != "Baseline":
            raise ValueError('not valid analytics type: ' + values["name"])
        return v

    @validator('datamodel')
    def datamodel_valid(cls, v, values):
        for datamodel in v:
            if datamodel not in [el.name for el in DataModel]:
                raise ValueError('not valid data model: ' + values["name"])
        return v

    @validator('description', 'how_to_implement')
    def encode_error(cls, v, values, field):
        try:
            v.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('encoding error in ' + field.name + ': ' + values["name"])
        return v

    @validator('references')
    def references_check(cls, v, values):

        return LinkValidator.SecurityContentObject_validate_references(v, values)


    @validator('search')
    def search_validate(cls, v, values):
        # write search validator
        return v
