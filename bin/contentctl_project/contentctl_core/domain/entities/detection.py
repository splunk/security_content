import uuid
import string
import requests
import time
from pydantic import BaseModel, validator, root_validator
from dataclasses import dataclass
from datetime import datetime
from typing import Union


from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import (
    SecurityContentObject,
)
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import (
    AnalyticsType,
)
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import DataModel
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import (
    DetectionStatus,
)


from bin.contentctl_project.contentctl_core.domain.entities.detection_tags import (
    DetectionTags,
)
from bin.contentctl_project.contentctl_core.domain.entities.deployment import Deployment
from bin.contentctl_project.contentctl_core.domain.entities.unit_test import UnitTest
from bin.contentctl_project.contentctl_core.domain.entities.macro import Macro
from bin.contentctl_project.contentctl_core.domain.entities.lookup import Lookup
from bin.contentctl_project.contentctl_core.domain.entities.baseline import Baseline
from bin.contentctl_project.contentctl_core.domain.entities.playbook import Playbook
from bin.contentctl_project.contentctl_core.domain.entities.link_validator import (
    LinkValidator,
)
from bin.contentctl_project.contentctl_core.domain.entities.deployment import Deployment
import sys


class Detection(BaseModel, SecurityContentObject):
    # detection spec
    name: str
    id: str
    version: int
    date: str
    author: str
    type: str
    status: DetectionStatus
    description: str
    data_source: list[str]
    search: Union[str, dict]
    how_to_implement: str
    known_false_positives: str
    references: list
    tags: DetectionTags
    tests: list[UnitTest] = None

    # enrichments
    datamodel: list = None
    deprecated: bool = None
    experimental: bool = None
    deployment: Deployment = None
    annotations: dict = None
    risk: list = None
    playbooks: list[Playbook] = None
    baselines: list[Baseline] = None
    mappings: dict = None
    test: Union[UnitTest, dict] = None
    macros: list[Macro] = None
    lookups: list[Lookup] = None
    cve_enrichment: list = None
    splunk_app_enrichment: list = None
    file_path: str = None
    source: str = None
    nes_fields: str = None
    providing_technologies: list = None
    runtime: str = None

    # @validator('name')v
    # def name_max_length(cls, v, values):
    #     if len(v) > 67:
    #         raise ValueError('name is longer then 67 chars: ' + v)
    #     return v

    class Config:
        use_enum_values = True

    @validator("name")
    def name_invalid_chars(cls, v):
        invalidChars = set(string.punctuation.replace("-", ""))
        if any(char in invalidChars for char in v):
            raise ValueError("invalid chars used in name: " + v)
        return v

    @validator("id")
    def id_check(cls, v, values):
        try:
            uuid.UUID(str(v))
        except:
            raise ValueError("uuid is not valid: " + values["name"])
        return v

    @validator("date")
    def date_valid(cls, v, values):
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except:
            raise ValueError("date is not in format YYYY-MM-DD: " + values["name"])
        return v

    @validator("type")
    def type_valid(cls, v, values):
        if v.lower() not in [el.name.lower() for el in AnalyticsType]:
            raise ValueError("not valid analytics type: " + values["name"])
        return v

    @validator("description", "how_to_implement")
    def encode_error(cls, v, values, field):
        try:
            v.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("encoding error in " + field.name + ": " + values["name"])
        return v

    # @root_validator
    # def search_validation(cls, values):
    #     if 'ssa_' not in values['file_path']:
    #         if not '_filter' in values['search']:
    #             raise ValueError('filter macro missing in: ' + values["name"])
    #         if any(x in values['search'] for x in ['eventtype=', 'sourcetype=', ' source=', 'index=']):
    #             if not 'index=_internal' in values['search']:
    #                 raise ValueError('Use source macro instead of eventtype, sourcetype, source or index in detection: ' + values["name"])
    #     return values

    @root_validator
    def name_max_length(cls, values):
        # Check max length only for ESCU searches, SSA does not have that constraint
        if "ssa_" not in values["file_path"]:
            if len(values["name"]) > 67:
                raise ValueError("name is longer then 67 chars: " + values["name"])
        return values

    # @validator('references')
    # def references_check(cls, v, values):
    #     return LinkValidator.SecurityContentObject_validate_references(v, values)

    @root_validator
    def missing_test_file(cls, values):
        if values["status"] == DetectionStatus.production:
            if "tests" not in values:
                raise ValueError("Missing test file for detection: " + values["name"])
        return values

    @validator("search")
    def search_validate(cls, v, values):
        # write search validator
        return v

    @validator("tests")
    def tests_validate(cls, v, values):
        if values["status"] != DetectionStatus.production and not v:
            raise ValueError(
                "tests value is needed for production detection: " + values["name"]
            )
        return v

    @validator("experimental", always=True)
    def experimental_validate(cls, v, values):
        if DetectionStatus(values["status"]) == DetectionStatus.experimental:
            return True
        return False

    @validator("deprecated", always=True)
    def deprecated_validate(cls, v, values):
        if DetectionStatus(values["status"]) == DetectionStatus.deprecated:
            return True
        return False
