
from pydantic import BaseModel, validator, ValidationError


class PlaybookTag(BaseModel):
    analytic_story: list = None
    detections: list = None
    platform_tags: list = None
    playbook_fields: list = None
    product: list = None
    playbook_fields: list = None
    detection_objects: list = None  
    