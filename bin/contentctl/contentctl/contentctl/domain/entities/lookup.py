from pydantic import BaseModel, validator, ValidationError

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject



class Lookup(BaseModel, SecurityContentObject):
    name: str
    description: str
    collection: str = None
    fields_list: list = None
    filename: str = None
    default_match: str = None
    match_type: str = None
    min_matches: int = None
    case_sensitive_match: str = None