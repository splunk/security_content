from pydantic import BaseModel, validator, ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject



class Lookup(BaseModel, SecurityContentObject):
    name: str
    description: str
    collection: str = None
    fields_list: str = None
    filename: str = None
    default_match: str = None
    match_type: str = None
    min_matches: int = None
    case_sensitive_match: str = None
