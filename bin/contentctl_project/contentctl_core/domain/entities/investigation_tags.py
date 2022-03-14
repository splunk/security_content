
from pydantic import BaseModel, validator, ValidationError


class InvestigationTags(BaseModel):
    analytic_story: list
    product: list
    required_fields: list
    security_domain: str