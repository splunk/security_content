

from pydantic import BaseModel, validator, ValidationError


class StoryTags(BaseModel):
    analytic_story: str
    category: list
    product: list
    usecase: str

    