
from pydantic import BaseModel, validator, ValidationError



class BaselineTags(BaseModel):
    analytic_story: list
    deployments: list = None
    detections: list
    product: list
    required_fields: list
    security_domain: str


    @validator('product')
    def tags_product(cls, v, values):
        valid_products = [
            "Splunk Enterprise", "Splunk Enterprise Security", "Splunk Cloud",
            "Splunk Security Analytics for AWS", "Splunk Behavioral Analytics"
        ]

        for value in v:
            if value not in valid_products:
                raise ValueError('product is not valid for ' + values['name'] + '. valid products are ' + str(valid_products))
        return v