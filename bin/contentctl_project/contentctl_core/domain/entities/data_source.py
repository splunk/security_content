


from pydantic import BaseModel, validator, ValidationError
from dataclasses import dataclass


class DataSource(BaseModel):
    name: str
    id: str
    date: str
    author: str
    type: str
    source: str
    sourcetype: str
    category: str = None
    product: str
    service: str = None
    supported_TA: list
    references: list
    raw_fields: list
    field_mappings: list = None
    convert_to_log_source: list = None