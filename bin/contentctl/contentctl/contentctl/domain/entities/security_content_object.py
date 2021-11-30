from dataclasses import dataclass
from pydantic import BaseModel, validator


@dataclass
class SecurityContentObject(BaseModel):
    content: dict

    
