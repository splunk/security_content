import pathlib
from pydantic import BaseModel, validator, root_validator, ValidationError

from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import (
    SecurityContentObject,
)


class Lookup(BaseModel, SecurityContentObject):
    name: str
    description: str
    # Collection indicates a KV Store that will be created and/or updated during detection runtime
    collection: str = None
    fields_list: str = None

    # Filename points to a lookup file that must exist during app build time
    filename: str = None
    default_match: str = None
    match_type: str = None
    min_matches: int = None
    case_sensitive_match: str = None

    @root_validator(pre=True)
    def ensure_collection_or_filename_exists(cls, values):
        # Exactly one of the fields "collection" or "filename" MUST be defined
        # Check max length only for ESCU searches, SSA does not have that constraint

        if (
            values.get("collection", None) == None
            and values.get("filename", None) == None
        ):
            raise ValueError(
                "Error in lookup.  Eaxctly one of 'collection' or 'filename' filename MUST be defined, but NEITHER was defined."
            )

        if (
            values.get("collection", None) != None
            and values.get("filename", None) != None
        ):
            raise ValueError(
                "Error in lookup.  Exactly one of 'collection' or 'filename' filename MUST be defined, but BOTH were defined."
            )
        return values

    @validator("filename")
    def filename_validate(cls, v, values):
        lookup_file_path = pathlib.Path(".") / "lookups" / str(v)
        if not lookup_file_path.is_file():
            raise ValueError(
                f"Lookup references lookup file '{lookup_file_path}', but that file does not exist."
            )

        return v
