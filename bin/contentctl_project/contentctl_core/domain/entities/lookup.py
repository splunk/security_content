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
        
        #Also check the format of the lookup file. It MUST be a valid CSV.  Valid CSV must have the 
        #correct number of fields (each row has the same number of columns, even if empty, as the
        # number of columns declared at the top of the file)
        import csv
        with open(lookup_file_path, "r") as csv_file_obj:
            reader = csv.reader(csv_file_obj, delimiter=',',quoting=csv.QUOTE_ALL)
            try:
                reader_list = list(reader)
            except Exception as e:
                raise ValueError(f"Error validating lookup file '{lookup_file_path}': the follow error was encountered when parsing the csv file: {str(e)}")
            if len(reader_list)>0:
                csv_keys = reader_list[0]
            else:
                raise ValueError(f"Error validating lookup file '{lookup_file_path}': 0 rows found in file. a csv MUST contain at least one row (which contains the field names)")

            row_errors=[]
            for index,row in enumerate(reader_list[1:]):
                if len(row) != len(csv_keys) and len(row) != 0:
                    row_errors.append(f"Error in row {index+2}: expected {len(csv_keys)} columns but got {len(row)}.")
            if len(row_errors) > 0:
                condensed_string = '\n\t'.join(row_errors)
                raise ValueError(f"Error validating lookup file '{lookup_file_path}':\n\t{condensed_string}.")
            
        return v
    

