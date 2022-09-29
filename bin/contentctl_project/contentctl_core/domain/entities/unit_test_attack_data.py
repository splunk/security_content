

from pydantic import BaseModel, validator, ValidationError


class UnitTestAttackData(BaseModel):
    file_name: str
    data: str
    source: str
    sourcetype: str = None
    update_timestamp: bool = None

    @validator('data')
    def data_valid(cls, v):
        VALID_PREAMBLES = ["https://media.githubusercontent.com/media/splunk/attack_data/master/"]
        for preamble in VALID_PREAMBLES:
            if v.startswith(preamble):
                return v

        #If we get this far, then the dataset did not exist with a valid preamble    
        valid_paths = '\n\t'.join(VALID_PREAMBLES)
        raise ValueError(f"Dataset link {v} does not being with a valid path. Valid paths are: \n\t{valid_paths}")
    
    '''
    @validator('file_name')
    def file_name_valid(cls, v, values):
        filename_from_data = values['data'].split('/')[-1]
        if v != filename_from_data:
            print(f"AttackData Source Field {values['data']} has an expected filename of {filename_from_data}, however the file_name field provided was {v}")
            #raise ValueError(f"AttackData Source Field {values['data']} has an expected filename of {filename_from_data}, however the file_name field provided was {v}")
        return v
    '''