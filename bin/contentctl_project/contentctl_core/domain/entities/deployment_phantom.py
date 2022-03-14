
from pydantic import BaseModel, validator, ValidationError


class DeploymentPhantom(BaseModel):
    cam_workers : str
    label : str
    phantom_server : str
    sensitivity : str
    severity : str