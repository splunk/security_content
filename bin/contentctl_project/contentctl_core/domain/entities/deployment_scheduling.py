

from pydantic import BaseModel, validator, ValidationError


class DeploymentScheduling(BaseModel):
    cron_schedule: str
    earliest_time: str
    latest_time: str
    schedule_window: str