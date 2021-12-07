

from pydantic import BaseModel, validator, ValidationError



class DetectionTags(BaseModel):
    analytic_story: list
    asset_type: str
    automated_detection_testing: str = None
    cis20: list
    confidence: str
    context: list
    dataset: list = None
    impact: int
    kill_chain_phases: list
    message: str
    mitre_attack_id: list
    nist: list
    observable: list
    product: list
    required_fields: list
    risk_score: int
    security_domain: str


    @validator('risk_score')
    def tags_calculate_risk_score(cls, v, values):
        calculated_risk_score = (int(values['impact']))*(int(values['confidence']))/100
        if calculated_risk_score != int(v):
            raise ValueError('risk_score is calculated wrong')
        return v