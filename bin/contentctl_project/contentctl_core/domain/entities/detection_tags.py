import re

from pydantic import BaseModel, validator, ValidationError
from bin.contentctl_project.contentctl_core.domain.entities.mitre_attack_enrichment import MitreAttackEnrichment
from bin.contentctl_project.contentctl_core.domain.constants.constants import *


class DetectionTags(BaseModel):
    # detection spec
    name: str
    analytic_story: list
    asset_type: str
    automated_detection_testing: str = None
    cis20: list = None
    confidence: str
    context: list = None
    dataset: list = None
    impact: int
    kill_chain_phases: list = None
    message: str
    mitre_attack_id: list = None
    nist: list = None
    observable: list
    product: list
    required_fields: list = None
    risk_score: int
    security_domain: str
    risk_severity: str = None
    cve: list = None
    supported_tas: list = None
    atomic_guid: list = None
    drilldown_search: str = None
    manual_test: str = None


    # enrichment
    mitre_attack_enrichments: list[MitreAttackEnrichment] = []
    confidence_id: int = None
    impact_id: int = None
    context_ids: list = None
    risk_level_id: int = None
    risk_level: str = None
    observable_str: str = None
    evidence_str: str = None
    kill_chain_phases_id: list = None
    research_site_url: str = None
    event_schema: str = None
    mappings: list = None


    @validator('cis20')
    def tags_cis20(cls, v, values):
        pattern = '^CIS ([0-9]|1[0-9]|20)$' #DO NOT match leading zeroes and ensure no extra characters before or after the string
        for value in v:
            if not re.match(pattern, value):
                raise ValueError(f"CIS control '{value}' is not a valid Control ('CIS 1' -> 'CIS 20'):  {values['name']}")
        return v
    
    @validator('nist')
    def tags_nist(cls, v, values):
        # Sourced Courtest of NIST: https://www.nist.gov/system/files/documents/cyberframework/cybersecurity-framework-021214.pdf (Page 19)
        IDENTIFY = [f'ID.{category}' for category in ["AM", "BE", "GV", "RA", "RM"]      ]
        PROTECT  = [f'PR.{category}' for category in ["AC", "AT", "DS", "IP", "MA", "PT"]]
        DETECT   = [f'DE.{category}' for category in ["AE", "CM", "DP"]                  ]
        RESPOND  = [f'RS.{category}' for category in ["RP", "CO", "AN", "MI", "IM"]      ]
        RECOVER  = [f'RC.{category}' for category in ["RP", "IM", "CO"]                  ]
        ALL_NIST_CATEGORIES = IDENTIFY + PROTECT + DETECT + RESPOND + RECOVER

        
        for value in v:
            if not value in ALL_NIST_CATEGORIES:
                raise ValueError(f"NIST Category '{value}' is not a valid category")
        return v

    @validator('confidence')
    def tags_confidence(cls, v, values):
        v = int(v)
        if not (v > 0 and v <= 100):
             raise ValueError('confidence score is out of range 1-100: ' + values["name"])
        else:
            return v

    @validator('context')
    def tags_context(cls, v, values):
        context_list = SES_CONTEXT_MAPPING.keys()
        for value in v:
            if value not in context_list:
                raise ValueError('context value not valid for ' + values["name"] + '. valid options are ' + str(context_list) )
        return v

    @validator('impact')
    def tags_impact(cls, v, values):
        if not (v > 0 and v <= 100):
             raise ValueError('impact score is out of range 1-100: ' + values["name"])
        else:
            return v

    @validator('kill_chain_phases')
    def tags_kill_chain_phases(cls, v, values):
        valid_kill_chain_phases = SES_KILL_CHAIN_MAPPINGS.keys()
        for value in v:
            if value not in valid_kill_chain_phases:
                raise ValueError('kill chain phase not valid for ' + values["name"] + '. valid options are ' + str(valid_kill_chain_phases))
        return v

    @validator('mitre_attack_id')
    def tags_mitre_attack_id(cls, v, values):
        pattern = 'T[0-9]{4}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('Mitre Attack ID are not following the pattern Txxxx: ' + values["name"])
        return v

    # @validator('observable')
    # def tags_observable(cls,v,values):
    #     valid_roles = SES_OBSERVABLE_ROLE_MAPPING.keys()
    #     valid_types = SES_OBSERVABLE_TYPE_MAPPING.keys()
        
    #     for value in v:
    #         if value['type'] in valid_types:
    #             for role in value['role']:
    #                 if role not in valid_roles:
    #                     raise ValueError('Observable role ' + role + ' not valid for ' + values["name"] + '. valid options are ' + str(valid_roles))
    #         else:
    #             raise ValueError('Observable type ' + value['type'] + ' not valid for ' + values["name"] + '. valid options are ' + str(valid_types))
    #     return v

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

    @validator('risk_score')
    def tags_calculate_risk_score(cls, v, values):
        calculated_risk_score = round(values['impact'] * values['confidence'] / 100)
        if calculated_risk_score != int(v):
            raise ValueError(f"Risk Score must be calculated as round(confidence * impact / 100)"
                             f"\n  Expected risk_score={calculated_risk_score}, found risk_score={int(v)}: {values['name']}")
        return v

