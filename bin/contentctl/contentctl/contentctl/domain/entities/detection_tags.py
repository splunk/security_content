import re

from pydantic import BaseModel, validator, ValidationError



class DetectionTags(BaseModel):
    name: str
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


    @validator('cis20')
    def tags_cis20(cls, v):
        pattern = 'CIS [0-9]{1,2}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('CIS controls are not following the pattern CIS xx')
        return v

    @validator('confidence')
    def tags_confidence(cls, v):
        v = int(v)
        if not (v > 0 and v <= 100):
             raise ValueError('confidence score is out of range 1-100')
        else:
            return v

    @validator('context')
    def tags_context(cls, v):
        context_list = [
            "Other", "Unknown", "Source:Endpoint",
            "Source:AD", "Source:Firewall", "Source:Application Log",
            "Source:IPS", "Source:Cloud Data", "Source:Correlation",
            "Source:Printer", "Source:Badge", "Scope:Internal",
            "Scope:External", "Scope:Inbound", "Scope:Outbound",
            "Scope:Local", "Scope:Network", "Outcome:Blocked",
            "Outcome:Allowed", "Stage:Recon", "Stage:Initial Access",
            "Stage:Execution", "Stage:Persistence", "Stage:Privilege Escalation",
            "Stage:Defense Evasion", "Stage:Credential Access", "Stage:Discovery",
            "Stage:Lateral Movement", "Stage:Collection", "Stage:Exfiltration",
            "Stage:Command And Control", "Consequence:Infection", "Consequence:Reduced Visibility",
            "Consequence:Data Destruction", "Consequence:Denial Of Service", "Consequence:Loss Of Control",
            "Rares:Rare User", "Rares:Rare Process", "Rares:Rare Device", 
            "Rares:Rare Domain", "Rares:Rare Network", "Rares:Rare Location",
            "Other:Peer Group", "Other:Brute Force", "Other:Policy Violation",
            "Other:Threat Intelligence", "Other:Flight Risk", "Other:Removable Storage"
        ]
        for value in v:
            if value not in context_list:
                raise ValueError('context value not valid. valid options are ' + str(context_list))
        return v

    @validator('impact')
    def tags_impact(cls, v):
        if not (v > 0 and v <= 100):
             raise ValueError('impact score is out of range 1-100')
        else:
            return v

    @validator('kill_chain_phases')
    def tags_kill_chain_phases(cls, v):
        valid_kill_chain_phases = [
            'Reconnaissance', 'Weaponization', 'Delivery', 
            'Exploitation', 'Installation', 'Command and Control', 
            'Actions on Objectives']
        for value in v:
            if value not in valid_kill_chain_phases:
                raise ValueError('kill chain phase not in ' + str(valid_kill_chain_phases))
        return v

    @validator('mitre_attack_id')
    def tags_mitre_attack_id(cls, v):
        pattern = 'T[0-9]{4}'
        for value in v:
            if not re.match(pattern, value):
                raise ValueError('Mitre Attack ID are not following the pattern Txxxx')
        return v

    @validator('observable')
    def tags_observable(cls,v,values):
        print(values)
        valid_roles = [
            "Other", "Unknown", "Actor",
            "Target", "Attacker", "Victim",
            "Parent Process", "Child Process", "Known Bad",
            "Data Loss", "Observer"
        ]
        valid_types = [
            "Other", "Unknown", "Device",
            "Container", "Endpoint", "Hostname",
            "IP Address", "User", "Username",
            "Email", "Email Address", "URL",
            "URL Domain", "File", "File Name",
            "File Hash", "Process", "Process Name",
            "Location"
        ]
        
        for value in v:
            if value['type'] in valid_types:
                for role in value['role']:
                    if role not in valid_roles:
                        raise ValueError('Observable role ' + role + ' not valid. valid options are ' + str(valid_roles))
            else:
                raise ValueError('Observable type ' + value['type'] + ' not valid. valid options are ' + str(valid_types))
        return v


    @validator('risk_score')
    def tags_calculate_risk_score(cls, v, values):
        calculated_risk_score = (int(values['impact']))*(int(values['confidence']))/100
        if calculated_risk_score != int(v):
            raise ValueError('risk_score is calculated wrong')
        return v

