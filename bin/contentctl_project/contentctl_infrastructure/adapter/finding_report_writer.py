import os
import re
from jinja2 import Environment, FileSystemLoader

from bin.contentctl_project.contentctl_core.domain.entities.detection import Detection
from bin.contentctl_project.contentctl_core.domain.constants.constants import *

class FindingReportObject():

    @staticmethod
    def writeFindingReport(detection : Detection) -> None:


        if detection.tags.risk_score < 20:
            detection.tags.risk_level_id = 0
            detection.tags.risk_level = "Info"
        elif detection.tags.risk_score < 40:
            detection.tags.risk_level_id = 1
            detection.tags.risk_level = "Low"            
        elif detection.tags.risk_score < 60:
            detection.tags.risk_level_id = 2
            detection.tags.risk_level = "Medium"   
        elif detection.tags.risk_score < 80:
            detection.tags.risk_level_id = 3
            detection.tags.risk_level = "High"   
        else:
            detection.tags.risk_level_id = 4
            detection.tags.risk_level = "Critical"  

        evidence_str = "create_map("
        for i in range(len(detection.tags.observable)):            
            evidence_str = evidence_str + '"' + detection.tags.observable[i]["name"] + '", ' + detection.tags.observable[i]["name"].replace(".", "_")
            if not i == (len(detection.tags.observable) - 1):
                evidence_str = evidence_str + ', '
        evidence_str = evidence_str + ')'        

        detection.tags.evidence_str = evidence_str

        if "actor.user.name" in detection.tags.required_fields:
            actor_user_name = "actor_user_name"
        else:
            actor_user_name = "\"Unknown\""

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)
        template = j2_env.get_template('finding_report.j2')
        body = template.render(detection=detection, attack_tactics_id_mapping=SES_ATTACK_TACTICS_ID_MAPPING, actor_user_name=actor_user_name)

        return body
