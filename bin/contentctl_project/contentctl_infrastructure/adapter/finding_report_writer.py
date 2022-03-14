import os
import re
from jinja2 import Environment, FileSystemLoader

from bin.contentctl_project.contentctl_core.domain.entities.detection import Detection
from bin.contentctl_project.contentctl_core.domain.constants.constants import *

class FindingReportObject():

    @staticmethod
    def writeFindingReport(detection : Detection) -> None:
    
        if detection.tags.confidence < 33:
            detection.tags.confidence_id = 1
        elif detection.tags.confidence < 66:
            detection.tags.confidence_id = 2
        else:
            detection.tags.confidence_id = 3

        detection.tags.context_ids = list()
        for context in detection.tags.context:
            detection.tags.context_ids.append(SES_CONTEXT_MAPPING[context])
        
        if detection.tags.impact < 20:
            detection.tags.impact_id = 1
        elif detection.tags.impact < 40:
            detection.tags.impact_id = 2
        elif detection.tags.impact < 60:
            detection.tags.impact_id = 3
        elif detection.tags.impact < 80:
            detection.tags.impact_id = 4
        else:
            detection.tags.impact_id = 5                 

        detection.tags.kill_chain_phases_id = list()
        for kill_chain_phase in detection.tags.kill_chain_phases:
            detection.tags.kill_chain_phases_id.append(SES_KILL_CHAIN_MAPPINGS[kill_chain_phase]) 

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

        observable_str = "["
        for i in range(len(detection.tags.observable)):
            role_list = []
            for role in detection.tags.observable[i]["role"]:
                role_list.append(str(SES_OBSERVABLE_ROLE_MAPPING[role]))
            
            observable_str = observable_str + 'create_map("name", "' + detection.tags.observable[i]["name"] + '", "role_ids", [' + ",".join(role_list) + '], "type_id", ' + str(SES_OBSERVABLE_TYPE_MAPPING[detection.tags.observable[i]["type"]]) + ', "value", ' + detection.tags.observable[i]["name"] + ')'
            if not i == len(detection.tags.observable):
                observable_str = observable_str + ', '
        observable_str = observable_str + ']'

        detection.tags.observable_str = observable_str

        j2_env = Environment(
            loader=FileSystemLoader(os.path.join(os.path.dirname(__file__), 'templates')), 
            trim_blocks=True)
        template = j2_env.get_template('finding_report.j2')
        body = template.render(detection=detection)

        return body
