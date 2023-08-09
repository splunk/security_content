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

        detection.tags.kill_chain_phases_id = dict()
        for kill_chain_phase in detection.tags.kill_chain_phases:
            detection.tags.kill_chain_phases_id[kill_chain_phase] = SES_KILL_CHAIN_MAPPINGS[kill_chain_phase]

        kill_chain_phase_str = "["
        i = 0
        for kill_chain_phase in detection.tags.kill_chain_phases_id.keys():
            kill_chain_phase_str = kill_chain_phase_str + '{"phase": "' + kill_chain_phase + '", "phase_id": ' + str(detection.tags.kill_chain_phases_id[kill_chain_phase]) + "}"
            if not i == (len(detection.tags.kill_chain_phases_id.keys()) - 1):
                kill_chain_phase_str = kill_chain_phase_str + ', '
                i = i + 1
        kill_chain_phase_str = kill_chain_phase_str + ']'
        detection.tags.kill_chain_phases_str = kill_chain_phase_str

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

        evidence_str = "{"
        for i in range(len(detection.tags.observable)):            
            evidence_str = evidence_str + '"' + detection.tags.observable[i]["name"] + '": ' + detection.tags.observable[i]["name"].replace(".", "_")
            if not i == (len(detection.tags.observable) - 1):
                evidence_str = evidence_str + ', '
        evidence_str = evidence_str + '}'        

        detection.tags.evidence_str = evidence_str

        analytics_story_str = "["
        for i in range(len(detection.tags.analytic_story)):
            analytics_story_str = analytics_story_str + '"' + detection.tags.analytic_story[i] + '"'
            if not i == (len(detection.tags.analytic_story) - 1):
                analytics_story_str = analytics_story_str + ', '
        analytics_story_str = analytics_story_str + ']'
        detection.tags.analytics_story_str = analytics_story_str

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
