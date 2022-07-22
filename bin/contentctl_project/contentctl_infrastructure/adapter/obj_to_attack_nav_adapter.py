import os


from bin.contentctl_project.contentctl_core.application.adapter.adapter import Adapter
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.adapter.attack_nav_writer import AttackNavWriter


class ObjToAttackNavAdapter(Adapter):

    def writeObjects(self, objects: list, output_path: str, type: SecurityContentType = None) -> None:
        techniques = dict()
        for detection in objects:
            if detection.tags.mitre_attack_enrichments:
                for mitre_attack_enrichment in detection.tags.mitre_attack_enrichments:
                    if not mitre_attack_enrichment.mitre_attack_id in techniques:
                        techniques[mitre_attack_enrichment.mitre_attack_id] = {
                                'score': 1,
                                'file_paths': ['https://github.com/splunk/security_content/blob/develop/detections/' + detection.source + '/' + self.convertNameToFileName(detection.name)]
                            }
                    else:
                        techniques[mitre_attack_enrichment.mitre_attack_id]['score'] = techniques[mitre_attack_enrichment.mitre_attack_id]['score'] + 1
                        techniques[mitre_attack_enrichment.mitre_attack_id]['file_paths'].append('https://github.com/splunk/security_content/blob/develop/detections/' + detection.source + '/' + self.convertNameToFileName(detection.name))

        AttackNavWriter.writeAttackNavFile(techniques, os.path.join(output_path, 'coverage.json'))


    def convertNameToFileName(self, name: str):
        file_name = name \
            .replace(' ', '_') \
            .replace('-','_') \
            .replace('.','_') \
            .replace('/','_') \
            .lower()
        file_name = file_name + '.yml'
        return file_name
