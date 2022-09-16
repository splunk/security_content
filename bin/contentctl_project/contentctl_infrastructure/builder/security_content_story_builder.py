import re
import sys
import json
import pathlib
import os

from pydantic import ValidationError
from typing import Union
from bin.contentctl_project.contentctl_core.application.builder.story_builder import StoryBuilder
from bin.contentctl_project.contentctl_core.domain.entities.story import Story
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader


class SecurityContentStoryBuilder(StoryBuilder):
    story: Story
    check_references: bool

    def __init__(self, output_path:Union[str,None]=None, check_references: bool = False):
        self.check_references = check_references
        self.app_name = self.get_app_name_from_manifest(output_path)

    def get_app_name_from_manifest(self, output_path:Union[str,None])->str:
        if output_path is None:
            return "ESCU"
        
        try:
            manifest_path = pathlib.Path(os.path.join(output_path, "app.manifest"))
        except Exception as e:
            raise(Exception(f"Failed to convert string {output_path} to path: {str(e)}"))
        try:
            with open(manifest_path, "r") as manifestFile:
                manifest_obj = json.load(manifestFile)
        except Exception as e:
            raise(Exception(f"Failed to open manifest at path {manifest_path}: {str(e)}"))
        
        try:
            app_name_from_manifest = manifest_obj['info']['id']['name']
            #Minor fix to shorten the name of ESCU detections and match with everything else
            if app_name_from_manifest == "DA-ESS-ContentUpdate":
                app_name_from_manifest = "ESCU"
            return app_name_from_manifest
        except Exception as e:
            raise(Exception(f"Manifest file {manifest_path} missing nested object ['info']['id']['name']: {str(e)}"))
        
    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        yml_dict["tags"]["name"] = yml_dict["name"]
        yml_dict["check_references"] = self.check_references
        try:
            self.story = Story.parse_obj(yml_dict)
            del(yml_dict["check_references"])
        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)

    def reset(self) -> None:
        self.story = None

    def getObject(self) -> Story:
        return self.story

    def addDetections(self, detections: list) -> None:
        matched_detection_names = []
        matched_detections = []
        mitre_attack_enrichments = []
        mitre_attack_tactics = set()
        datamodels = set()
        kill_chain_phases = set()

        for detection in detections:
            if detection:
                for detection_analytic_story in detection.tags.analytic_story:
                    if detection_analytic_story == self.story.name:
                        matched_detection_names.append(str(f'{self.app_name} - ' + detection.name + ' - Rule'))
                        # SSE-638: detections object should at least contain the name attribute.
                        # We also need a minimal set of the following attributes to satisfy docgen (doc_stories.j2):
                        # name, source, type, tags.mitre_attack_enrichments.mitre_attack_technique
                        mitre_attack_enrichments_list = []
                        if (detection.tags.mitre_attack_enrichments):
                            for attack in detection.tags.mitre_attack_enrichments:
                                mitre_attack_enrichments_list.append({"mitre_attack_technique": attack.mitre_attack_technique})
                        tags_obj = {"mitre_attack_enrichments": mitre_attack_enrichments_list}
                        matched_detections.append({
                            "name": detection.name,
                            "source": detection.source,
                            "type": detection.type,
                            "tags": tags_obj
                        })
                        datamodels.update(detection.datamodel)
                        if detection.tags.kill_chain_phases:
                            kill_chain_phases.update(detection.tags.kill_chain_phases)

                        if detection.tags.mitre_attack_enrichments:
                            for attack_enrichment in detection.tags.mitre_attack_enrichments:
                                mitre_attack_tactics.update(attack_enrichment.mitre_attack_tactics)
                                if attack_enrichment.mitre_attack_id not in [attack.mitre_attack_id for attack in mitre_attack_enrichments]:
                                    mitre_attack_enrichments.append(attack_enrichment)

        self.story.detection_names = matched_detection_names
        self.story.detections = matched_detections
        self.story.tags.datamodels = sorted(list(datamodels))
        self.story.tags.kill_chain_phases = sorted(list(kill_chain_phases))
        self.story.tags.mitre_attack_enrichments = mitre_attack_enrichments
        self.story.tags.mitre_attack_tactics = sorted(list(mitre_attack_tactics))


    def addBaselines(self, baselines: list) -> None:
        matched_baseline_names = []
        for baseline in baselines:
            for baseline_analytic_story in  baseline.tags.analytic_story:
                if baseline_analytic_story == self.story.name:
                    matched_baseline_names.append(str(f'{self.app_name} - ' + baseline.name))

        self.story.baseline_names = matched_baseline_names

    def addInvestigations(self, investigations: list) -> None:
        matched_investigation_names = []
        matched_investigations = []
        for investigation in investigations:
            for investigation_analytic_story in  investigation.tags.analytic_story:
                if investigation_analytic_story == self.story.name:
                    matched_investigation_names.append(str(f'{self.app_name} - ' + investigation.name + ' - Response Task'))
                    matched_investigations.append(investigation)

        self.story.investigation_names = matched_investigation_names
        self.story.investigations = matched_investigations

    def addAuthorCompanyName(self) -> None:
        match_author = re.search(r'^([^,]+)', self.story.author)
        if match_author is None:
            self.story.author_name = 'no'
        else:
            self.story.author_name = match_author.group(1)

        match_company = re.search(r',\s?(.*)$', self.story.author)
        if match_company is None:
            self.story.author_company = 'no'
        else:
            self.story.author_company = match_company.group(1)
