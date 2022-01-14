import re
import sys

from pydantic import ValidationError

from contentctl.contentctl.application.builder.story_builder import StoryBuilder
from contentctl.contentctl.domain.entities.story import Story
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl_infrastructure.contentctl_infrastructure.builder.yml_reader import YmlReader


class SecurityContentStoryBuilder(StoryBuilder):
    story: Story

    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        try:
            self.story = Story.parse_obj(yml_dict)
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
        for detection in detections:
            for detection_analytic_story in detection.tags.analytic_story:
                if detection_analytic_story == self.story.name:
                    matched_detection_names.append(str('ESCU - ' + detection.name + ' - Rule'))

        self.story.detection_names = matched_detection_names

    def addBaselines(self, baselines: list) -> None:
        matched_baseline_names = []
        for baseline in baselines:
            for baseline_analytic_story in  baseline.tags.analytic_story:
                if baseline_analytic_story == self.story.name:
                    matched_baseline_names.append(str('ESCU - ' + baseline.name))

        self.story.baseline_names = matched_baseline_names

    def addInvestigations(self, investigations: list) -> None:
        matched_investigation_names = []
        for investigation in investigations:
            for investigation_analytic_story in  investigation.tags.analytic_story:
                if investigation_analytic_story == self.story.name:
                    matched_investigation_names.append(str('ESCU - ' + investigation.name + ' - Response Task'))

        self.story.investigation_names = matched_investigation_names

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
