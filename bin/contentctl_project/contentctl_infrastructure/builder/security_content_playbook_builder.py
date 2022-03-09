
import sys

from pydantic import ValidationError

from bin.contentctl_project.contentctl_core.application.builder.playbook_builder import PlaybookBuilder
from bin.contentctl_project.contentctl_core.domain.entities.playbook import Playbook
from contentctl_infrastructure.builder.yml_reader import YmlReader


class SecurityContentPlaybookBuilder(PlaybookBuilder):
    playbook: Playbook


    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        try:
            self.playbook = Playbook.parse_obj(yml_dict)
        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)


    def addDetections(self, detections : list) -> None:
        if detections:
            if self.playbook.tags.detections:
                self.playbook.tags.detection_objects = []
                for detection in detections:
                    if detection.name in self.playbook.tags.detections:
                        self.playbook.tags.detection_objects.append(detection)


    def reset(self) -> None:
        self.playbook = None


    def getObject(self) -> Playbook:
        return self.playbook