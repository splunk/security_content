import logging
import json

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.application.repositories.security_content import SecurityContentRepository
from contentctl_infrastructure.contentctl_infrastructure.repositories.yml_reader import YmlReader
from contentctl.contentctl.domain.entities.detection import Detection
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType


class FileSecurityContentRepository(SecurityContentRepository):

    def get(self, path: str, type: SecurityContentType) -> SecurityContentObject:
        yml_dict = YmlReader.load_file(path)
        if type == SecurityContentType.detections:
            yml_dict["tags"]["name"] = yml_dict["name"]
            detection = Detection.parse_obj(yml_dict)
            logging.info("Read and parse object: " + detection.name)
            return detection

    def convert(self, security_content_obj: SecurityContentObject) -> None:
        pass
