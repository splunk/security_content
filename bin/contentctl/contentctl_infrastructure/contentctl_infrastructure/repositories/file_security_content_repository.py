
import json

from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl.contentctl.application.repositories.security_content import SecurityContentRepository
from contentctl_infrastructure.contentctl_infrastructure.repositories.yml_reader import YmlReader
from contentctl.contentctl.domain.entities.detection import Detection


class FileSecurityContentRepository(SecurityContentRepository):

    def get(self, path: str) -> SecurityContentObject:
        yml_dict = YmlReader.load_file(path)
        detection = Detection.parse_obj(yml_dict)
        return detection

    def convert(self, security_content_obj: SecurityContentObject) -> None:
        pass
