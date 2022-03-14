import sys

from pydantic import ValidationError

from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_core.domain.entities.security_content_object import SecurityContentObject
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.domain.entities.deployment import Deployment
from bin.contentctl_project.contentctl_core.domain.entities.macro import Macro
from bin.contentctl_project.contentctl_core.domain.entities.lookup import Lookup
from bin.contentctl_project.contentctl_core.domain.entities.playbook import Playbook
from bin.contentctl_project.contentctl_core.domain.entities.unit_test import UnitTest


class SecurityContentBasicBuilder(BasicBuilder):
    security_content_obj : SecurityContentObject


    def setObject(self, path: str, type: SecurityContentType) -> None:
        yml_dict = YmlReader.load_file(path)
        if type == SecurityContentType.deployments:
            if "alert_action" in yml_dict:
                alert_action_dict = yml_dict["alert_action"]
                for key in alert_action_dict.keys():
                    yml_dict[key] = yml_dict["alert_action"][key]
            try:
                self.security_content_obj = Deployment.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.macros:
            try:
                self.security_content_obj = Macro.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.lookups:
            try:
                self.security_content_obj = Lookup.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
        elif type == SecurityContentType.unit_tests:
            try:
                self.security_content_obj = UnitTest.parse_obj(yml_dict)
            except ValidationError as e:
                print('Validation Error for file ' + path)
                print(e)
                sys.exit(1)
    
    def reset(self) -> None:
        self.security_content_obj = None

    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj