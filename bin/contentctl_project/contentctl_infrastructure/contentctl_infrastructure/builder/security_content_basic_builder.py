import sys

from pydantic import ValidationError

from contentctl.contentctl.application.builder.basic_builder import BasicBuilder
from contentctl.contentctl.domain.entities.security_content_object import SecurityContentObject
from contentctl_infrastructure.contentctl_infrastructure.builder.yml_reader import YmlReader
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType
from contentctl.contentctl.domain.entities.deployment import Deployment
from contentctl.contentctl.domain.entities.macro import Macro
from contentctl.contentctl.domain.entities.lookup import Lookup
from contentctl.contentctl.domain.entities.playbook import Playbook
from contentctl.contentctl.domain.entities.baseline import Baseline
from contentctl.contentctl.domain.entities.investigation import Investigation


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
        elif type == SecurityContentType.playbooks:
            try:
                self.security_content_obj = Playbook.parse_obj(yml_dict)
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
    
    def reset(self) -> None:
        self.security_content_obj = None

    def getObject(self) -> SecurityContentObject:
        return self.security_content_obj