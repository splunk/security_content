import re

from contentctl.contentctl.application.builder.investigation_builder import InvestigationBuilder
from contentctl.contentctl.domain.entities.investigation import Investigation
from contentctl_infrastructure.contentctl_infrastructure.builder.yml_reader import YmlReader
from contentctl.contentctl.domain.entities.enums.enums import SecurityContentType


class SecurityContentInvestigationBuilder(InvestigationBuilder):
    investigation: Investigation


    def setObject(self, path: str, type: SecurityContentType) -> None:
        yml_dict = YmlReader.load_file(path)
        self.investigation = Investigation.parse_obj(yml_dict)


    def reset(self) -> None:
        self.investigation = None


    def getObject(self) -> Investigation:
        return self.investigation


    def addInputs(self) -> None:
        pattern = r"\$([^\s.]*)\$"
        inputs = []

        for input in re.findall(pattern, self.investigation.search):
            inputs.append(input)

        self.investigation.inputs = inputs

    
    def addLowercaseName(self) -> None:
        self.investigation.lowercase_name = self.investigation.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower().replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()