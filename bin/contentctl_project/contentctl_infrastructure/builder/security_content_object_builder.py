


from bin.contentctl_project.contentctl_core.application.builder.basic_builder import BasicBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType


class SecurityContentObjectBuilder(BasicBuilder):
    object: dict
    
    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        yml_dict['file_path'] = path
        self.object = yml_dict

    def reset(self) -> None:
        self.object = None

    def getObject(self) -> dict:
        return self.object