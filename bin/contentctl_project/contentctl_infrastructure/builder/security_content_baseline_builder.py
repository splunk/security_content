import sys

from pydantic import ValidationError

from bin.contentctl_project.contentctl_core.application.builder.baseline_builder import BaselineBuilder
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_core.domain.entities.baseline import Baseline
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentType
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SecurityContentProduct


class SecurityContentBaselineBuilder(BaselineBuilder):
    baseline : Baseline
    check_references: bool

    def __init__(self, check_references: bool = False):
        self.check_references = check_references

    def setObject(self, path: str) -> None:
        yml_dict = YmlReader.load_file(path)
        yml_dict["tags"]["name"] = yml_dict["name"]

        yml_dict["check_references"] = self.check_references
        try:
            self.baseline = Baseline.parse_obj(yml_dict)
            del(yml_dict["check_references"])
        except ValidationError as e:
            print('Validation Error for file ' + path)
            print(e)
            sys.exit(1)

    def addDeployment(self, deployments: list) -> None:
        matched_deployments = []

        for d in deployments:
            d_tags = dict(d.tags)
            baseline_dict = self.baseline.dict()
            baseline_tags_dict = self.baseline.tags.dict()
            for d_tag in d_tags.keys():
                for attr in baseline_dict.keys():
                    if attr == d_tag:
                        if isinstance(baseline_dict[attr], str):
                            if baseline_dict[attr] == d_tags[d_tag]:
                                matched_deployments.append(d)
                        elif isinstance(baseline_dict[attr], list):
                            if d_tags[d_tag] in baseline_dict[attr]:
                                matched_deployments.append(d)

                for attr in baseline_tags_dict.keys():
                    if attr == d_tag:
                        if isinstance(baseline_tags_dict[attr], str):
                            if baseline_tags_dict[attr] == d_tags[d_tag]:
                                matched_deployments.append(d)
                        elif isinstance(baseline_tags_dict[attr], list):
                            if d_tags[d_tag] in baseline_tags_dict[attr]:
                                matched_deployments.append(d)

        if len(matched_deployments) == 0:
            raise ValueError('No deployment found for baseline: ' + self.baseline.name)

        print(matched_deployments[-1])

        self.baseline.deployment = matched_deployments[-1]


    def reset(self) -> None:
        self.baseline = None


    def getObject(self) -> Baseline:
        return self.baseline