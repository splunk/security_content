import os
import sys
import copy

from dataclasses import dataclass
from jinja2 import Environment, FileSystemLoader

from sigma.processing.conditions import LogsourceCondition
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.collection import SigmaCollection
from sigma.backends.splunk import SplunkBackend
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

from bin.contentctl_project.contentctl_infrastructure.builder.utils import Utils
from bin.contentctl_project.contentctl_core.domain.entities.enums.enums import SigmaConverterTarget
from bin.contentctl_project.contentctl_infrastructure.builder.yml_reader import YmlReader
from bin.contentctl_project.contentctl_core.domain.entities.detection import Detection
from bin.contentctl_project.contentctl_core.domain.entities.data_source import DataSource
from bin.contentctl_project.contentctl_infrastructure.builder.backend_splunk_ba import SplunkBABackend
from bin.contentctl_project.contentctl_core.application.factory.utils.utils import Utils
from bin.contentctl_project.contentctl_core.domain.constants.constants import *

@dataclass(frozen=True)
class SigmaConverterInputDto:
    data_model: SigmaConverterTarget
    detection_path: str
    detection_folder : str
    input_path: str
    log_source: str
    cim_to_ocsf: bool


@dataclass(frozen=True)
class SigmaConverterOutputDto:
    detections: list


class SigmaConverter():
    output_dto : SigmaConverterOutputDto

    def __init__(self, output_dto: SigmaConverterOutputDto) -> None:
        self.output_dto = output_dto


    def execute(self, input_dto: SigmaConverterInputDto) -> None:
        
        detection_files = []
        errors = []

        if input_dto.detection_path:
            detection_files.append(input_dto.detection_path)
        elif input_dto.detection_folder:
            detection_files = Utils.get_all_yml_files_from_directory(input_dto.detection_folder)
        else:
            print("ERROR: --detection_path or --detection_folder needed.") 
            sys.exit(1)

        for detection_file in detection_files:
            #try:
                detection = self.read_detection(str(detection_file))
                print("Converting detection: " + detection.name)
                data_source = self.load_data_source(input_dto.input_path, detection.data_source[0])
                if not data_source:
                    print("ERROR: Didn't find data source with name: " + detection.data_source[0] + " for detection " + detection.name)
                    sys.exit(1)

                file_name = detection.name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()

                sigma_rule = self.get_sigma_rule(detection, data_source)


                if input_dto.data_model == SigmaConverterTarget.RAW:
                    if input_dto.log_source and input_dto.log_source != detection.data_source[0][0]:
                        try:
                            field_mapping = self.find_mapping(data_source.convert_to_log_source, 'data_source', input_dto.log_source)
                        except Exception as e:
                            print(e)
                            print("ERROR: Couldn't find data source mapping for log source " + input_dto.log_source + " for detection: " + detection.name)
                            sys.exit(1)
                        
                        logsource_condition = self.get_logsource_condition(data_source)
                        processing_item = self.get_field_transformation_processing_item(
                            field_mapping['mapping'],
                            logsource_condition
                        )
                        sigma_processing_pipeline = self.get_pipeline_from_processing_items([processing_item])
                        splunk_backend = SplunkBackend(processing_pipeline=sigma_processing_pipeline)
                        data_source = self.load_data_source(input_dto.input_path, input_dto.log_source) 
                    else:
                        splunk_backend = SplunkBackend()
                    
                    search = splunk_backend.convert(sigma_rule)[0]
                    search = self.add_source_macro(search, data_source.type)
                    search = self.add_stats_count(search, data_source.raw_fields)
                    search = self.add_timeformat_conversion(search)
                    search = self.add_filter_macro(search, file_name)

                    detection.file_path = file_name + '.yml'

                elif input_dto.data_model == SigmaConverterTarget.CIM:
                    logsource_condition = self.get_logsource_condition(data_source)
                    try:
                        field_mapping = self.find_mapping(data_source.field_mappings, 'data_model', 'cim')
                    except Exception as e:
                        print(e)
                        print("ERROR: Couldn't find data source mapping to cim for log source " + detection.data_source[0] + " and detection " + detection.name)
                        sys.exit(1)
                    sigma_transformation_processing_item = self.get_field_transformation_processing_item(
                        field_mapping['mapping'],
                        logsource_condition
                    )
                    sigma_state_fields_processing_item = self.get_state_fields_processing_item(
                        field_mapping['mapping'].values(),
                        logsource_condition
                    )
                    sigma_state_data_model_processing_item = self.get_state_data_model_processing_item(
                        field_mapping['data_set'],
                        logsource_condition
                    )
                    sigma_processing_pipeline = self.get_pipeline_from_processing_items([
                        sigma_transformation_processing_item,
                        sigma_state_fields_processing_item,
                        sigma_state_data_model_processing_item
                    ])
                    splunk_backend = SplunkBackend(processing_pipeline=sigma_processing_pipeline)
                    search = splunk_backend.convert(sigma_rule, "data_model")[0]
                    search = self.add_filter_macro(search, file_name)

                    detection.file_path = file_name + '.yml'

                elif input_dto.data_model == SigmaConverterTarget.OCSF:

                    if not data_source.name == "Windows Security 4688":
                        print("ERROR: Convert command for OCSF only supports data source Windows Security 4688 for now.")
                        sys.exit(1)

                    processing_items = list()
                    logsource_condition = self.get_logsource_condition(data_source)
                    if input_dto.log_source and input_dto.log_source != detection.data_source[0]:
                        try:
                            field_mapping = self.find_mapping(data_source.convert_to_log_source, 'data_source', input_dto.log_source)
                        except Exception as e:
                            print(e)
                            print("ERROR: Couldn't find data source mapping for log source " + input_dto.log_source + " and detection " + detection.name)
                            sys.exit(1)

                        processing_items.append(
                            self.get_field_transformation_processing_item(
                                field_mapping['mapping'],
                                logsource_condition
                            )
                        )
                        data_source = self.load_data_source(input_dto.input_path, input_dto.log_source) 

                    if input_dto.cim_to_ocsf:
                        field_mapping_dot = {
                            "data_model": "ocsf",
                            "mapping": {
                                "process_name": "process.file.name",
                                "parent_process_name": "actor.process.file.name",
                                "cmd_line": "process.cmd_line",
                                "process": "process.cmd_line",
                                "process_path": "process.file.path"
                            }
                        }

                        field_mapping = copy.deepcopy(field_mapping_dot)
                        for field in field_mapping["mapping"].keys():
                            field_mapping["mapping"][field] = field_mapping["mapping"][field].replace(".", "_")
                        
                    else:
                        field_mapping = self.find_mapping(data_source.field_mappings, 'data_model', 'ocsf')

                    self.add_required_fields(field_mapping, detection)
                    self.update_observables(detection)

                    processing_items.append(
                        self.get_field_transformation_processing_item(
                            field_mapping['mapping'],
                            logsource_condition
                        )
                    )
                    processing_items.append(
                        self.get_state_fields_processing_item(
                            field_mapping['mapping'].values(),
                            logsource_condition
                        )
                    )

                    sigma_processing_pipeline = self.get_pipeline_from_processing_items(processing_items)

                    if input_dto.cim_to_ocsf:
                        splunk_backend = SplunkBABackend(processing_pipeline=sigma_processing_pipeline, detection=detection, field_mapping=field_mapping_dot)
                    else:
                        splunk_backend = SplunkBABackend(processing_pipeline=sigma_processing_pipeline, detection=detection)
                    search = splunk_backend.convert(sigma_rule, "data_model")[0]

                    search = search + ' --finding_report--'
                    detection.file_path = 'ssa___' + file_name + '.yml'                    

                detection.search = search
                
                self.output_dto.detections.append(detection)

            # except Exception as e:
            #     print(e)
            #     errors.append("ERROR: Converting detection " + detection.name)

        print()
        for error in errors:
            print(error)
        
        print()

    def read_detection(self, detection_path : str) -> Detection:
        yml_dict = YmlReader.load_file(detection_path)
        yml_dict["tags"]["name"] = yml_dict["name"]
        detection = Detection.parse_obj(yml_dict)
        detection.source = os.path.split(os.path.dirname(detection_path))[-1]  
        return detection 


    def load_data_source(self, input_path: str, data_source_name: str) -> DataSource:
        data_sources = list()
        files = Utils.get_all_yml_files_from_directory(os.path.join(input_path, 'data_sources'))
        for file in files:
           data_sources.append(DataSource.parse_obj(YmlReader.load_file(str(file))))

        data_source = None

        for obj in data_sources:
            if obj.name == data_source_name:
                return obj

        return None


    def get_sigma_rule(self, detection: Detection, data_source: DataSource) -> SigmaCollection:
        return SigmaCollection.from_dicts([{
            "title": detection.name,
            "status": "experimental",
            "logsource": {
                "category": data_source.category,
                "product": data_source.product
            },
            "detection": detection.search
        }])


    def get_logsource_condition(self, data_source: DataSource) -> LogsourceCondition:
        return LogsourceCondition(
            category=data_source.category,
            product=data_source.product,
        )


    def get_field_transformation_processing_item(self, data_source_mapping: dict, logsource_condition: LogsourceCondition) -> ProcessingItem:
        return ProcessingItem(
            identifier="field_mapping_transformation",
            transformation=FieldMappingTransformation(data_source_mapping),
            rule_conditions=[
                logsource_condition
            ]
        )


    def get_state_fields_processing_item(self, fields: list, logsource_condition: LogsourceCondition) -> ProcessingItem:
        return ProcessingItem(
            identifier="fields",
            transformation=SetStateTransformation("fields", fields),
            rule_conditions=[
                logsource_condition
            ]
        ) 


    def get_state_data_model_processing_item(self, data_model: str, logsource_condition: LogsourceCondition) -> ProcessingItem:
        return ProcessingItem(
            identifier="data_model",
            transformation=SetStateTransformation("data_model_set", data_model),
            rule_conditions=[
                logsource_condition
            ]
        )


    def get_pipeline_from_processing_items(self, processing_items: list) -> ProcessingPipeline:
        return ProcessingPipeline(
            name="Splunk Sigma",
            priority=10,
            items=processing_items
        )

    def add_source_macro(self, search: str, data_source_type: str) -> str:
        return "`" + data_source_type + "` " + search

    def add_stats_count(self, search: str, fields: list) -> str:
        search = search + " | fillnull | stats count min(_time) as firstTime max(_time) as lastTime by " 
        for key in fields:
            search = search + key + " "
        return search

    def add_timeformat_conversion(self, search: str) -> str:
        return search + '| convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(firstTime) | convert timeformat="%Y-%m-%dT%H:%M:%S" ctime(lastTime) '

    def add_filter_macro(self, search: str, file_name: str) -> str:
        return search + '| `' + file_name + '_filter`'

    def find(self, name: str, path: str) -> str:
        for root, dirs, files in os.walk(path):
            if name in files:
                return os.path.join(root, name)
        return None

    def find_mapping(self, field_mappings: list, object: str, data_model: str) -> dict:
        for mapping in field_mappings:
            if mapping[object] == data_model:
                return mapping
        
        raise AttributeError("ERROR: Couldn't find mapping.")


    def add_required_fields(self, field_mapping: dict, detection: Detection) -> None:
        required_fields = list()
        for mapping in field_mapping["mapping"].keys():
            for selection in detection.search.keys():
                if selection != "condition":
                    for detection_field in detection.search[selection]:
                        if detection_field.startswith(mapping):
                            if not field_mapping["mapping"][mapping] in required_fields:
                                required_fields.append(field_mapping["mapping"][mapping])

        detection.tags.required_fields = required_fields


    def update_observables(self, detection : Detection) -> None:
        mapping_field_to_type = {
            "process_file_name": "File Name",
            "actor_process_file_name": "File Name",
            "process_cmd_line": "Other",
            "process_cmd_line": "Other",
            "process_file_path": "File"
        }

        observables = list()
        observables.append({"name": "inferred_caller_user_name", "type": "User Name"})
        observables.append({"name": "device_hostname", "type": "Hostname"})
        
        for field in detection.tags.required_fields:
            observables.append({
                "name": field,
                "type": mapping_field_to_type[field]
            })

        detection.tags.observable = observables