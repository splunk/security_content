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
                

                if input_dto.data_model == SigmaConverterTarget.RAW:
                    if input_dto.log_source and input_dto.log_source != detection.data_source[0][0]:
                        try:
                            field_mapping = self.find_mapping(data_source.convert_to_log_source, 'data_source', input_dto.log_source)
                        except Exception as e:
                            print(e)
                            print("ERROR: Couldn't find data source mapping for log source " + input_dto.log_source + " for detection: " + detection.name)
                            sys.exit(1)

                        detection = self.convert_detection_fields(detection, field_mapping)

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
                    
                    sigma_rule = self.get_sigma_rule(detection, data_source)
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

                    detection = self.convert_detection_fields(detection, field_mapping)
                    sigma_rule = self.get_sigma_rule(detection, data_source)
                    
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

                    processing_items = list()
                    logsource_condition = self.get_logsource_condition(data_source)
                    if input_dto.log_source and input_dto.log_source != detection.data_source[0]:
                        data_source_new = self.load_data_source(input_dto.input_path, input_dto.log_source) 

                        try:
                            field_mapping = self.get_mapping_converted_data_source(
                                data_source,
                                "data_source",
                                input_dto.log_source,
                                data_source_new,
                                "data_model",
                                "ocsf"
                            )
                        except Exception as e:
                            print(e)
                            print("ERROR: Couldn't find data source mapping for log source " + input_dto.log_source + " and detection " + detection.name)
                            sys.exit(1)

                        cim_to_ocsf_mapping = self.get_cim_to_ocsf_mapping(data_source_new)

                    elif input_dto.cim_to_ocsf:
                        field_mapping = self.get_cim_to_ocsf_mapping(data_source)
                        cim_to_ocsf_mapping = field_mapping

                    else:
                        field_mapping = self.find_mapping(data_source.field_mappings, 'data_model', 'ocsf')
                        cim_to_ocsf_mapping = self.get_cim_to_ocsf_mapping(data_source)

                    field_mapping_underline = copy.deepcopy(field_mapping)
                    for field in field_mapping_underline["mapping"].keys():
                        field_mapping_underline["mapping"][field] = field_mapping_underline["mapping"][field].replace(".", "_")     

                    self.add_required_fields(field_mapping, detection)
                    self.add_mappings(cim_to_ocsf_mapping, detection)

                    self.update_observables(detection)

                    processing_items.append(
                        self.get_field_transformation_processing_item(
                            field_mapping_underline['mapping'],
                            logsource_condition
                        )
                    )
                    processing_items.append(
                        self.get_state_fields_processing_item(
                            field_mapping_underline['mapping'].values(),
                            logsource_condition
                        )
                    )

                    detection = self.convert_detection_fields(detection, field_mapping_underline)
                    sigma_rule = self.get_sigma_rule(detection, data_source)
                    sigma_processing_pipeline = self.get_pipeline_from_processing_items(processing_items)

                    splunk_backend = SplunkBABackend(processing_pipeline=sigma_processing_pipeline, detection=detection, field_mapping=field_mapping)
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


    def convert_detection_fields(self, detection: Detection, mappings: dict) -> Detection:
        for selection in detection.search.keys():
            if selection != "condition":
                new_selection = copy.deepcopy(detection.search[selection])
                for field in detection.search[selection].keys():
                    for mapping in mappings["mapping"].keys():
                        if mapping == field:
                            new_selection[mappings["mapping"][mapping]] =  detection.search[selection][field]
                            new_selection.pop(field)
                detection.search[selection] = new_selection

        return detection


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
        required_fields = ["process.user.name", "device.hostname"]
        for mapping in field_mapping["mapping"].keys():
            for selection in detection.search.keys():
                if selection != "condition":
                    for detection_field in detection.search[selection]:
                        if detection_field.startswith(mapping):
                            if not field_mapping["mapping"][mapping] in required_fields:
                                required_fields.append(field_mapping["mapping"][mapping])

        detection.tags.required_fields = required_fields


    def add_mappings(self, field_mapping: dict, detection: Detection) -> None:
        mappings = list()
        for mapping in field_mapping["mapping"].keys():
            mappings.append({
                "ocsf": field_mapping["mapping"][mapping],
                "cim": mapping
            })
        detection.tags.mappings = mappings

    def update_observables(self, detection : Detection) -> None:
        mapping_field_to_type = {
            "process.user.name": "User Name",
            "device.hostname": "Hostname",
            "process.file.name": "File Name",
            "actor.process.file.name": "File Name",
            "actor.process.file.path": "File Name",
            "actor.process.cmd_line": "Process",
            "process.cmd_line": "Other",
            "process.file.path": "File",
            "process.file.name": "File"
        }

        observables = list()
        
        for field in detection.tags.required_fields:
            observables.append({
                "name": field,
                "type": mapping_field_to_type[field]
            })

        detection.tags.observable = observables


    def get_cim_to_ocsf_mapping(self, data_source : DataSource) -> dict:
        cim_to_ocsf_mapping = dict()
        cim_to_ocsf_mapping["mapping"] = dict()
        cim_mapping = self.find_mapping(data_source.field_mappings, "data_model", "cim")
        ocsf_mapping = self.find_mapping(data_source.field_mappings, "data_model", "ocsf")

        for key in cim_mapping["mapping"].keys():
            cim_field = cim_mapping["mapping"][key].split(".")[1]
            cim_to_ocsf_mapping["mapping"][cim_field] = ocsf_mapping["mapping"][key]

        return cim_to_ocsf_mapping


    def get_mapping_converted_data_source(self, det_ds: DataSource, det_ds_obj: str, det_ds_dm: str,  con_ds: DataSource, con_ds_obj: str, con_ds_dm: str) -> dict:
        mapping = dict()
        mapping["mapping"] = dict()
        det_ds_mapping = self.find_mapping(det_ds.convert_to_log_source, det_ds_obj, det_ds_dm)
        con_ds_mapping = self.find_mapping(con_ds.field_mappings, con_ds_obj, con_ds_dm)

        for key in det_ds_mapping["mapping"].keys():
            mapped_field = con_ds_mapping["mapping"][det_ds_mapping["mapping"][key]]
            mapping["mapping"][key] = mapped_field

        return mapping