from curses.ascii import TAB
from dataclasses import dataclass, field
import json
import pathlib
import sys
import re

EXCLUDE_PATHS = ["/deprecated/", "/experimental/"]

TAB_CHARACTER='\t'

DATAMODEL_PATTERN = r"datamodel\s*=\s*\S*"
QUOTATIONS_PATTERN = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
KEY_VALUE_PATTERN = r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)+"

class DatamodelRoot:
    def __init__(self, paths:list[pathlib.Path]):
        self.datamodels = {}
        for p in paths:
            if p.is_file():
                self.add_datamodel_file(p)
            elif p.is_dir():
                self.add_datamodel_directory(p)
            else:
                raise(Exception(f"Path {p} is neither a directory nor a path"))

        print(f"Processed [{len(self.datamodels)}] datamodels")
    
    def add_datamodel_file(self, path:pathlib.Path)->None:
        dm = Datamodel(path)
        self.datamodels[dm.name] = dm

    def add_datamodel_directory(self, directory_path:pathlib.Path)->None:
        for filePath in directory_path.rglob("*.json"):
            self.add_datamodel_file(filePath)
    '''
    def pretty_print(self, indent_spaces:int = 3):
        for dm_name, dm_obj in self.datamodels.items():
            print(f"{dm_obj.name} - {dm_obj.path}")
            
            for object_name, object_item  in dm_obj.objects.items():
                print(' ' * (indent_spaces*1) + object_item.name)
                for field_name, field_object in object_item.fields.items():
                    print(' ' * (indent_spaces*2) + field_object.name)
    '''
    
    def resolve_fieldname(self, full_path:str)->list[str]:
        
        #First, try to resolve the full path. We must do this because the
        #fieldname could be something long, like Risk.All_Risk.annotations.mitre_attack.mitre_description or annotations.mitre_attack.mitre_description
        #Or, it could be something shorter like Risk.All_Risk.dest or All_Risk.dest or dest
        paths = self.resolve_field(full_path)
        if len(paths) > 0:
            return sorted(paths)
        segments = full_path.split('.')

        if len(segments) > 1:
            paths = self.resolve_submodel_field(segments[0], '.'.join(segments[1:]))
        if len(paths) > 0:
            return sorted(paths)

        if len(segments) > 2:
            paths=self.resolve_model_submodel_field(segments[0], segments[1], '.'.join(segments[2:]))
        
        return sorted(paths)

        '''
        segments = full_path.split('.')
        if len(segments) == 3:
            paths = self.resolve_model_submodel_field(segments[0], segments[1], segments[2])
                
        elif len(segments) == 2:
            paths = self.resolve_submodel_field(segments[0], segments[1])
        elif len(segments) == 1:
            paths = self.resolve_field(segments[0])
        else:
            raise(Exception(f"Could not resolve the reference to {full_path} in any datamodel"))

        #if len(paths) == 0:
        #    print(f"Failed to find [{full_path}]")
        return sorted(paths)
        '''
    
    def resolve_model_submodel_field(self, datamodelName:str, submodelName:str, fieldName:str)->list[str]:
        paths  = []
        if datamodelName in self.datamodels:
            dm = self.datamodels[datamodelName]
            if dm.resolve_submodel_and_field(submodelName, fieldName):
                paths.append(f"{datamodelName}.{submodelName}.{fieldName}")
        return paths

    def resolve_submodel_field(self, submodelName:str, fieldName:str)->list[str]:
        paths = []
        for dm_name in self.datamodels:
            paths += self.resolve_model_submodel_field(dm_name, submodelName, fieldName)
        return paths
        
    def resolve_field(self, fieldName:str)->list[str]:
        paths = []
        for dmName, dmObject in self.datamodels.items():
            for objectName, objectObject in dmObject.objects.items():
                paths += self.resolve_model_submodel_field(dmName, objectName, fieldName)
        return paths

    def validate_model_and_submodel(self, modelAndSubmodel:str)->bool:
        parts = modelAndSubmodel.split('.')
        if len(parts) == 1:
            model = parts[0]
            if model in self.datamodels:
                return True
        elif len(parts) == 2:
            model = parts[0]
            submodel = parts[1]
            if model in self.datamodels:
                if submodel in self.datamodels[model].objects:
                    return True
                else:
                    raise(Exception(f"Submodel {submodel} not found in the {model} Datamodel: {self.datamodels[model].objects.keys()}"))
            else:
                raise(Exception(f"Model {model} not found in the valid datamodels: {self.datamodels.keys()}"))
            
        else:
            raise(Exception(f"The datamodel {modelAndSubmodel} was not in the expected format of 'model[.submodel]'"))
        

        raise(Exception(f"The datamodel {modelAndSubmodel} was not found in the defined datamodels and submodels"))

    def printDatamodels(self):
        for dmName, dm in self.datamodels.items():
            dm.printDatamodel()


class Datamodel:
    def __init__(self, path:pathlib.Path):
        self.path = path
        with open(path, 'r') as datamodel_file:
            model = json.load(datamodel_file)
        
        #print(f"Parsing Datamodel [{model['modelName']}]...")
        self.name = model['modelName']
        self.objects = {}
        if 'objects' in model:
            self.parse_objects(model['objects'])
        else:
            raise(Exception(f"Datamodel file [{self.path}] did not contain 'objects'"))

        

    def parse_objects(self, json_objects: list,depth:int=0):
        for json_object in json_objects:
            datamodel_object = DatamodelObject(json_object)
            self.objects[datamodel_object.name] = datamodel_object
    
    def resolve_submodel_and_field(self, submodelName:str, fieldName:str)->bool:
        if submodelName in self.objects:
            obj = self.objects[submodelName]
            return obj.resolve_field_name(fieldName)
        else:
            return False

    def printDatamodel(self):
        print(self.name)
        for oName, o in self.objects.items():
            o.printObject()

        
            

class DatamodelObject:
    def __init__(self, datamodel_object: dict):
        
        self.name = datamodel_object['objectName']
        self.fields = {}
        if 'fields' in datamodel_object:
            self.parse_fields(datamodel_object['fields'])
        #else:
        #    print(f"'fields' not found in datamodel object {self.name}")
        if 'calculations' in datamodel_object:            
            self.parse_calculations(datamodel_object['calculations'])
        #else:
        #    print(f"'calculations' not found in datamodel object {self.name}")
    
    def parse_fields(self, fields_object: list):
        for field in fields_object:
            field = DatamodelField(field)
            self.fields[field.name] = field 
    def parse_calculations(self, calculations_object: list):
        for calculation in calculations_object:
            self.parse_fields(calculation['outputFields'])
    def resolve_field_name(self, fieldName:str)->bool:
        if fieldName in self.fields:
            return True
        else:
            return False
    def printObject(self):
        print(f"\t{self.name}")
        for fieldName, field in self.fields.items():
            field.printField()

    

        

class DatamodelField:
    def __init__(self, datamodel_field: dict):
        self.name = datamodel_field['fieldName']
#class DatamodelCalculation:
#    def __init__(self, datamodel_calculation: dict):
#        self.name = datamodel_calculation[]
#        pass
    def printField(self):
        print(f"\t\t{self.name}")


class SearchFieldValidator:
    def __init__(self, path:pathlib.Path, yaml_search:str, yaml_datamodels: set[str], yaml_required_fields: set[str], datamodelRoot: DatamodelRoot, errorOnMissingSubmodel:bool=True):
        self.path = path
        self.yaml_search = yaml_search
        if 'tstats' not in search:
            self.valid_search = True
            return
        self.yaml_datamodels = yaml_datamodels
        self.yaml_required_fields = yaml_required_fields
        self.errorOnMissingSubmodel = errorOnMissingSubmodel
        self.datamodelRoot = datamodelRoot
        self.datamodels_declared_in_search = self.extractDatamodelsFromSearch()
        self.fields_from_search = self.extractFieldsFromSearch()
        
        self.datamodels_used_in_search = set()
        

        #print("Datamodels:")
        #print(self.search_datamodels_from_search)
        #print("Fields:")
        #print(self.fields_from_search)
        self.updated = False
        self.valid_search = self.validate_search()
        if self.valid_search is False:
            print(f"{self.path} - Failed Validation")
        if self.updated:
            print("yes, it was updated")

    def extractDatamodelsFromSearch(self, interactive:bool=False)->set[str]:
        #First search includes the beginning datamodel= (including whitespace)
        all_data_models =  re.findall(DATAMODEL_PATTERN, self.yaml_search)

        #Trim off the beginning datamodel= and leading and trailing
        cleaned_models = set()
        for datamodel in all_data_models:
            try:
                equals_and_datamodel = datamodel.split('=')
                
                if len(equals_and_datamodel) != 2:
                    #print("\n")
                    #print(self.yaml_search)
                    #print(datamodel)
                    #print(equals_and_datamodel)
                    #sys.exit(1)
                    raise(Exception(f"Expected format 'datamodel=Model.submodel' but received {datamodel}, parsed as {equals_and_datamodel}"))

                cleaned_datamodel = equals_and_datamodel[1].strip().rstrip()
                if '.' not in cleaned_datamodel and self.errorOnMissingSubmodel:
                    #raise(Exception(f"No submodel contained in datamodel [{datamodel}]"))
                    pass
                if not self.datamodelRoot.validate_model_and_submodel(cleaned_datamodel):
                    raise(Exception(f"The datamodel and submodel {cleaned_datamodel} do not exist in the parsed datamodels"))
                cleaned_models.add(cleaned_datamodel)

                
            except Exception as e:
                raise(Exception(f"Error trying to extract the Datamodel from datamodel [{datamodel}]: {str(e)}"))
        
        return cleaned_models

        
    def extractFieldsFromSearch(self)->list[str]:
        #First, remove the datamodel(s) from the search
        all_data_models = re.findall(DATAMODEL_PATTERN, self.yaml_search)
        search_without_datamodels = self.yaml_search
        for dms in all_data_models:
            search_without_datamodels = search_without_datamodels.replace(dms, "")
        
        #Remove all of the quoted text.  We do this because things like cmd.exe could be
        #interpreted as a field. In reality, we need to quote these in the raw files
        #so that they can be removed during this step
        search_without_quoted_text = re.sub(QUOTATIONS_PATTERN, "", search_without_datamodels)        
        all_possible_fields = re.findall(KEY_VALUE_PATTERN, search_without_quoted_text)
        #Sometimes things are recognized as fields, but they are actually just numeric values, like 0.5 for example
        #We want to filter those out
        def is_number(test_str:str)->bool:
            try:
                float(test_str)
            except:
                return False
            return True

        return [f for f in all_possible_fields if is_number(f) is False]

        
    def validate_search(self, interactive:bool = False, verbose:bool=True)->bool:
        validation_success = True
        duplicate_fields_found = False
        

        #We start with no fields, so of course we found them
        found_all_fields_in_yaml_datamodels = True
        found_all_fields_in_search_declared_datamodels = True

        for fieldname in self.fields_from_search:
            found_fields = self.datamodelRoot.resolve_fieldname(fieldname)
            
            if len(found_fields) == 0:
                if verbose:
                    print(f"Failed to validate field name [{fieldname}] in {self.path} - field does not exist in any datamodels")
                    print(self.yaml_search)
                    input("Waiting...")
                validation_success = False
                found_all_fields_in_yaml_datamodels = False
                found_all_fields_in_search_declared_datamodels = False
            else:

                for field in found_fields:
                    #Add the . at the end to ensure it is the end of the datamodel's name
                    field_datamodel = field.split('.')[0]+'.'
                    
                    found = False
                    for datamodel in self.yaml_datamodels:                        
                        if datamodel.startswith(field_datamodel):
                            found|=True
                    found_all_fields_in_yaml_datamodels &= found


                    found=False
                    for datamodel in self.datamodels_declared_in_search:
                        #print(f"Checking for {field} in {datamodel}")
                        if datamodel.startswith(field_datamodel):            
                            found |= True
                    found_all_fields_in_search_declared_datamodels &= True

                    self.datamodels_used_in_search.add('.'.join(field.split('.')[0:2]))

          
        
        
        if self.datamodels_used_in_search != self.datamodels_declared_in_search != self.yaml_datamodels:
            print(f"Difference between declared datamodels and used datamodels in {self.path}")
            print(f"1) Parsed from YAML Field          : {self.yaml_datamodels} - {'FOUND' if found_all_fields_in_yaml_datamodels else 'NOT_FOUND'}")
            print(f"2) Declared in Search              : {self.datamodels_declared_in_search} - {'FOUND' if found_all_fields_in_search_declared_datamodels else 'NOT_FOUND'}")
            
            if duplicate_fields_found:
                print(f"FIELD FOUND IN MULTIPLE DATAMODELS : {self.datamodels_used_in_search}")
                dm_choices = [1,2]

            else:
                print(f"3) Extracted from Search           : {self.datamodels_used_in_search}")
                dm_choices = [1,2,3]

            print(f"4) Fields                          : {self.fields_from_search}")
            input("waiting...")
            print('\n')
            if interactive:

                while True:
                    choice = input(f"Which one do you want to keep {dm_choices}: ")
                    if choice == '1':
                        self.updated = False
                        break
                    elif choice == '2':
                        self.updated = True
                        break
                    elif choice == '3' and duplicate_fields_found:
                        print("Invalid choice - datamodel(s) could not be identified due to conflict(s).")
                    elif choice == '3':
                        self.updated = True
                        break
                    else:
                        print(f"Bad choice: {choice}, not one of {dm_choices}. Try again...")

            

                
            
        
        '''
        print(f"Was validation successful? {validation_success}")
        #print(self.fields_from_search)
        print(self.datamodels_declared_in_search)
        print(self.datamodels_used_in_search)
        if self.datamodels_declared_in_search != self.datamodels_used_in_search != self.yaml_datamodels:
            print("Difference between the datamodels declared in the search and the datamodels used in the search")
            print(f"FROM : {self.datamodels_declared_in_search}")
            print(f"USED : {self.datamodels_used_in_search}")
            print(f"YAML : {self.yaml_datamodels}")
        '''
        

            
        if validation_success is False:
            pass
            #input("Hit enter to continue")

        return validation_success

            
            

        return True





if __name__ == "__main__":
    import sys
    datamodel_argument = [sys.argv[1]]
    detection_argument = [sys.argv[2]]
    interactive = sys.argv[3]
    #input_paths = [pathlib.Path(input_path_argument) for input_path_argument in input_path_arguments]
    datamodel_paths = [pathlib.Path(input_path_argument) for input_path_argument in datamodel_argument]
    root = DatamodelRoot(datamodel_paths)
    
    root.printDatamodels()
    #print(root.resolve_fieldname("mitre_attack.mitre_tactic"))
    #print(root.resolve_fieldname("annotations.mitre_attack.mitre_tactic"))
    
    #print(root.resolve_fieldname("Risk.All_Risk.annotations.mitre_attack.mitre_description"))
    #print(root.resolve_fieldname("All_Risk.annotations.mitre_attack.mitre_description"))
    #print(root.resolve_fieldname("annotations.mitre_attack.mitre_description"))
    #print(root.resolve_fieldname("annotations.mitre_attack.mitre_description"))
    #print(root.resolve_fieldname("dest"))
    #sys.exit(0)

    import yaml
    detection_paths = [pathlib.Path(detection_path_argument) for detection_path_argument in detection_argument]

    
    #glob all the yml files in that directory
    
    total_searches = 0
    errored_searches = 0
    valid_searches = 0
    failed_searches = 0
    for p in detection_paths:
        for filePath in p.rglob("*.yml"):
            skip = False
            for EXCLUDE_PATH in EXCLUDE_PATHS:
                if EXCLUDE_PATH in str(filePath):
                    skip = True
                    break
            if skip is True:
                continue
            total_searches += 1
            with open(filePath, 'rb') as detection_data:
                try:
                    dat = yaml.safe_load(detection_data)
                    search = dat['search']
                    decalared_dms = set(dat['datamodel'])
                    declared_required_fields = dat['tags']['required_fields']
                    #print(filePath)
                    valid = SearchFieldValidator(filePath, search, decalared_dms, declared_required_fields, root)
                    if valid.valid_search == True:
                        valid_searches += 1
                    else:
                        failed_searches += 1

                except Exception as e:
                    print(f"Error testing [{filePath}]: {str(e)}")
                    errored_searches += 1
    
    print("Summary")
    print(f"Total   Searches: {total_searches: >4}")
    print(f"Passed  Searches: {valid_searches: >4}")
    print(f"Failed  Searches: {failed_searches: >4}")
    print(f"Errored Searches: {errored_searches: >4}")
    
    
    '''
    example_search = '| tstats `security_content_summariesonly` values(All_Changes.result_id) as\
  result_id count min(_time) as firstTime max(_time) as lastTime from datamodel=Change\
  where All_Changes.result_id=4720 OR All_Changes.result_id=4726 by _time span=4h\
  All_Changes.user All_Changes.dest | `security_content_ctime(lastTime)` | `security_content_ctime(firstTime)`\
  | `drop_dm_object_name("All_Changes")` | search result_id = 4720 result_id=4726\
  | transaction user connected=false maxspan=240m | table firstTime lastTime count\
  user dest result_id | `short_lived_windows_accounts_filter`'
    example_datamodels = {"Change"}
    example_required_fields = {"_time", "All_Changes.result_id", "All_Changes.user","All_Changes.dest"}
    example_path_string = "/tmp/scann/security_content/detections/endpoint/short_lived_windows_accounts.yml"
    examplePath = pathlib.Path(example_path_string)
    s = SearchFieldValidator(examplePath, example_search, example_datamodels, example_required_fields, root)
    '''
