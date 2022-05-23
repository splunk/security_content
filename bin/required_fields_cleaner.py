import collections
import yaml
import sys
import re
import json
import pprint
import argparse
import pathlib

#find datamodel=SOMETHING, allowing for whitespace on either side of =
DATAMODEL_PATTERN = r"datamodel\s*=?\s*\S*"

QUOTATIONS_PATTERN = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
KEY_VALUE_PATTERN = r"[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+"

SMALL_INDENT = '  -'

def dictPrint(d:dict):

    printer = pprint.PrettyPrinter(indent=3)
    printer.pprint(d)


def parse_datamodel(datamodel_name, object)->dict:
    submodules = {}
    if "objects" in object:
        raise(Exception(("nested objects!")))

    #print(object.keys())

    #print(object['calculations'])
    #input("W")
    allFields = []
    if 'fields' in object:
        allFields += object['fields']

    if 'calculations' in object:
        for calc_dict in object['calculations']:
            if 'outputFields' in calc_dict:
                allFields += calc_dict['outputFields']


    for field in allFields:

        fieldName = field['fieldName']
        if fieldName in submodules:
            raise(Exception(f"Duplicate Field {field} in {datamodel_name}"))

        submodel_fieldname = f"{object['objectName']}.{fieldName}"
        model_submodel_fieldname =  f"{datamodel_name}.{submodel_fieldname}"
        submodules[fieldName] = {"field_name": fieldName, "submodel.fieldname": submodel_fieldname, "datamodel.submodel.field_name": model_submodel_fieldname}


    return submodules

def load_datamodels_from_directory(datamodels_directory:pathlib.PosixPath)->dict:
    print("Loading datamodel templates...", end='', flush=True)

    all_models = {}
    datamodel_filenames = list(datamodels_directory.glob("*.json"))
    for datamodel_filename in datamodel_filenames:
        #Load the YAML File
        with open(datamodel_filename, "r") as model_stream:
            json_datamodel = json.load(model_stream)

        model_name = json_datamodel['modelName']
        model_fields = {}

        #Load all the submodels from the YAML file
        for submodel in json_datamodel['objects']:
            model_fields[submodel['objectName']] = parse_datamodel(model_name, submodel)


        all_models[model_name] = model_fields
    print(f"[{len(datamodel_filenames):4d}] datamodel templates loaded")

    return all_models


def get_datamodels(search:str, filename:str)->dict:
    #print(search)
    matches = re.findall(DATAMODEL_PATTERN, search)

    #get the models and strip out the whitespace

    #If we want different dot-separated versions

    models_and_submodels = [model.replace(" ","=").split("=")[1].strip() for model in matches]


    results = {}
    for model_and_submodel in models_and_submodels:
        if model_and_submodel.count(".") != 1:
            print(f"datamodel {model_and_submodel} is not in model.submodel format in {filename}")
        else:
            model, submodel = model_and_submodel.split(".")
            if model in results:
                results[model].append(submodel)
            else:
                results[model]=[submodel]
    #If we only care about the top level
    #models_only = [model.split(".")[0].strip() for model in models_and_submodels]

    return results

def remove_datamodel_submodel_from_fields(defined_datamodels:dict ,fields:set[str])->set[str]:
    
    trimmed_fields = set()
    for field in fields:
        parts = field.split(".")
        if len(parts) == 2:
            if (parts[0] not in defined_datamodels) or (parts[1] not in defined_datamodels[parts[0]]):
                trimmed_fields.add(field)
    return trimmed_fields

def get_datamodel_fields(defined_datamodels:dict, search:str)->set[str]:
    quoted_text_removed = re.sub(QUOTATIONS_PATTERN, "", search)
    all_fields =  set(re.findall(KEY_VALUE_PATTERN, quoted_text_removed))
    return remove_datamodel_submodel_from_fields(defined_datamodels, all_fields)


def check_for_presence_of_fields(filename:str, container:dict, field_names:list[str])->bool:
    missing_fields = []
    for field_name in field_names:
        if field_name not in container:
            missing_field = True
            missing_fields.append(field_name)
    
    if len(missing_fields) > 0:
        #One of more fields that we were required to find were not found
        print(f"Detection file {filename} is missing the following keys: [{sorted(missing_fields)}]")
        return False

    return True
    

def verify_dataset_field(filename:str, detection_file_data:dict)->tuple[bool,bool,dict]:
    #Always validate that the same dataset is linked in the detection as in the test file

    #Update the filename to refer to the test instead of the detection
    
    test_filename = filename.replace(".yml", ".test.yml",1).replace("/detections/","/tests/",1)

    test_file_data_files = set()

    try:
        with open(test_filename, "r") as test_stream:
            test_datamodel = yaml.safe_load(test_stream)
    except Exception as e:
        print(f"Error while parsing {test_filename}: {str(e)}")
        return (False,False,detection_file_data)

    #Get all of the links to test datasets in the test file
    if 'tests' in test_datamodel:
        for test in test_datamodel['tests']:
            if 'attack_data' in test:
                for data_file in test['attack_data']:
                    if 'data' in data_file:
                        test_file_data_files.add(data_file['data'])
                    else:
                        print(f"'data' field not found in attack_data for {test_filename}: {dictPrint(data_file)}")
                        return (False, False,detection_file_data)
            else:
                print(f"'attack_data' not found in the test file {test_filename}")
                return (False, False,detection_file_data)
    else:
        print(f"'tests' field not found in attack_data for {test_filename}")
        return(False, False,detection_file_data)

    #Get all of the datasets that are referenced in the detection YML file
    if 'dataset' in detection_file_data['tags']:
        detection_file_data_files = set(detection_file_data['tags']['dataset'])
    else:
        detection_file_data_files = set()
    
    #Check to see if the test and detection ymls have the same datasets

    diff = test_file_data_files.symmetric_difference(detection_file_data_files)
    if len(diff) > 0:
        print(f"{len(diff)} Error(s) for {filename:}")
        for data_file in (test_file_data_files - detection_file_data_files):
            print(f"\tTest file references file NOT detection file:\n\t{SMALL_INDENT} {data_file}")
        for data_file in (detection_file_data_files - test_file_data_files):
            print(f"\tDetection file references file NOT included in the test file:\n\t{SMALL_INDENT} {data_file}")
        print("")
        return (False,False,{})
    

    #Success, no updates need to be made!
    return (True, False, detection_file_data)

    


def validate_datamodels(filename:str, search_datamodels:dict, defined_datamodels:dict)->tuple[bool,dict]:
    errors = []
    submodels_with_fields = {}

    for search_datamodel in search_datamodels:
        if search_datamodel not in defined_datamodels:
            errors.append(f"Failed to find the datamodel {search_datamodel} in predefined datamodels {defined_datamodels.keys()}")
            continue
        for submodel in search_datamodels[search_datamodel]:
            if submodel not in defined_datamodels[search_datamodel]:
                errors.append(f"Failed to find {'.'.join([search_datamodel,submodel])} in {search_datamodel}: {defined_datamodels[search_datamodel].keys()} ")
            elif submodel not in submodels_with_fields:
                submodels_with_fields[submodel] = defined_datamodels[search_datamodel][submodel]

                
    if len(errors) == 0:
        return (True, submodels_with_fields)
    else:
        #There was at least one error, print it out
        print(f"Error(s) validating the search datamodel for {filename}:")
        for error in errors:
            print(f"{SMALL_INDENT} {error}")
        return (False, {})



def validate_fields(filename:str, submodels_with_fields:dict, search_submodel_fields:set)->bool:
    errors = []

    
    
    for field in search_submodel_fields:
        tokens = field.split(".")
        if len(tokens) <= 1:
            errors.append(f"Failed to find a submodel and a model for {field}") 
        elif len(tokens) == 2:
            submodel, field = tokens
            try:
                if field not in submodels_with_fields[submodel]:
                    errors.append(f"[{submodel}] does not contain field [{field}]")
            except Exception as e:
                errors.append(f"Problem resolving [{submodel}.{field}]: [{str(e)}] is not a valid submodel")

        else:
            errors.append(f"Found more than just a submodel and field for {field}")


    
    if len(errors) == 0:
        return True
    else:
        #There was at least one error, print it out
        print(f"Error(s) validating the datamodel fields in the search for {filename}:")
        for error in errors:
            print(f"{SMALL_INDENT} {error}")
        return False


def update_datamodels(filename:str, defined_datamodels:dict, detection_file_data: dict)->tuple[bool,bool,dict]:
    if not check_for_presence_of_fields(filename, detection_file_data, ["search","tags"]):
        return (False,False,{})

    if not check_for_presence_of_fields(filename, detection_file_data["tags"], ["required_fields"]):
        return (False,False,{})
    

    if not check_for_presence_of_fields(filename, detection_file_data, ["datamodel"]):
        return (False,False,{})

    
    #Pull the datamodel(s) from the search
    search_datamodels = get_datamodels(detection_file_data['search'],filename)
    #Validate that the datamodel(s) we pulled from the search exist
    success, submodels_with_fields = validate_datamodels(filename, search_datamodels, defined_datamodels)
    if success is False:
        return (success, False, {})


    if len(detection_file_data["datamodel"]) == 0 and len(search_datamodels) == 0:
        if "|tstats" in detection_file_data["search"] or "| tstats" in detection_file_data["search"]:
            print(f"{SMALL_INDENT} Error - {filename} contains tstats but no datamodels.  Raw search:\n\t{detection_file_data['search']}")
            return (False,False,{})            
        else:
            #print(f"{filename} is a search that does not contain any datamodels.  required_fields will not be validated or updated")
            return (True,False,detection_file_data)        

    #Pull all the the datamodel fields from the search
    search_submodel_fields = get_datamodel_fields(defined_datamodels, detection_file_data['search'])

    #Validate the fields we pulled from the search
    success = validate_fields(filename, submodels_with_fields, search_submodel_fields)
    if success is False:
        return (success, False, detection_file_data)

    search_datamodel_and_submodel_set = set()
    for model in search_datamodels:
        for submodel in search_datamodels[model]:
            search_datamodel_and_submodel_set.add(f"{model}.{submodel}")
    
    search_datamodel_and_submodel_list = sorted(list(search_datamodel_and_submodel_set))
    if search_datamodel_and_submodel_list != detection_file_data['datamodel']:
          print(f"Updated datamodel(s) in {filename}:\n\t {detection_file_data['datamodel']} --> {search_datamodel_and_submodel_list}")
          detection_file_data['datamodel'] = search_datamodel_and_submodel_list
          updated = True
    else:
        #No updates to the datamodel field
        updated = False
    

    #print(f"{filename}:\n\t{datamodel_fields}")
    #sys.exit(0)

    return (True, updated, detection_file_data)

def validate_detection(filename:str, defined_datamodels:dict)->tuple[bool,bool, dict]:
    #Use this variable to determine whether or not the yaml data is updated and should
    #be rewritten to the file
    dataset_updates = False
    

    #load the yaml file
    try:
        with open(filename, "r") as detection_file:
            detection_file_data = yaml.safe_load(detection_file)
    except Exception as e:
        print(f"Error processing file [{filename}]: {str(e)}")
        return (False,False,{})
    

    #Ensure the 'type' field exists
    if not check_for_presence_of_fields(filename, detection_file_data, ['type']):
        raise(Exception("YML missing field name 'type'"))
    if detection_file_data['type'] not in ["Anomaly", "Hunting", "TTP" ]:
        #This is not one of the detection types we want to update
        return (True,False,{})

    if not check_for_presence_of_fields(filename, detection_file_data, ['search']):
        raise(Exception("YML missing field name 'search'"))
    if not check_for_presence_of_fields(filename, detection_file_data, ['tags']):
        raise(Exception("YML missing field name 'tags'"))
    if not check_for_presence_of_fields(filename, detection_file_data, ['datamodel']):
        raise(Exception("YML missing field name 'datamodel'"))
    if not check_for_presence_of_fields(filename, detection_file_data['tags'], ['required_fields']):
        raise(Exception("YML missing field name ['tags']['required_fields']"))
            
        


    #Always validate that the same dataset is linked in the detection as in the test file
    

    success, dataset_updates, detection_file_data = verify_dataset_field(filename, detection_file_data)
    if success is False:
        return (success, False, {})
    
    success, datamodel_updates, detection_file_data = update_datamodels(filename, defined_datamodels, detection_file_data)
    if success is False:
        return (success, False, {})

 
    #Updates requires that one, or both, of the dataset and datamodels are updated
    updates = dataset_updates | datamodel_updates
    

    return (success, updates, detection_file_data)
        


def get_detection_filenames(detection_directory:pathlib.PosixPath, sort=True)->list[str]:
    detection_filenames = [str(p) for p in detection_directory.glob("**/[!ssa___]*.yml") if "/deprecated/" not in str(p) and "/experimental/" not in str(p)]
    print("Enumerating detections........", end='', flush=True)
    print(f"[{len(detection_filenames):4d}] detections found")
    if sort:
        return sorted(detection_filenames)
    else:
        return detection_filenames    

def output_updated_detection(detection_filename:str, detection_data:dict)->bool:
    try:
        with open(detection_filename, "w") as updated_detection:
            yaml.dump(detection_data, updated_detection, sort_keys=False)
        print(f"\t{detection_filename} changes written to disk")
        return True
    except Exception as e:
        print(f"Error writing {detection_filename} to disk: {str(e)}")
        return False


def main():

    parser  =argparse.ArgumentParser(prog="fields_extractor_and_updater",
                                     description="This tool parses the search field and uses it to "
                                        "determine and update the values in the datamodel "
                                        "and required_fields portions of the detection yml.")
    
    parser.add_argument("mode", 
                        choices=["check", "update"], 
                        help="Determines whether detections should be checked or updated.  "
                             "Check will print the results, but update will update "
                             "(and overrwrite) files that require changes.")
    parser.add_argument("-d", 
                        "--detection_directory", 
                        type=pathlib.Path, 
                        required=False, 
                        default = "../detections/",
                        help="Root directory (or filename) to update.  "
                             "Please note that this should NOT be a regular expression")

    parser.add_argument("-dm", 
                        "--datamodel_directory", 
                        type=pathlib.Path, 
                        required=False,
                        default="base_datamodels", 
                        help="Root directory containing the standard datamodels. "
                             "Please note that this should NOT be a regular expression")
    
    args = parser.parse_args()


    #Load all the datamodels to validate against
    defined_datamodels = load_datamodels_from_directory(args.datamodel_directory)

    #Get all the files that we will process
    detection_filenames = get_detection_filenames(args.detection_directory)
    


    
    
    all_success = True
    #Update/check each of the files
    for detection_filename in detection_filenames:
        #Convert from 
        try:
            success, dataset_has_updates, updated_dataset = validate_detection(detection_filename, defined_datamodels)
            all_success &= success #accumulate any errors that may occur here

            if success and dataset_has_updates and (args.mode == "update"):
                output_updated_detection(detection_filename, updated_dataset)

                        
        except Exception as e:
            print(f"Error processing {detection_filename}: {str(e)}")

    
    if all_success is True:
        print("All required fields pass!")
        sys.exit(0)
    else:
        print("At least one error occurred - check the output for details")
        sys.exit(1)

if __name__ == "__main__":
    main()




