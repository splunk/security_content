import collections
import yaml
import sys
import glob
import os
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

def load_datamodels_from_directory(datamodels_directory:str)->dict:
    all_models = {}
    datamodel_filenames = glob.glob(os.path.join(datamodels_directory,"*.json"))
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
    print(f"All {len(datamodel_filenames)} datamodels parsed")

    '''
    dups = [{"field_name": element, "number_of_occurences":count} for element, count in collections.Counter(all_fields).items() if count > 1]
    if len(dups) != 0:
        print("There were duplicate field names in the data models. They are listed below")
        for dup in dups:
            print(f"{dup['field_name']}: {dup['number_of_occurences']} occurences")
        raise Exception("Duplicate fields detected")
    '''
    '''
    counts= {}
    for field in all_fields:
        c = field.count(".")
        if c in counts:
            counts[c] += 1
        else:
            counts[c] = 1
    print(counts)

    print("\n".join(all_fields))
    '''

    return all_models


def get_datamodels(search:str)->dict:
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

def get_datamodel_fields(search:str):
    quoted_text_removed = re.sub(QUOTATIONS_PATTERN, "", search)
    return set(re.findall(KEY_VALUE_PATTERN, quoted_text_removed))


def update_required_fields_for_yaml(filename:str, search:str, required_fields:set, datamodels_from_datamodel_field:set, defined_datamodels:dict, required_fields_from_yaml:set[str])->dict:

    datamodels_from_search = get_datamodels(search,filename)
    #print(f"Datamodels found in {filename}: {datamodels}")
    yaml_fields_to_update = {}





    #Now, ensure all the datamodels that we read from the file exist in the defiend datamodels
    for model, submodel in datamodels_from_search:
        if model not in defined_datamodels :
            print(f"Error in {filename} - Failed to find model {model} in {defined_datamodels.keys()}")
            #sys.exit(1)
        elif submodel not in defined_datamodels[model]:
            print(f"Error in {filename} - Failed to find submodel {submodel} in {defined_datamodels[model].keys()}")
            sys.exit(1)




    datamodels_with_submodel = [f"{d[0]}.{d[1]}" for d in datamodels_from_search]
    disjoint_members = datamodels_from_datamodel_field.symmetric_difference(datamodels_with_submodel)
    if len(disjoint_members) != 0:
        yaml_fields_to_update['datamodel'] = sorted(datamodels_with_submodel)
    #if len(datamodels_from_datamodel_field) == 0:
    #    print(f"{filename} is {datamodels_from_datamodel_field}")
    for model in datamodels_from_datamodel_field:
        if model not in datamodels_with_submodel:
            #print (f"{filename} used datamodel {model} but not in search {datamodels_from_search}")
            break


    '''
    for model in datamodels_from_datamodel_field:
        if model not in datamodels_from_search:
            print(f"file {filename} yml contains datamodels:{datamodels_from_datamodel_field} but {model} was not found in search")
            #print("ERROR")
            #yaml_update_required = True
            #input("waiting...\n")

    for model in datamodels_from_search:
        if model not in datamodels_from_datamodel_field:
            #print(f"file {filename} yml contains search: {search} but {model} was not found in datamodels: {yml_datamodels}")
            #print("ERROR")
            yaml_update_required = True
            #input("waiting...\n")
    '''

    toks = get_datamodel_fields(search)

    #print(defined_datamodels)
    #print(toks)
    #dictPrint(defined_datamodels)

    #For each token (submodel.field) found in the search field, make sure that it is included in the
    # required_fields portion of the YAML.
    #Required fields in a datamodel should be in the format model.submodel.fieldname to be more explicit.
    #If a field is declared in required_fields that does not have a dot and exists in the raw search, then keep it.
    #If a field is declared in required_fields that does not have a dot and does not exit in the raw search, then remove it.

    #Remove all the datamodels and datamodel.submodels from toks.
    toks_without_datamodels = set()
    datamodels_in_use = dict()
    for tok in toks:
        try:
            model,submodel = tok.split(".")
        except Exception:
            raise Exception(f"Did not find 2 . in {tok}")

        if model in defined_datamodels and submodel in defined_datamodels[model]:
            #print(f"Found {tok} in defined datamodels!")
            if model not in datamodels_in_use:
                datamodels_in_use[model] = {}

            datamodels_in_use[model][submodel] = defined_datamodels[model][submodel]
        else:
            toks_without_datamodels.add((model,submodel))


    #dictPrint(datamodels_in_use.keys())
    #dictPrint(toks_without_datamodels)


    fully_qualified_field_dicts = {}
    #locate the field in the declared models
    for submodel, fieldname in toks_without_datamodels:
        #print(f"{submodel}.{fieldname}")
        found = False
        for model in datamodels_in_use:
            dm = datamodels_in_use[model]
            #dictPrint(dm)
            if submodel in dm and fieldname in dm[submodel]:
                fully_qualified_field_dicts[f"{model}.{submodel}.{fieldname}"] = dm[submodel][fieldname]
                found=True
                break
        #If we got here, then we didn't find the fieldname in any of the models! This is bad. All these fields should probably be quoted... and there is some cleaning that needs to take place here...
        #if found == False and len(datamodels_in_use) > 0:
        if found == False and len(datamodels_in_use) > 0 and "exe" not in fieldname.lower():
            print(f"Failed to find {submodel}.{fieldname} in the datamodels {datamodels_in_use.keys()} for {filename}")


    non_datamodel_required_fields_from_yaml = [f for f in required_fields if "." not in f]
    new_required_fields = list(fully_qualified_field_dicts.keys())
    for field in non_datamodel_required_fields_from_yaml:
        if field in search:
            new_required_fields.append(field)
    new_required_fields.sort()
    symdiff = required_fields_from_yaml.symmetric_difference(set(new_required_fields))
    if len(symdiff) != 0:
        yaml_fields_to_update['tags']= {'required_fields': new_required_fields}




    return yaml_fields_to_update
    if yaml_update_required and False:
        '''
        print(f"\nMismatch between datamodel(s) used in search and declared datamodel(s)\n"\
              f"\tFilename                        : {filename}\n"\
              f"\tDisjoint Members                : {disjoint_members if len(disjoint_members) > 0 else '{}'}\n"\
              f"\tdatamodels extracted from search: {datamodels_from_search if len(datamodels_from_search) > 0 else '{}'}\n"\
              f"\tdatamodels declared in YAML     : {datamodels_from_datamodel_field if len(datamodels_from_datamodel_field) > 0 else '{}'}\n"\
              f"\tUpdating the datamodels field in the YAML to contain datamodels extracted from search\n")
        '''
        yaml_fields_to_update['datamodel'] = datamodels_from_search




    #print(datamodels)
    #print(yml_datamodels)
    #input("waiting...")
    return yaml_fields_to_update


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
        return (False,False,detection_file_data)
    

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
        else:
            errors.append(f"Found more than just a submodel and field for {field}")


    input("waiting...")
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
        return (False,False,detection_file_data)

    if not check_for_presence_of_fields(filename, detection_file_data["tags"], ["required_fields"]):
        return (False,False,detection_file_data)
    

    if not check_for_presence_of_fields(filename, detection_file_data, ["datamodel"]):
        return (False,False,detection_file_data)

    
    #Pull the datamodel(s) from the search
    search_datamodels = get_datamodels(detection_file_data['search'])
    #Validate that the datamodel(s) we pulled from the search exist
    success, submodels_with_fields = validate_datamodels(filename, search_datamodels, defined_datamodels)

    
    if len(detection_file_data["datamodel"]) == 0 and len(search_datamodels) == 0:
        print(f"{filename} is a search that does not contain any datamodels.  required_fields will not be validated or updated")
        if "tstats" in detection_file_data["search"]:
            print(f"{SMALL_INDENT} Error - how can it contain no datamodels if it contains tstats?  Raw search:\n\t{detection_file_data['search']}")
            return (False,False,detection_file_data)            
        return (True,False,detection_file_data)        

    #Pull all the the datamodel fields from the search
    search_submodel_fields = get_datamodel_fields(detection_file_data['search'])

    #Validate the fields we pulled from the search
    validate_fields(filename, submodels_with_fields, search_submodel_fields)



    #print(f"{filename}:\n\t{datamodel_fields}")
    #sys.exit(0)





    return (True, False, detection_file_data)

def update_detection(filename:str, defined_datamodels:dict)->tuple[bool,bool, dict]:
    #Use this variable to determine whether or not the yaml data is updated and should
    #be rewritten to the file
    dataset_updates = False
    
    try:
        with open(filename, "r") as detection_file:
            detection_file_data = yaml.safe_load(detection_file)
    except Exception as e:
        print(f"Error processing file [{filename}]: {str(e)}")
        return (False,False,{})
    

    if not check_for_presence_of_fields(filename, detection_file_data, ['type']):
        return (True,False,{})
    if detection_file_data['type'] not in ["Anomaly", "Hunting", "TTP" ]:
        #This is not one of the detection types we want to update
        return (True,False,{})

    if not (check_for_presence_of_fields(filename, detection_file_data, ['search', 'tags', 'datamodel']) and 
            check_for_presence_of_fields(filename, detection_file_data["tags"], ['required_fields'])):
        return (False, False,{})


    #Always validate that the same dataset is linked in the detection as in the test file
    

    success, updates, detection_file_data = verify_dataset_field(filename, detection_file_data)
    
    success, updates, detection_file_data = update_datamodels(filename, defined_datamodels, detection_file_data)

    

    return (success, updates, detection_file_data)
        


    

def clean_folder(directory:str, defined_datamodels:dict):
    files = glob.glob(os.path.join(directory,"*"))
    files.sort()
    files = [file for file in files if not os.path.basename(file).startswith("ssa___")]
    #print(f"Processing folder {directory} with {len(files)} files")
    failure_count = 0
    required_updates = 0
    no_updates = 0
    error_files = []
    total_files = 0
    files_with_datamodels = 0
    files_without_datamodels = 0
    for filename in files:
        try:
            attack_datafiles_in_test = []
            dataset_updates = False

            total_files+=1
            with open(filename,"r") as cfg:
                parsed = yaml.safe_load(cfg)

            if parsed["type"] not in ["Anomaly", "Hunting", "TTP" ]:
                continue



            if "search" not in parsed:
                print(f"Failed to find ['search'] in {filename}")
                failure_count += 1
                continue
            elif "tags" not in parsed:
                print(f"Failed to find ['tags'] {filename}")
                failure_count += 1
                continue
            elif "required_fields" not in parsed["tags"]:
                print(f"Failed to find ['tags']['required_fields'] in {filename}")
                failure_count += 1
                continue
            elif "datamodel" not in parsed:
                print(f"Failed to find ['datamodel'] in {filename}")
                failure_count += 1
                continue

            if "dataset" not in parsed["tags"] or True:
                #print(f"Error - did not find dataset in   {filename}", file=sys.stderr)
                test_filename = filename.replace(".yml", ".test.yml",1).replace("/detections/","/tests/",1)
                #print(f"      Populating from test file   {test_filename}")
                try:
                    with open(test_filename, "r") as test_stream:
                        test_datamodel = yaml.safe_load(test_stream)
                        if 'tests' in test_datamodel:
                            for test in test_datamodel['tests']:
                                if 'attack_data' in test:
                                    for data_file in test['attack_data']:
                                        if 'data' in data_file:
                                            attack_datafiles_in_test.append(data_file['data'])
                                        else:
                                            print(f"'data' field not found in attack_data for {test_filename}: {dictPrint(data_file)}")
                                            sys.exit(1)
                                else:
                                    print(f"'attack_data' not found in the test file {test_filename}: : {dictPrint(test)}")
                                    sys.exit(1)
                        else:
                            print(f"'tests' field not found in attack_data for {test_filename}: {dictPrint(test_datamodel)}")
                            sys.exit(1)

                    if 'dataset' in parsed['tags']:
                        for attack_file in attack_datafiles_in_test:
                            if attack_file not in parsed['tags']['dataset']:
                                print(f"{filename[50:]: <60} dataset in test file but not in detection file {attack_file}")
                                dataset_updates = True
                        for attack_file in parsed['tags']['dataset']:
                            if attack_file not in attack_datafiles_in_test:
                                print(f"{filename[50:]: <60} dataset in detection file but not in test file {attack_file}")
                                dataset_updates = True
                    else:
                        print(f"{filename[50:]: <60} dataset not declared in detection file {attack_file}")
                        parsed["tags"]['dataset'] = attack_datafiles_in_test
                        dataset_updates = True
                        print("\tUpdated")

                except Exception as e:
                    print(f"Error while parsing {test_filename}: {str(e)}")
                    sys.exit(1)







            required_fields_from_yaml = set(parsed['tags']['required_fields'])
            fields_to_update = update_required_fields_for_yaml(filename, parsed["search"], set(parsed["tags"]["required_fields"]), set(parsed["datamodel"]), defined_datamodels, required_fields_from_yaml)

            if fields_to_update != {} or dataset_updates is True:
                if 'datamodel' in fields_to_update:
                    parsed['datamodel'] = fields_to_update['datamodel']
                if 'tags' in fields_to_update and 'required_fields' in fields_to_update['tags']:
                    parsed['tags']['required_fields'] = fields_to_update['tags']['required_fields']
                if dataset_updates is True:
                    print(f"Updated dataset in {filename}")
                    parsed["tags"]['dataset'] = attack_datafiles_in_test

                required_updates += 1

                with open(filename, 'w') as updated_cfg:
                    yaml.safe_dump(parsed, updated_cfg)


            else:
                no_updates += 1

            if len(parsed['datamodel']) > 0:
                files_with_datamodels+=1
            else:
                files_without_datamodels+=1
            #print(fields_to_update)
            #input("wait")







        except yaml.YAMLError as e:
            print(e)


    print(f"{directory}")
    print("Errors:%d %s"%(len(error_files), "\n\t".join(error_files)))
    print(f"The number of failures     : {failure_count}")
    print(f"The total number of files  : {len(files)}\n")
    print(f"The total number of updates: {required_updates}\n")
    return  (total_files, files_with_datamodels, files_without_datamodels)


def main():

    parser  =argparse.ArgumentParser(prog="fields_extractor_and_updater",
                                     description="This tool parses the search field and uses it to "
                                        "determine and update the values in the datamodel "
                                        "and required_fields portions of the detection yml.")
    
    parser.add_argument("mode", 
                        choices=["check", "update"], 
                        nargs = 1,
                        help="Determines whether detections should be checked or updated.  "
                             "Check will print the results, but update will update "
                             "(and overrwrite) files that require changes.")
    parser.add_argument("-d", 
                        "--detection_directory", 
                        type=pathlib.Path, 
                        required=False, 
                        nargs = 1,
                        default = "../detections/",
                        help="Root directory (or filename) to update.  "
                             "Please note that this should NOT be a regular expression")

    parser.add_argument("-dm", 
                        "--datamodel_directory", 
                        type=pathlib.Path, 
                        required=False,
                        nargs = 1,
                        default="base_datamodels", 
                        help="Root directory containing the standard datamodels. "
                             "Please note that this should NOT be a regular expression")
    
    args = parser.parse_args()


    defined_datamodels = load_datamodels_from_directory(args.datamodel_directory)

    
    
    total_files = 0
    total_files_with_datamodels = 0
    total_files_without_datamodels = 0

    #Get all the files that we will process
    detection_filenames = [str(p) for p in args.detection_directory.glob("**/[!ssa___]*.yml") if "/deprecated/" not in str(p) and "/experimental/" not in str(p)]
    detection_filenames.sort()
    print(f"Detection files to be checked for possible updates: [{len(detection_filenames)}]")
    
    
    #Update/check each of the files
    for detection_filename in detection_filenames:
        #Convert from 
        success, dataset_has_updates, updated_dataset = update_detection(detection_filename, defined_datamodels)
        if args.mode == "update" and dataset_has_updates:
            pass

        #total_files_folder, files_with_datamodels_folder, files_without_datamodels_folder = clean_folder(folder, defined_datamodels)
        #total_files += total_files_folder
        #total_files_with_datamodels += files_with_datamodels_folder
        #total_files_without_datamodels += files_without_datamodels_folder


    #print(f"Total Files                   : {total_files}")
    #print(f"Total Files with datamodels   : {total_files_with_datamodels}")
    #print(f"Total Files without datamodels: {total_files_without_datamodels}")
    pass


if __name__ == "__main__":
    main()
