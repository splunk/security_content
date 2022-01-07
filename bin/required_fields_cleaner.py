import collections
import yaml
import sys
import glob
import os
import re
import json

#find datamodel=SOMETHING, allowing for whitespace on either side of =
DATAMODEL_PATTERN = r"datamodel\s*=?\s*\S*"

QUOTATIONS_PATTERN = r'''(["'])(?:(?=(\\?))\2.)*?\1'''
KEY_VALUE_PATTERN = r"[a-zA-Z0-9_]*\.[a-zA-Z0-9_]*"

def parse_object(datamodel_name, object)->list[str]:
    members = []
    if "objects" in object:
        raise(Exception(("nested objects!")))
    for field in object['fields']:
        members.append((f"{datamodel_name}.{object['objectName']}.{field['fieldName']}"))

    return members

def load_all_datamodels(datamodels_directory:str)->list[str]:
    all_fields = []
    datamodel_files = glob.glob(os.path.join(datamodels_directory,"*.json"))    
    for datamodel_file in datamodel_files:
        with open(datamodel_file, "r") as model_stream:
            json_datamodel = json.load(model_stream)
        #print(f"Loaded {datamodel_file}: {json_datamodel['modelName']}\n"\
        #      f"\tNum Objects: {len(json_datamodel['objects'])}")
        for object in json_datamodel['objects']:
            all_fields.extend(parse_object(json_datamodel['modelName'], object))
    
    dups = [{"field_name": element, "number_of_occurences":count} for element, count in collections.Counter(all_fields).items() if count > 1]
    if len(dups) != 0:
        print("There were duplicate field names in the data models. They are listed below")
        for dup in dups:
            print(f"{dup['field_name']}: {dup['number_of_occurences']} occurences")
        raise Exception("Duplicate fields detected")
    
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
    return all_fields


def get_datamodels(search:str)->list[str]:
    #print(search)
    matches = re.findall(DATAMODEL_PATTERN, search)

    #get the models and strip out the whitespace
    
    #If we want different dot-separated versions
    
    models_and_submodels = [model.replace(" ","=").split("=")[1].strip() for model in matches]

    #If we only care about the top level
    models_only = [model.split(".")[0].strip() for model in models_and_submodels]

    
    return list(set(models_only))

def get_tokens(search:str):
    quoted_text_removed = re.sub(QUOTATIONS_PATTERN, "", search)
    return re.findall(KEY_VALUE_PATTERN, quoted_text_removed)


def update_required_fields_for_yaml(filename:str, search:str, required_fields, datamodels_from_datamodel_field)->tuple[str,bool]:
    datamodels_from_search = get_datamodels(search)
    #print(f"Datamodels found in {filename}: {datamodels}")
    error_found = False
    if len(datamodels_from_search) > 0:
        for model in datamodels_from_search:
            pass
            #if model.count(".") != 1:
            #    print(f"{filename}:\n{search}\n--------> {model}")
            #    error_found=True
        
    
    for model in datamodels_from_datamodel_field:
        if model not in datamodels_from_search:
            #print(f"file {filename} yml contains datamodels:{yml_datamodels} but {model} was not found in search: {search}")
            error_found = True
            #input("waiting...\n")
    
    for model in datamodels_from_search:
        if model not in datamodels_from_datamodel_field:
            #print(f"file {filename} yml contains search: {search} but {model} was not found in datamodels: {yml_datamodels}")
            error_found = True
            #input("waiting...\n")
    
    if error_found or True:
        print(f"filename      : {filename}\n"\
              f"datamodels    : {datamodels_from_search}\n"\
              f"yml_datamodels: {datamodels_from_datamodel_field}\n")
    

    #print(datamodels)
    #print(yml_datamodels)
    #input("waiting...")
    return "", error_found


def clean_folder(directory:str):
    files = glob.glob(os.path.join(directory,"*"))
    files = [file for file in files if not os.path.basename(file).startswith("ssa___")]
    #print(f"Processing folder {directory} with {len(files)} files")
    failure_count = 0
    error_files = []
    for filename in files:
        try:
            with open(filename,"r") as cfg:
                parsed = yaml.safe_load(cfg)
            
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
            else:
                res, new_quit = update_required_fields_for_yaml(filename, parsed["search"], parsed["tags"]["required_fields"], parsed["datamodel"])
                if new_quit is True:
                    error_files.append(filename)
                    continue

                toks = get_tokens(parsed['search'])
                print(f"{parsed['search']}")
                print(f"{filename} ---> {toks}")
                input("WAIT")

        except yaml.YAMLError as e:
            print(e)
    
    
    print("Errors:%d %s"%(len(error_files), "\n\t".join(error_files)))
    print(f"The number of failures   : {failure_count}")
    print(f"The total number of files: {len(files)}")
    return        


def clean():
    datamodel_directory = sys.argv[1]
    load_all_datamodels(datamodel_directory)

    #sys.exit(0)
    folders = sys.argv[2:]
    for folder in folders:
        clean_folder(folder)

    pass


if __name__ == "__main__":
    clean()