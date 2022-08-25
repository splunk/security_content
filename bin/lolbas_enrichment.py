import yaml
import argparse
import sys
import re
import json 
from os import path, walk
from tqdm import tqdm


def read_security_content_detections(SECURITY_CONTENT_PATH, VERBOSE):
    types = ["endpoint", "application", "cloud", "network", "web", "experimental", "deprecated"]
    manifest_files = [
        SECURITY_CONTENT_PATH + 'detections/endpoint/ssa___windows_lolbin_binary_in_non_standard_path.yml'

    ]

    detections = []
    for manifest_file in tqdm(manifest_files):
        detection_yaml = dict()
        if VERBOSE:
            print("processing detection yaml {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
                object['file_path'] = manifest_file
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        detection_yaml = object
        detections.append(detection_yaml)
    return detections

def read_lolbas(LOLBAS_PATH, VERBOSE):
    types = ["OSBinaries", "OSLibraries", "OSScripts", "OtherMSBinaries"]
    manifest_files = []
    for t in types:
        for root, dirs, files in walk(LOLBAS_PATH + '/yml/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    lolbas = []
    for manifest_file in tqdm(manifest_files):
        lolba_yaml = dict()
        if VERBOSE:
            print("processing lolba yaml {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
                object['file_path'] = manifest_file
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        lolba_yaml = object
        lolbas.append(lolba_yaml)
    return lolbas

def confirm_match(lolba, matching_id_detections):
    matching_detections = []
    # grab just the name but not extension
    search_word = lolba['Name'].split('.')[0]
    # remove any (64) entries
    search_word = re.sub(r'\(\d+\)', '', search_word)

    for detection in matching_id_detections:
        if re.findall(search_word, detection['name'], re.IGNORECASE):
            matching_detections.append(detection)

    return matching_detections

def insert_splunk_detections(lolba, matching_detections):
    splunk_detections = []

    # build splunk detection entry object
    for matching_detection in matching_detections:
        detection_entry = {'Splunk' : "https://research.splunk.com/" + matching_detection['kind'] + "/" + matching_detection['id'] + "/"}
        splunk_detections.append(detection_entry)
    
    # clean up current splunk entries
    lolba_detections = []
    if 'Detection' in lolba and lolba['Detection'] != None:
        for detection in lolba['Detection']:
            lolba_detections.append(detection)

    # extend cleaned up detections with correct splunk urls
    lolba_detections.extend(splunk_detections)

    # replace list with newly cleaned 
    lolba['Detection'] = lolba_detections

    return lolba

def unique_detections(lolba_with_detections, lolba, VERBOSE):
    # unique all detections
    unique_detection_list = []
    if 'Detection' in lolba_with_detections and lolba_with_detections['Detection'] != None:
        for detection in lolba_with_detections['Detection']:
            if detection in unique_detection_list:
                pass
            else:
                if VERBOSE:
                    print("enriching lolba {0} with matching splunk detection: {1}".format(lolba['Name'], detection))
                unique_detection_list.append(detection)
        lolba['Detection'] = unique_detection_list    
    return lolba
    

def update_detections(detections, lolbas, VERBOSE):
    ssa_base_search = """$ssa_input = | from read_ssa_enriched_events() | eval device=ucast(map_get(input_event,
    "dest_device_id"), "string", null), user=ucast(map_get(input_event, "dest_user_id"),
    "string", null), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string",
    null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string",
    null)), process_path=lower(ucast(map_get(input_event, "process_path"), "string",
    null)), event_id=ucast(map_get(input_event, "event_id"), "string", null);"""

    for lolba in lolbas: 
        print("Name: {0}".format(lolba['Name']))
    ssa__location_condition = """| from $ssa_input | where"""

  

def write_lolbas(enriched_lolbas, LOLBAS_PATH, VERBOSE):
    for lolba in enriched_lolbas:
        file_path = lolba['file_path']
        lolba.pop('file_path')
        if VERBOSE:
            print(yaml.dump(lolba, indent=2))
        with open(file_path, 'w') as outfile:
            yaml.dump(lolba, outfile, default_flow_style=False, sort_keys=False)

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates Updates Splunk detections with latest LOLBAS")
    parser.add_argument("-splunk_security_content_path", "--spath", required=False, default='.', help="path to security_content repo")
    parser.add_argument("-lolbas_path", "--lpath", required=False, default='LOLBAS', help="path to the lolbas repo")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    
   # parse them
    args = parser.parse_args()
    SECURITY_CONTENT_PATH = args.spath
    LOLBAS_PATH = args.lpath
    VERBOSE = args.verbose

    if not (path.isdir(SECURITY_CONTENT_PATH) or path.isdir(SECURITY_CONTENT_PATH)):
        print("error: {0} is not a directory".format(SECURITY_CONTENT_PATH))
        sys.exit(1)

    print("processing lolbas")
    lolbas = read_lolbas(LOLBAS_PATH, VERBOSE)
    print("processing splunk security content detections")
    detections = read_security_content_detections(SECURITY_CONTENT_PATH, VERBOSE)
    print("updating detections")
    enriched_lolbas = update_detections(detections, lolbas, VERBOSE)
    #print("writing enriched lolbas")
    #write_lolbas(enriched_lolbas, LOLBAS_PATH, VERBOSE)