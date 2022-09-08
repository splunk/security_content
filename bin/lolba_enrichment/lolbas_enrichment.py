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





def update_detection(detections, lolbas, VERBOSE):

    # windows_lolbin_binary_in_non_standard_path auto search generation
    # first process SSA search
    ssa_base_search = """$ssa_input = | from read_ssa_enriched_events() | eval device=ucast(map_get(input_event,
    "dest_device_id"), "string", null), user=ucast(map_get(input_event, "dest_user_id"),
    "string", null), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string",
    null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string",
    null)), process_path=lower(ucast(map_get(input_event, "process_path"), "string",
    null)), event_id=ucast(map_get(input_event, "event_id"), "string", null);"""

    ssa_end_search ="""| eval start_time=timestamp,
  end_time=timestamp, entities=mvappend(device, user), body=create_map(["event_id",
  event_id, "process_path", process_path, "process_name", process_name]) | into write_ssa_detected_events();"""


    condition_1 = "$cond_1 = | from $ssa_input | where "
    condition_2 = "| from $cond_1 | where "
    lolbas_strings = ''
    lolbas_path_strings = '' 

    for lolba in lolbas:
        if 'Full_Path' in lolba:
            for fullpath in lolba['Full_Path']:
                # check path is not none
                if fullpath['Path']:
                    # check path is in c:\ there are some entries with N/A, No fixed path etc. . we should skip those
                    if re.findall('c:', fullpath['Path'], re.IGNORECASE):
                        # grab the exe 
                        lolbas_strings += 'process_name="' + lolba['Name'].lower() + '" OR '

                        # drop the drive letter
                        full_path = fullpath['Path'][2:]

                        # add path escapes
                        full_path = full_path.replace("\\", "\\\\").lower()
                        lolbas_path_strings += 'match_regex(process_path, /(?i)' + full_path + ')=false AND '


    # remove trailing OR and merge with condition
    condition_1 = condition_1 + lolbas_strings[:-3]
    # remove trailing AND nd merge with condition
    condition_2 = condition_2 + lolbas_path_strings[:-4]
    full_ssa_search = ssa_base_search + '\n' + condition_1 + '\n' + condition_2 + '\n' + ssa_end_search

    for detection in detections:
        # match the detection to change
        if detection['name'] == 'Windows LOLBin Binary in Non Standard Path':
            detection['search'] = full_ssa_search
            # write changes down
            write_yaml(detection, detection)
    

def write_yaml(detection, VERBOSE):
        file_path = detection['file_path']
        detection.pop('file_path')
        if VERBOSE:
            print(yaml.dump(detection, indent=2))
        with open(file_path, 'w') as outfile:
            yaml.dump(file_path, outfile, default_flow_style=False, sort_keys=False)

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates Updates Splunk detections with latest LOLBAS")
    parser.add_argument("-splunk_security_content_path", "--spath", required=False, default='../../', help="path to security_content repo")
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
    enriched_lolbas = update_detection(detections, lolbas, VERBOSE)
    #print("writing enriched lolbas")
    #write_lolbas(enriched_lolbas, LOLBAS_PATH, VERBOSE)
