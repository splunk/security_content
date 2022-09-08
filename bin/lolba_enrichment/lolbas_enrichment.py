import yaml
import argparse
import sys
import re
import json 
import csv
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

def get_lolbas_paths(lolba):
    lolbas_paths = []
    if 'Full_Path' in lolba:
            for fullpath in lolba['Full_Path']:
                # check path is not none
                if fullpath['Path']:
                    # check path is in c:\ there are some entries with N/A, No fixed path etc. . we should skip those
                    if re.findall('c:', fullpath['Path'], re.IGNORECASE):
                        lolbas_paths.append(fullpath['Path'])
    return lolbas_paths
    
                        
def update_detection(detection, lolbas, VERBOSE, OPUTPUT_PATH):

    # windows_lolbin_binary_in_non_standard_path auto search generation
    # first process SSA search
    ssa_base_search = 'ssa_input = | from read_ssa_enriched_events() | eval device=ucast(map_get(input_event, "dest_device_id"), "string", null), user=ucast(map_get(input_event, "dest_user_id"), "string", null), timestamp=parse_long(ucast(map_get(input_event, "_time"), "string", null)), process_name=lower(ucast(map_get(input_event, "process_name"), "string", null)), process_path=lower(ucast(map_get(input_event, "process_path"), "string", null)), event_id=ucast(map_get(input_event, "event_id"), "string", null);'
    ssa_end_search ='| eval start_time=timestamp,end_time=timestamp, entities=mvappend(device, user), body=create_map(["event_id", event_id, "process_path", process_path, "process_name", process_name]) | into write_ssa_detected_events();'
    condition_1 = '$cond_1 = | from $ssa_input | where '
    condition_2 = '| from $cond_1 | where '
    lolbas_strings = ''
    lolbas_path_strings = '' 

    for lolba in lolbas:
        if get_lolbas_paths(lolba):
            full_paths = get_lolbas_paths(lolba)
            for full_path in full_paths:
                # grab the exe name
                lolbas_strings += 'process_name="' + lolba['Name'].lower() + '" OR '

                # drop the drive letter
                full_path = full_path[2:]

                # add path escapes
                full_path = full_path.replace("\\", "\\\\").lower()
                lolbas_path_strings += 'match_regex(process_path, /(?i)' + full_path + ')=false AND '


    # remove trailing OR and merge with condition
    condition_1 = condition_1 + lolbas_strings[:-3]
    # remove trailing AND nd merge with condition
    condition_2 = condition_2 + lolbas_path_strings[:-4]
    full_ssa_search = ssa_base_search + condition_1 + condition_2 + ssa_end_search 

    detection_file_name = detection['file_path'].split('/')[-1]
    detection_output_path = OUTPUT_PATH + '/' + detection_file_name

    if detection['name'] == 'Windows LOLBin Binary in Non Standard Path':
        if VERBOSE:
            print("writing detection: {0}".format(detection_output_path))
        detection['search'] = full_ssa_search
        # write changes down
        write_yaml(detection, VERBOSE, detection_output_path)

def write_csv(lolbas, OUTPUT_PATH):
    with open(OUTPUT_PATH + '/' + 'lolbas_file_path.csv', 'w', newline='') as csvfile:
        fieldnames = ['lolbas_file_name', 'lolbas_file_path', 'description']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for lolba in lolbas:
            if get_lolbas_paths(lolba):
                full_paths = get_lolbas_paths(lolba)
                for full_path in full_paths:
                    lolba_file_name = lolba['Name'].lower()
                    lolba_description = lolba['Description']
                    writer.writerow({'lolbas_file_name': lolba_file_name, 'lolbas_file_path': full_path.lower(), 'description': lolba_description})
   

def write_yaml(detection, VERBOSE, detection_output_path):
        detection.pop('file_path')
        if VERBOSE:
            print(yaml.dump(detection, indent=2, default_flow_style=False, sort_keys=False))
        with open(detection_output_path, 'w') as outfile:
            yaml.safe_dump(detection, outfile, default_flow_style=False, sort_keys=False)

        

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates Updates Splunk detections with latest LOLBAS")
    parser.add_argument("-splunk_security_content_path", "--spath", required=False, default='../../', help="path to security_content repo")
    parser.add_argument("-lolbas_path", "--lpath", required=False, default='LOLBAS', help="path to the lolbas repo")
    parser.add_argument("-o", "--output_path", required=False, default='.', help="Were to write results to")

    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    
   # parse them
    args = parser.parse_args()
    SECURITY_CONTENT_PATH = args.spath
    LOLBAS_PATH = args.lpath
    VERBOSE = args.verbose
    OUTPUT_PATH = args.output_path

    if not (path.isdir(SECURITY_CONTENT_PATH) or path.isdir(SECURITY_CONTENT_PATH)):
        print("error: {0} is not a directory".format(SECURITY_CONTENT_PATH))
        sys.exit(1)

    print("processing lolbas")
    lolbas = read_lolbas(LOLBAS_PATH, VERBOSE)
    print("processing splunk security content detections")
    detections = read_security_content_detections(SECURITY_CONTENT_PATH, VERBOSE)
    for detection in detections:
        detection_file_name = detection['file_path'].split('/')[-1]
        print("updating detection: {0}".format(OUTPUT_PATH + '/' + detection_file_name))
        update_detection(detection, lolbas, VERBOSE, OUTPUT_PATH)
    print("writing lolbas_file_path lookup to: {0}".format(OUTPUT_PATH + '/' + 'lolbas_file_path.csv'))
    write_csv(lolbas, OUTPUT_PATH)
    #print("writing enriched lolbas")
    #write_lolbas(enriched_lolbas, LOLBAS_PATH, VERBOSE)
