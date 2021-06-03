import glob
import yaml
import sys
import re
import argparse
import requests
import csv
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

from os import path

BASE_URL = f"https://ip:8089"
SEARCH_PARSER_ENDPOINT = f"/services/search/parser"
USER = f"admin"
PASSWORD = f"password"
parsed_fields = dict()


def load_objects(file_path, REPO_PATH):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)
    for file in sorted(glob.glob(manifest_files)):
        files.append(load_file(file))
    return files


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def load_content(old_project):

    # process all detections
    detections = []
    detections = load_objects("detections/*/*.yml", old_project)
    detections.extend(load_objects("detections/*/*/*.yml", old_project))

    #print(len(detections))

    return detections


def analysis_detection(detections):

    for detection in detections:#
        if detection['type'] != 'streaming':
            #if detection['name'] == 'Attempted Credential Dump From Registry via Reg exe':
            print('Analysis Detection: ' + detection['name'])
            call_splunk_parser_api(detection)

    # sort parsed fields by occurence
    sorted_dict = {k: v for k, v in sorted(parsed_fields.items(), key=lambda item: item[1], reverse=True)}

    with open('output_fields_ordered_by_usage.csv', mode='w') as csv_file:
        writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        writer.writerow(['field_name', 'occurence'])

        for field_name in sorted_dict:
            writer.writerow([field_name, sorted_dict[field_name]])

    # sort parsed fields by name
    sorted_dict_2 = sorted(parsed_fields.items())

    with open('output_fields_ordered_by_keys.csv', mode='w') as csv_file:
        writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        writer.writerow(['field_name', 'occurence'])

        for field_name in sorted_dict_2:
            writer.writerow([field_name[0], field_name[1]])


def call_splunk_parser_api(detection):
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    spl = ''
    if detection['search'].startswith('| tstats'):
        spl = detection['search']
    else:
        spl = 'search ' + detection['search']
    data = {
        "output_mode": "json",
        "q": spl,
        "parse_only": "true"
    }
    response = requests.post(BASE_URL + SEARCH_PARSER_ENDPOINT, data=data, auth=(USER, PASSWORD), verify=False, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if response.status_code != 200:
        print(response.json())
        print('ERROR: parser endpoint problems')
        return
    parse_commands(response.json())


def parse_commands(api_response):
    tmp_parsed_fields = {}

    last_stat_command = ''
    rename_command_after_stats_arr = []

    for command in api_response['commands']:
        if command['command'] in ['tstats', 'stats', 'table']:
            last_stat_command = command
        if (command['command'] == 'rename') and last_stat_command:
            rename_command_after_stats_arr.append(command)
        

    if not last_stat_command:
        print('ERROR: could not find stats table or tasts command')
        return
        
    # last command table
    if last_stat_command['command'] == 'table':
        matches = re.findall(r'([0-9a-zA-Z_]+)', last_stat_command['rawargs'])
        for match in matches:
            if match in tmp_parsed_fields:
                tmp_parsed_fields[match] = tmp_parsed_fields[match] + 1
            else:
                tmp_parsed_fields[match] = 1

    # last command stats
    if last_stat_command['command'] == 'stats':
        match = re.match(r'(.*)by', last_stat_command['rawargs'])
        if match:
            args_one = match.group(1)
            matches = re.findall(r'(?:min|max|values)\(([0-9a-zA-Z_]+)\)', args_one)
            if matches:
                for match in matches:
                    if match in tmp_parsed_fields:
                        tmp_parsed_fields[match] = tmp_parsed_fields[match] + 1
                    else:
                        tmp_parsed_fields[match] = 1
        match = re.match(r'.*by(.*)$', last_stat_command['rawargs'])
        if match:
            args_two = match.group(1)
            matches = re.findall(r'([0-9a-zA-Z_]+)', args_two)
            if matches:
                for match in matches:
                    if match in tmp_parsed_fields:
                        tmp_parsed_fields[match] = tmp_parsed_fields[match] + 1
                    else:
                        tmp_parsed_fields[match] = 1    

    # tstats command
    if last_stat_command['command'] == 'tstats':
        match = re.match(r'(.*)(?:from|FROM)', last_stat_command['rawargs'])
        if match:
            args_one = match.group(1)
            matches = re.findall(r'(?:min|max|values)\(([0-9a-zA-Z_]+)\.([0-9a-zA-Z_]+)\)', args_one)
            if matches:
                for match in matches:
                    field = match[0] + '.' + match[1]
                    if field in tmp_parsed_fields:
                        tmp_parsed_fields[field] = tmp_parsed_fields[field] + 1
                    else:
                        tmp_parsed_fields[field] = 1    

        match = re.match(r'.*by(.*)$', last_stat_command['rawargs'])
        if match:
            args_two = match.group(1)
            matches = re.findall(r'([0-9_a-zA-Z]+)\.([0-9a-zA-Z_]+)', args_two)
            if matches:
                for match in matches:
                    field = match[0] + '.' + match[1]
                    if field in tmp_parsed_fields:
                        tmp_parsed_fields[field] = tmp_parsed_fields[field] + 1
                    else:
                        tmp_parsed_fields[field] = 1    

        match = re.match(r'.*where(.*)by.*$', last_stat_command['rawargs'])
        if match:
            args_three = match.group(1)
            matches = re.findall(r'([0-9_a-zA-Z]+)\.([0-9a-zA-Z_]+)=', args_three)
            if matches:
                for match in matches:
                    field = match[0] + '.' + match[1]
                    if field in tmp_parsed_fields:
                        tmp_parsed_fields[field] = tmp_parsed_fields[field] + 1
                    else:
                        tmp_parsed_fields[field] = 1    


    # rename occured 
    for rename_command_after_stats in rename_command_after_stats_arr:
        if rename_command_after_stats:
            renamed_field = {}
            matches = re.findall(r'(?:(([0-9a-zA-Z_]+)\s+as\s+([0-9a-zA-Z_]+)))', rename_command_after_stats['rawargs'])
            for match in matches:
                renamed_field[match[1]] = match[2]

            for key in renamed_field:
                if key in tmp_parsed_fields:
                    tmp_parsed_fields[renamed_field[key]] = tmp_parsed_fields.pop(key)

    # write to global parsed fields var
    for key in tmp_parsed_fields:
        if key in parsed_fields:
            parsed_fields[key] = parsed_fields[key] + tmp_parsed_fields[key]
        else:
            parsed_fields[key] = tmp_parsed_fields[key]


def main(project):

    detections = load_content(project)
    analysis_detection(detections)


if __name__ == "__main__":

    main("../")
