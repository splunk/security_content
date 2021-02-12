#!/usr/bin/python

import sys
import argparse
import json
import glob
import yaml
import os
import csv
from os import path
from stix2 import FileSystemSource
from stix2 import Filter

VERSION = "4.1"
NAME = "Detection Coverage"
DESCRIPTION = "security_content detection coverage"
DOMAIN = "mitre-enterprise"

def main(argv):

    # parse input variables
    parser = argparse.ArgumentParser(description='Detection Coverage')
    parser.add_argument('-p', '--projects_path', default='.', action='store', metavar='N', help='folder containing the projects Mitre Cyber Threat Intelligence Repository, Security Content and Sigma')
    parser.add_argument('-o', '--output', default='output', action='store', help='result output directory, defaults to output')
    cmdargs = parser.parse_args()

    print("get all techniques")
    techniques = get_all_techniques(cmdargs.projects_path)

    print("load detections")
    detections = []
    detections = load_objects(path.join(cmdargs.projects_path),'detections/*/*.yml')

    print("get matched techniques")
    matched_techniques = get_matched_techniques(techniques, detections)

    print("score detections")
    scored_techniques, max_count = count_detections(matched_techniques)

    print("generate navigator layer")
    generate_navigator_layer(scored_techniques, max_count, cmdargs.output)

    print("generate csv file")
    generate_csv_file(scored_techniques, cmdargs.output)


def count_detections(matched_techniques):
    scored_detections = []
    final_scored_detections = []
    max_count = 0

    for technique in matched_techniques:
        if "splunk_rules" in technique:
            technique['score'] = len(technique['splunk_rules'])
            max_count = technique['score'] if technique['score'] > max_count else max_count
            scored_detections.append(technique)

    for technique in matched_techniques:
        if "." in technique['ID']:
            parent_id = technique['ID'].split(".")[0]
            for scored in scored_detections:
                if parent_id == scored['ID']:
                    scored['score'] += len(technique['splunk_rules'])
                final_scored_detections.append(scored)

    return final_scored_detections, max_count


def get_all_techniques(projects_path):
    path_cti = path.join(projects_path,'cti/enterprise-attack')
    fs = FileSystemSource(path_cti)
    all_techniques = get_techniques(fs)
    return all_techniques


def get_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)



def get_matched_techniques(counted_techniques, detections):
    matched_techniques = []

    for technique in counted_techniques:
        matched_splunk_detections = []

        # find detections from Splunks security content
        # https://github.com/splunk/security_content
        for detection in detections:
            if 'mitre_attack_id' in detection['object']['tags']:
                for mitreid in detection['object']['tags']['mitre_attack_id']:
                    if mitreid == technique["external_references"][0]["external_id"]:
                        matched_splunk_detections.append(detection)

        matched_techniques.append({
            "ID": technique["external_references"][0]["external_id"],
            "splunk_rules": matched_splunk_detections,
        })
    return matched_techniques


def generate_navigator_layer(matched_techniques, max_count, output):

    # Base ATT&CK Navigator layer
    layer_json = {
        "version": VERSION,
        "name": NAME,
        "description": DESCRIPTION,
        "domain": DOMAIN,
        "techniques": []
    }

    for technique in matched_techniques:
        comments = []
        if len(technique["splunk_rules"]) > 0:
            for splunk_rule in technique["splunk_rules"]:
                comments.append("https://github.com/splunk/security_content/blob/develop/detections/" + splunk_rule['filename'])
                layer_technique = {
                "techniqueID": technique["ID"],
                "score" : technique["score"]

                }
        else:
            layer_technique = {}
        if len(comments) > 0:
            layer_technique["comment"] = "\n\n".join(comments)

        layer_json["techniques"].append(layer_technique)

    # add a color gradient (white -> red) to layer
    # ranging from zero (white) to the maximum score in the file (red)
    layer_json["gradient"] = {
        "colors": [
			"#ffffff",
			"#66b1ff",
            "#096ed7"
        ],
        "minValue": 0,
        "maxValue": max_count
    }

    layer_json["filters"] = {
            "platforms":
                ["Windows",
                "Linux",
                "macOS",
                "AWS",
                "GCP",
                "Azure",
                "Office 365",
                "SaaS"
            ]
    }

    layer_json["legendItems"] = [
        {
            "label": "NO available detections",
            "color": "#ffffff"
        },
		{
			"label": "Some detections available",
			"color": "#66b1ff"
		}
    ]

    layer_json['showTacticRowBackground'] = True
    layer_json['tacticRowBackground'] = "#dddddd"
    layer_json["sorting"] = 3

    # output JSON
    with open(output + '/coverage.json', 'w') as f:
        json.dump(layer_json, f, indent=4)

#    print("Mitre ATT&CK Navigator overlay was successfully written to output/detections.json")


def generate_csv_file(matched_techniques, output):

    security_content_url = 'https://github.com/splunk/security_content/blob/develop/detections/'

    with open(output + '/coverage.csv', 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['Technique ID', 'Detection Available', 'Link', 'score'])

        for technique in matched_techniques:
            if len(technique['splunk_rules']) > 0:
                for splunk_rule in technique["splunk_rules"]:
                    writer.writerow([technique["ID"], "Yes", \
                    security_content_url + splunk_rule["filename"], technique['score']])
            else:
                writer.writerow([technique["ID"], "No", \
                "-", technique['score']])
#    print("Recommended detections were successfully written to output/detections.csv")


def load_objects(security_content_path, file_path):
    files = []
    detection_files = path.join(path.expanduser(security_content_path), file_path)

    for file in glob.glob(detection_files):
        files.append({
            "filename": os.path.basename(file),
            "object": load_file(file)
        })

    return files


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
#            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file

if __name__ == "__main__":
    main(sys.argv)
