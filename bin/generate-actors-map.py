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

VERSION = "4.3"
NAME = "Detection Priority by Threat Actors"
DESCRIPTION = "security_content detection priorty by common techniques used from threat actors"
DOMAIN = "mitre-enterprise"

def main(argv):

    # parse input variables
    parser = argparse.ArgumentParser(description='Detection Priority based on APT groups')
    parser.add_argument('-p', '--projects_path', default='.', action='store', metavar='N', help='folder containing the projects Mitre Cyber Threat Intelligence Repository, Security Content and Sigma')
    parser.add_argument('-o', '--output', default='output', action='store', help='result output directory, defaults to output')
    cmdargs = parser.parse_args()

    print("get all techniques for group")
    techniques, all_techniques = get_all_techniques_for_groups(cmdargs.projects_path)

    print("count techniques")
    counted_techniques, max_count = count_techniques(techniques, all_techniques)

    print("load detections techniques")
    detections = []
    detections = load_objects(path.join(cmdargs.projects_path),'detections/*/*.yml')

    print("get matched techniques")
    matched_techniques = get_matched_techniques(counted_techniques, detections)

    print("generate navigator layer")
    generate_navigator_layer(matched_techniques, max_count, cmdargs.output)

    print("generate csv file")
    generate_csv_file(matched_techniques, cmdargs.output)


def count_techniques(techniques, all_techniques):
    counted_techniques = []
    final_counted_techniques = []

    max_count = 0
    actors = []
    for all_technique in all_techniques:
        count_technique = sum(t['name'] == all_technique['name'] for t in techniques)
        if count_technique > 0:
            counted_techniques.append({'name': all_technique['name'], 'object': all_technique, 'count': count_technique})
            max_count = count_technique if count_technique > max_count else max_count

    for all_technique in all_techniques:
        if "." in all_technique["external_references"][0]["external_id"]:
            parent_id = all_technique["external_references"][0]["external_id"].split(".")[0]
            for counted in counted_techniques:
                if parent_id == counted["object"]["external_references"][0]["external_id"]:
                    counted['count'] += 1
                final_counted_techniques.append(counted)

    counted_techniques = sorted(final_counted_techniques, key = lambda i: i['count'], reverse=True)

    return counted_techniques, max_count

def get_all_techniques_for_groups(projects_path):
    path_cti = path.join(projects_path,'cti/enterprise-attack')
    fs = FileSystemSource(path_cti)
    all_techniques = get_all_techniques(fs)

    techniques = []

    groups = get_all_groups(fs)
    for group_obj in groups:
        techniques.extend(get_technique_by_group(fs, group_obj))

        # ONLY FOR TESTING
        #if len(techniques) > 50 :
        #    return techniques, all_techniques

    return techniques, all_techniques


def get_all_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)


def get_all_groups(src):
    filt = [Filter('type', '=', 'intrusion-set')]
    return src.query(filt)


def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])


def get_matched_techniques(counted_techniques, detections):
    matched_techniques = []

    for technique in counted_techniques:
        matched_splunk_detections = []

        # find detections from Splunks security content
        # https://github.com/splunk/security_content
        for detection in detections:
            if 'mitre_attack_id' in detection['object']['tags']:
                for mitreid in detection['object']['tags']['mitre_attack_id']:
                    if mitreid == technique["object"]["external_references"][0]["external_id"]:
                        matched_splunk_detections.append(detection)

        matched_techniques.append({
            "ID": technique["object"]["external_references"][0]["external_id"],
            # substract the amount of detections we have from the score
            "score": technique["count"] - len(matched_splunk_detections),
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

        layer_technique = {
            "techniqueID": technique["ID"],
            "score" : technique["score"],
            "showSubtechniques": False
        }


        if len(technique["splunk_rules"]) > 0:
            for splunk_rule in technique["splunk_rules"]:
                comments.append("https://github.com/splunk/security_content/blob/develop/detections/" + splunk_rule['filename'])

        if len(comments) > 0:
            layer_technique["comment"] = "\n\n".join(comments)

        layer_json["techniques"].append(layer_technique)

    # add a color gradient (white -> red) to layer
    # ranging from zero (white) to the maximum score in the file (red)
    layer_json["gradient"] = {
        "colors": [
			"#66b1ff",
			"#ff66f4",
			"#ff6666"
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
            "label": "Low Priority",
            "color": "#66b1ff"
            },
        {
            "label": "Medium Priority",
            "color": "#ff66f4"
        },
		{
			"label": "High Priority",
			"color": "#ff6666"
		}
    ]

    layer_json['showTacticRowBackground'] = True
    layer_json['tacticRowBackground'] = "#dddddd"

    # output JSON
    with open(output + '/detections.json', 'w') as f:
        json.dump(layer_json, f, indent=4)

#    print("Mitre ATT&CK Navigator overlay was successfully written to output/detections.json")


def generate_csv_file(matched_techniques, output):

    security_content_url = 'https://github.com/splunk/security_content/blob/develop/detections/'

    with open(output + '/detections.csv', 'w') as f:
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
        file_name  =  file.replace('./detections/', '')
        files.append({
            "filename": file_name,
            "object": load_file(file)
        })

    return files


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            sys.exit("ERROR: reading {0}".format(file_path))
    return file

if __name__ == "__main__":
    main(sys.argv)
