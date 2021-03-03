import glob
import yaml
import argparse
import sys
import re
from os import path, walk
import json
from jinja2 import Environment, FileSystemLoader
from attackcti import attack_client
from pyattck import Attck


def mitre_attack_object(technique, attack):
    mitre_attack = dict()
    mitre_attack['technique_id'] = technique.id
    mitre_attack['technique'] = technique.name

    # process tactics
    tactics = []
    for tactic in technique.tactics:
        tactics.append(tactic.name)
    mitre_attack['tactic'] = tactics

    return mitre_attack

def get_mitre_enrichment_new(attack, mitre_attack_id):
    for technique in attack.enterprise.techniques:
        apt_groups = []
        if '.' in mitre_attack_id:
            for subtechnique in technique.subtechniques:
                if mitre_attack_id == subtechnique.id:
                    mitre_attack = mitre_attack_object(subtechnique, attack)
                    return mitre_attack

        elif mitre_attack_id == technique.id:
            mitre_attack = mitre_attack_object(technique, attack)
            return mitre_attack

def generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, sorted_detections, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + '/stories'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    stories = []
    for manifest_file in manifest_files:
        story_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue
        story_yaml = object

        # enrich the mitre object
        mitre_attacks = []
        if 'mitre_attack_id' in story_yaml['tags']:
            for mitre_technique_id in story_yaml['tags']['mitre_attack_id']:
                mitre_attack = get_mitre_enrichment_new(attack, mitre_technique_id)
                mitre_attacks.append(mitre_attack)
            story_yaml['mitre_attacks'] = mitre_attacks
        stories.append(story_yaml)

    sorted_stories = sorted(stories, key=lambda i: i['name'])

    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_kill_chain_phases = {}
    sto_to_det = {}
    for detection in sorted_detections:
        if 'analytic_story' in detection['tags']:
            for story in detection['tags']['analytic_story']:
                if story in sto_to_det.keys():
                    sto_to_det[story].add(detection['name'])
                else:
                    sto_to_det[story] = {detection['name']}
                data_model = detection['datamodel']
                if data_model:
                    for d in data_model:
                        if story in sto_to_data_models.keys():
                            sto_to_data_models[story].add(d)
                        else:
                            sto_to_data_models[story] = {d}

                if 'mitre_attack_id' in detection['tags']:
                    if story in sto_to_mitre_attack_ids.keys():
                        for mitre_attack_id in detection['tags']['mitre_attack_id']:
                            sto_to_mitre_attack_ids[story].add(mitre_attack_id)
                    else:
                        sto_to_mitre_attack_ids[story] = set(detection['tags']['mitre_attack_id'])

                if 'kill_chain_phases' in detection['tags']:
                    if story in sto_to_kill_chain_phases.keys():
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story].add(kill_chain)
                    else:
                        sto_to_kill_chain_phases[story] = set(detection['tags']['kill_chain_phases'])

    for story in sorted_stories:
        print(story)
        story['detections'] = sorted(sto_to_det[story['name']])
        if story['name'] in sto_to_data_models:
            story['data_models'] = sorted(sto_to_data_models[story['name']])
        if story['name'] in sto_to_mitre_attack_ids:
            story['mitre_attack_ids'] = sorted(sto_to_mitre_attack_ids[story['name']])
        if story['name'] in sto_to_kill_chain_phases:
            story['kill_chain_phases'] = sorted(sto_to_kill_chain_phases[story['name']])

    #sort stories into categories
    categories = []
    category_names = set()
    for story in sorted_stories:
        if 'category' in story['tags']:
            category_names.add(story['tags']['category'][0])

    for category_name in sorted(category_names):
        new_category = {}
        new_category['name'] = category_name
        new_category['stories'] = []
        categories.append(new_category)

    for story in sorted_stories:
        for category in categories:
            if category['name'] == story['tags']['category'][0]:
                category['stories'].append(story)

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                             trim_blocks=False)

    # write markdown
    template = j2_env.get_template('doc_stories_markdown.j2')
    output_path = path.join(OUTPUT_DIR + '/stories.md')
    output = template.render(categories=categories)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote {0} stories documentation in markdown to: {1}".format(len(stories),output_path))

def generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, messages, VERBOSE):
    types = ["endpoint", "application", "cloud", "network", "web", "experimental", "deprecated"]
    manifest_files = []
    for t in types:
        for root, dirs, files in walk(REPO_PATH + '/detections/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    detections = []
    for manifest_file in manifest_files:
        detection_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                error = True
                continue
        detection_yaml = object

        # enrich the mitre object
        mitre_attacks = []
        if 'mitre_attack_id' in detection_yaml['tags']:
            for mitre_technique_id in detection_yaml['tags']['mitre_attack_id']:
                mitre_attack = get_mitre_enrichment_new(attack, mitre_technique_id)
                mitre_attacks.append(mitre_attack)
            detection_yaml['mitre_attacks'] = mitre_attacks
        detection_yaml['kind'] = manifest_file.split('/')[-2]
        detections.append(detection_yaml)

    sorted_detections = sorted(detections, key=lambda i: i['name'])

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                             trim_blocks=False)

    # write markdown
    template = j2_env.get_template('doc_detections_markdown.j2')
    output_path = path.join(OUTPUT_DIR + '/detections.md')
    output = template.render(detections=sorted_detections)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote {0} detections documentation in markdown to: {1}".format(len(detections),output_path))

    #sort detections by kind into categories
    kinds = []
    kind_names = set()
    for detection in sorted_detections:
        kind_names.add(detection['kind'])

    for kind_name in sorted(kind_names):
        new_kind = {}
        new_kind['name'] = kind_name
        new_kind['detections'] = []
        kinds.append(new_kind)

    for detection in sorted_detections:
        for kind in kinds:
            if kind['name'] == detection['kind']:
                kind['detections'].append(detection)

    # write wikimarkup
    template = j2_env.get_template('doc_detections_wiki.j2')
    output_path = path.join(OUTPUT_DIR + '/detections.wiki')
    output = template.render(kinds=kinds)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote {0} detections documentation in mediawiki to: {1}".format(len(detections),output_path))

    return sorted_detections, messages
if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates documentation from Splunk Security Content", epilog="""
    This tool converts all Splunk Security Content detections, stories, workbooks and spec files into documentation. It builds both wiki markup (Splunk Docs) an markdown documentation.""")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory for the docs")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("-t", "--type", required=False, default="all", help="type of content to generate documentation for, supports `detections`, `stories`, `spec`, and `all`, defaults to `all`" )

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose
    type = args.type

    allowed_types = ['stories', 'detections', 'spec', 'all']
    if type not in allowed_types:
        print("ERROR: the type {0} is not support, the current support types are: {1}".format(type,allowed_types))
        parser.print_help()
        sys.exit(1)

    TEMPLATE_PATH = path.join(REPO_PATH, 'bin/jinja2_templates')

    if VERBOSE:
        print("getting mitre enrichment data from cti")
    attack = Attck()

    messages = []
    if type == 'all':
        sorted_detections, messages = generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, messages, VERBOSE)
        generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, sorted_detections, messages, VERBOSE)


    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")

#    stories = load_objects("stories/*.yml")
#    detections = []
#    detections = load_objects("detections/*/*.yml")
#    detections.extend(load_objects("detections/*/*/*.yml"))


    #story_count, path = write_splunk_docs(stories, detections, OUTPUT_DIR)
    #print("{0} story documents have been successfully written to {1}".format(story_count, path))
