#!/usr/bin/python

'''
Generates splunk configurations from manifest files under the security-content repo.
'''

import glob
import yaml
import argparse
from os import path
import sys
import datetime
from jinja2 import Environment, FileSystemLoader
import re


# global variables
REPO_PATH = ''
VERBOSE = False
OUTPUT_PATH = ''


def load_objects(file_path):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)

    for file in sorted(glob.glob(manifest_files)):
        files.append(load_file(file))

    return files


def load_file(file_path):
    with open(file_path, 'r') as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file


def generate_transforms_conf(lookups):
    sorted_lookups = sorted(lookups, key=lambda i: i['name'])

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('transforms.j2')
    output_path = OUTPUT_PATH + "/default/transforms.conf"
    output = template.render(lookups=sorted_lookups, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_savedsearches_conf(detections, response_tasks, baselines, deployments):

    for detection in detections:
        # parse out data_models
        data_model = parse_data_models_from_search(detection['search'])
        if data_model:
            detection['data_model'] = data_model

        matched_deployments = get_deployments(detection, deployments)
        if len(matched_deployments):
            detection['deployment'] = matched_deployments[-1]
            nes_fields = get_nes_fields(detection['search'], detection['deployment'])
            if len(nes_fields) > 0:
                detection['nes_fields'] = nes_fields

        keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
        mappings = {}
        for key in keys:
            if key == 'mitre_attack':
                if 'mitre_attack_id' in detection['tags']:
                    mappings[key] = detection['tags']['mitre_attack_id']
            else:
                if key in detection['tags']:
                    mappings[key] = detection['tags'][key]
        detection['mappings'] = mappings

    for baseline in baselines:
        data_model = parse_data_models_from_search(baseline['search'])
        if data_model:
            baseline['data_model'] = data_model

        matched_deployments = get_deployments(baseline, deployments)
        if len(matched_deployments):
            baseline['deployment'] = matched_deployments[-1]

    for response_task in response_tasks:
        if 'search' in response_task:
            data_model = parse_data_models_from_search(response_task['search'])
            if data_model:
                response_task['data_model'] = data_model

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    j2_env.filters['custom_jinja2_enrichment_filter'] = custom_jinja2_enrichment_filter
    template = j2_env.get_template('savedsearches.j2')
    output_path = OUTPUT_PATH + "/default/savedsearches.conf"
    output = template.render(detections=detections, baselines=baselines, response_tasks=response_tasks, time=utc_time)
    with open(output_path, 'w') as f:
        output = output.encode('ascii', 'ignore').decode('ascii')
        f.write(output)

    return output_path


def generate_analytics_story_conf(stories, detections, response_tasks):

    sto_det = map_detection_to_stories(detections)

    sto_res = map_response_tasks_to_stories(response_tasks)

    for story in stories:
        if story['name'] in sto_det:
            story['detections'] = list(sto_det[story['name']])
        if story['name'] in sto_res:
            story['response_tasks'] = list(sto_res[story['name']])

    stories = prepare_stories(stories, detections)

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('analytic_stories.j2')
    output_path = OUTPUT_PATH + "/default/analytic_stories.conf"
    output = template.render(stories=stories, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_use_case_library_conf(stories, detections, response_tasks, baselines):

    sto_det = map_detection_to_stories(detections)

    sto_res = map_response_tasks_to_stories(response_tasks)

    for story in stories:
        if story['name'] in sto_det:
            story['detections'] = list(sto_det[story['name']])
        if story['name'] in sto_res:
            story['response_tasks'] = list(sto_res[story['name']])
            story['searches'] = story['detections'] + story['response_tasks']
        else:
            story['searches'] = story['detections']

    for detection in detections:

        keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
        mappings = {}
        for key in keys:
            if key == 'mitre_attack':
                if 'mitre_attack_id' in detection['tags']:
                    mappings[key] = detection['tags']['mitre_attack_id']
            else:
                if key in detection['tags']:
                    mappings[key] = detection['tags'][key]
        detection['mappings'] = mappings

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('use_case_library.j2')
    output_path = OUTPUT_PATH + "/default/use_case_library.conf"
    output = template.render(stories=stories, detections=detections,
                             response_tasks=response_tasks,
                             baselines=baselines, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_macros_conf(macros, detections):
    filter_macros = []
    for detection in detections:
        new_dict = {}
        new_dict['definition'] = 'search *'
        new_dict['description'] = 'Update this macro to limit the output results to filter out false positives. '
        new_dict['name'] = detection['name']. \
            replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
        filter_macros.append(new_dict)

    all_macros = macros + filter_macros

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('macros.j2')
    output_path = OUTPUT_PATH + "/default/macros.conf"
    output = template.render(macros=all_macros, time=utc_time)
    with open(output_path, 'w') as f:
        f.write(output)

    return output_path


def generate_workbench_panels(response_tasks):
    workbench_panel_objects = []
    for response_task in response_tasks:
        if 'search' in response_task:
            if 'inputs' in response_task:
                response_file_name = response_task['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
                response_task['lowercase_name'] = response_file_name
                workbench_panel_objects.append(response_task)
                j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                                     trim_blocks=True)
                template = j2_env.get_template('panel.j2')
                output_path = OUTPUT_PATH + "/default/data/ui/panels/workbench_panel_" + response_file_name + ".xml"
                output = template.render(search=response_task['search'])
                with open(output_path, 'w') as f:
                    f.write(output)

    j2_env = Environment(loader=FileSystemLoader('bin/jinja2_templates'),
                         trim_blocks=True)
    template = j2_env.get_template('es_investigations.j2')
    output_path = OUTPUT_PATH + "/default/es_investigations.conf"
    output = template.render(response_tasks=workbench_panel_objects)
    with open(output_path, 'w') as f:
        f.write(output)


def parse_data_models_from_search(search):
    match = re.search(r'from\sdatamodel\s?=\s?([^\s.]*)', search)
    if match is not None:
        return match.group(1)
    return False


def get_deployments(object, deployments):
    matched_deployments = []

    for deployment in deployments:
        if 'analytics_story' in deployment['tags']:
            if type(deployment['tags']['analytics_story']) is str:
                tags_all_array = [deployment['tags']['analytics_story']]
            else:
                tags_all_array = deployment['tags']['analytics_story']
            if tags_all_array[0] == 'all':
                matched_deployments.append(deployment)
                continue

        for tag in object['tags'].keys():
            if tag in deployment['tags'].keys():
                if type(object['tags'][tag]) is str:
                    tag_array = [object['tags'][tag]]
                else:
                    tag_array = object['tags'][tag]

                for tag_value in tag_array:
                    if type(deployment['tags'][tag]) is str:
                        tag_array_deployment = [deployment['tags'][tag]]
                    else:
                        tag_array_deployment = deployment['tags'][tag]

                    for tag_value_deployment in tag_array_deployment:
                        if tag_value == tag_value_deployment:
                            matched_deployments.append(deployment)
                            continue

    return matched_deployments


def get_nes_fields(search, deployment):
    nes_fields_matches = []
    if 'notable' in deployment['alert_action']:
        if 'nes_fields' in deployment['alert_action']['notable']:
            for field in deployment['alert_action']['notable']['nes_fields']:
                if (search.find(field + ' ') != -1):
                    nes_fields_matches.append(field)

    return nes_fields_matches


def map_detection_to_stories(detections):
    sto_det = {}
    for detection in detections:
        if 'analytics_story' in detection['tags']:
            for story in detection['tags']['analytics_story']:
                if not (story in sto_det):
                    sto_det[story] = {str('ESCU - ' + detection['name'] + ' - Rule')}
                else:
                    sto_det[story].add(str('ESCU - ' + detection['name'] + ' - Rule'))
    return sto_det


def map_response_tasks_to_stories(response_tasks):
    sto_res = {}
    for response_task in response_tasks:
        if 'tags' in response_task:
            if 'analytics_story' in response_task['tags']:
                for story in response_task['tags']['analytics_story']:
                    if not (story in sto_res):
                        sto_res[story] = {str('ESCU - ' + response_task['name'])}
                    else:
                        sto_res[story].add(str('ESCU - ' + response_task['name']))
    return sto_res


def custom_jinja2_enrichment_filter(string, object):
    customized_string = string
    for key in object.keys():
        customized_string = customized_string.replace("%" + key + "%", str(object[key]))

    for key in object['tags'].keys():
        customized_string = customized_string.replace("%" + key + "%", str(object['tags'][key]))

    return customized_string


def prepare_stories(stories, detections):

    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases, nists
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_kill_chain_phases = {}
    sto_to_ciss = {}
    sto_to_nists = {}
    sto_to_det = {}
    for detection in detections:
        if 'analytics_story' in detection['tags']:
            for story in detection['tags']['analytics_story']:
                if story in sto_to_det.keys():
                    sto_to_det[story].add(str('ESCU - ' + detection['name'] + ' - Rule'))
                else:
                    sto_to_det[story] = {str('ESCU - ' + detection['name'] + ' - Rule')}

                data_model = parse_data_models_from_search(detection['search'])
                if data_model:
                    if story in sto_to_data_models.keys():
                        sto_to_data_models[story].add(data_model)
                    else:
                        sto_to_data_models[story] = {data_model}

                if 'mitre_attack_id' in detection['tags']:
                    if story in sto_to_mitre_attack_ids.keys():
                        for mitre_attack_id in detection['tags']['mitre_attack_id']:
                            sto_to_mitre_attack_ids[story].add(mitre_attack_id)
                    else:
                        for mitre_attack_id in detection['tags']['mitre_attack_id']:
                            sto_to_mitre_attack_ids[story] = {mitre_attack_id}

                if 'kill_chain_phases' in detection['tags']:
                    if story in sto_to_kill_chain_phases.keys():
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story].add(kill_chain)
                    else:
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story] = {kill_chain}

                if 'cis20' in detection['tags']:
                    if story in sto_to_ciss.keys():
                        for cis in detection['tags']['cis20']:
                            sto_to_ciss[story].add(cis)
                    else:
                        for cis in detection['tags']['cis20']:
                            sto_to_ciss[story] = {cis}

                if 'nist' in detection['tags']:
                    if story in sto_to_nists.keys():
                        for nist in detection['tags']['nist']:
                            sto_to_nists[story].add(nist)
                    else:
                        for nist in detection['tags']['nist']:
                            sto_to_nists[story] = {nist}

    for story in stories:
        story['detections'] = sorted(sto_to_det[story['name']])
        if story['name'] in sto_to_data_models:
            story['data_models'] = sorted(sto_to_data_models[story['name']])
        if story['name'] in sto_to_mitre_attack_ids:
            story['mitre_attack'] = sorted(sto_to_mitre_attack_ids[story['name']])
        if story['name'] in sto_to_kill_chain_phases:
            story['kill_chain_phases'] = sorted(sto_to_kill_chain_phases[story['name']])
        if story['name'] in sto_to_ciss:
            story['cis20'] = sorted(sto_to_ciss[story['name']])
        if story['name'] in sto_to_nists:
            story['nist'] = sorted(sto_to_nists[story['name']])

        keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
        mappings = {}
        for key in keys:
            if key in story:
                mappings[key] = story[key]

        story['mappings'] = mappings

    return stories


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="generates splunk conf files out of security-content manifests", epilog="""
    This tool converts manifests to the source files to be used by products like Splunk Enterprise.
    It generates the savesearches.conf, analytics_stories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security-content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_PATH = args.output
    VERBOSE = args.verbose
    stories = load_objects("stories/*.yml")
    macros = load_objects("macros/*.yml")
    lookups = load_objects("lookups/*.yml")
    baselines = load_objects("baselines/*.yml")
    detections = load_objects("detections/*.yml")
    responses = load_objects("responses/*.yml")
    response_tasks = load_objects("response_tasks/*.yml")
    deployments = load_objects("deployments/*.yml")

    lookups_path = generate_transforms_conf(lookups)

    detections = sorted(detections, key=lambda d: d['name'])
    response_tasks = sorted(response_tasks, key=lambda i: i['name'])
    baselines = sorted(baselines, key=lambda b: b['name'])
    detection_path = generate_savedsearches_conf(detections, response_tasks, baselines, deployments)

    stories = sorted(stories, key=lambda s: s['name'])
    story_path = generate_analytics_story_conf(stories, detections, response_tasks)

    use_case_lib_path = generate_use_case_library_conf(stories, detections, response_tasks, baselines)

    macros = sorted(macros, key=lambda m: m['name'])
    macros_path = generate_macros_conf(macros, detections)

    generate_workbench_panels(response_tasks)

    if VERBOSE:
        print("{0} stories have been successfully written to {1}".format(len(stories), story_path))
        print("{0} detections have been successfully written to {1}".format(len(detections), detection_path))
        print("{0} response tasks have been successfully written to {1}".format(len(response_tasks), detection_path))
        print("{0} baselines have been successfully written to {1}".format(len(baselines), detection_path))
        print("{0} macros have been successfully written to {1}".format(len(macros), macros_path))
        print("security content generation completed..")
