#!/usr/bin/python

'''
Generates splunk configurations from manifest files under the security_content repo.
'''

import glob
import yaml
import argparse
from os import path
import sys
import datetime
from jinja2 import Environment, FileSystemLoader
import re
from attackcti import attack_client
import csv
import shutil


def load_objects(file_path, VERBOSE, REPO_PATH):
    files = []
    manifest_files = path.join(path.expanduser(REPO_PATH), file_path)
    for file in sorted(glob.glob(manifest_files)):
        if VERBOSE:
            print("processing manifest: {0}".format(file))
        files.append(load_file(file))
    return files

def process_deprecated(file,file_path):
    DESCRIPTION_ANNOTATION = "WARNING, this detection has been marked deprecated by the Splunk Threat Research team, this means that it will no longer be maintained or supported. If you have any questions feel free to email us at: research@splunk.com. "
    if 'deprecated' in file_path:
        file['deprecated'] = True
        file['description'] = DESCRIPTION_ANNOTATION + file['description']
    return file

def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]

            # mark any files that have been deprecated
            file = process_deprecated(file,file_path)

        except yaml.YAMLError as exc:
            print(exc)
            sys.exit("ERROR: reading {0}".format(file_path))
    return file

def generate_lookup_files(lookups, TEMPLATE_PATH, OUTPUT_PATH,REPO_PATH):
    sorted_lookups = sorted(lookups, key=lambda i: i['name'])
    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()
    for i in sorted_lookups:
        for k,v in i.items():
            if k == 'filename':
                lookup_file = REPO_PATH +'/lookups/'+ v
                dist_lookup_dir = OUTPUT_PATH +'/lookups'
                shutil.copy(lookup_file,dist_lookup_dir)
    return sorted_lookups

def generate_transforms_conf(lookups, TEMPLATE_PATH, OUTPUT_PATH):
    sorted_lookups = sorted(lookups, key=lambda i: i['name'])

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('transforms.j2')
    output_path = path.join(OUTPUT_PATH, 'default/transforms.conf')
    output = template.render(lookups=sorted_lookups, time=utc_time)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return output_path

def generate_collections_conf(lookups, TEMPLATE_PATH, OUTPUT_PATH):
    filtered_lookups = list(filter(lambda i: 'collection' in i, lookups))
    sorted_lookups = sorted(filtered_lookups, key=lambda i: i['name'])

    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('collections.j2')
    output_path = path.join(OUTPUT_PATH, 'default/collections.conf')
    output = template.render(lookups=sorted_lookups, time=utc_time)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return output_path

def generate_savedsearches_conf(detections, response_tasks, baselines, deployments, TEMPLATE_PATH, OUTPUT_PATH):
    '''
    @param detections: input list of individual YAML detections in detections/ directory
    @param response_tasks:
    @param baselines:
    @param deployments:
    @return: the savedsearches.conf file located in package/default/
    '''


    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    j2_env.filters['custom_jinja2_enrichment_filter'] = custom_jinja2_enrichment_filter
    template = j2_env.get_template('savedsearches.j2')
    output_path = path.join(OUTPUT_PATH, 'default/savedsearches.conf')
    output = template.render(detections=detections, baselines=baselines, response_tasks=response_tasks, time=utc_time)
    with open(output_path, 'w') as f:
        output = output.encode('ascii', 'ignore').decode('ascii')
        f.write(output)

    return output_path

def generate_analytic_story_conf(stories, detections, response_tasks, baselines, TEMPLATE_PATH, OUTPUT_PATH):
    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('analytic_stories.j2')
    output_path = path.join(OUTPUT_PATH, 'default/analytic_stories.conf')
    output = template.render(stories=stories, time=utc_time)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return output_path

def generate_use_case_library_conf(stories, detections, response_tasks, baselines, TEMPLATE_PATH, OUTPUT_PATH):
    utc_time = datetime.datetime.utcnow().replace(microsecond=0).isoformat()

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('use_case_library.j2')
    output_path = path.join(OUTPUT_PATH, 'default/use_case_library.conf')
    output = template.render(stories=stories, detections=detections,
                             response_tasks=response_tasks,
                             baselines=baselines, time=utc_time)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return output_path

def generate_macros_conf(macros, detections, TEMPLATE_PATH, OUTPUT_PATH):
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

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('macros.j2')
    output_path = path.join(OUTPUT_PATH, 'default/macros.conf')
    output = template.render(macros=all_macros, time=utc_time)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return output_path

def generate_workbench_panels(response_tasks, stories, TEMPLATE_PATH, OUTPUT_PATH):
    workbench_panel_objects = []
    for response_task in response_tasks:
        if 'search' in response_task:
            if 'inputs' in response_task:
                response_file_name = response_task['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
                response_file_name_xml = response_file_name + "___response_task.xml"
                response_task['lowercase_name'] = response_file_name
                workbench_panel_objects.append(response_task)
                j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                                     trim_blocks=True)
                template = j2_env.get_template('panel.j2')
                file_path = "default/data/ui/panels/workbench_panel_" + response_file_name_xml
                output_path = path.join(OUTPUT_PATH, file_path)
                response_task['search']= response_task['search'].replace(">","&gt;")
                response_task['search']= response_task['search'].replace("<","&lt;")

                output = template.render(search=response_task['search'])
                with open(output_path, 'w') as f:
                    f.write(output)

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('es_investigations.j2')
    output_path = path.join(OUTPUT_PATH, 'default/es_investigations.conf')
    output = template.render(response_tasks=workbench_panel_objects, stories=stories)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)
    template = j2_env.get_template('workflow_actions.j2')
    output_path = path.join(OUTPUT_PATH, 'default/workflow_actions.conf')
    output = template.render(response_tasks=workbench_panel_objects)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)

    return workbench_panel_objects


def parse_data_models_from_search(search):
    match = re.search(r'from\sdatamodel\s?=\s?([^\s.]*)', search)
    if match is not None:
        return match.group(1)
    return False

def parse_author_company(story):
    match_author = re.search(r'^([^,]+)', story['author'])
    if match_author is None:
        match_author = 'no'
    else:
        match_author = match_author.group(1)

    match_company = re.search(r',\s?(.*)$', story['author'])
    if match_company is None:
        match_company = 'no'
    else:
        match_company = match_company.group(1)

    return match_author, match_company


def get_deployments(object, deployments):
    matched_deployments = []

    for deployment in deployments:

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
                            # print("tag value: {}, matched deployment tag: {} on deployment: {}".format(tag_value,tag_value_deployment, deployment))
                            matched_deployments.append(deployment)
                            continue

    # grab default for all stories if deployment not set
    if len(matched_deployments) == 0:
        for deployment in deployments:
            if 'analytic_story' in deployment['tags']:
                if deployment['tags']['analytic_story'] == 'all':
                    last_deployment = deployment
    else:
        last_deployment = matched_deployments[-1]
        # last_deployment = replace_vars_in_deployment(last_deployment, object) # Not needed because of custom_jinja2_enrichment_filter

    # print(last_deployment)
    return last_deployment

def get_nes_fields(search, deployment):
    nes_fields_matches = []
    if 'alert_action' in deployment:
        if 'notable' in deployment['alert_action']:
            if 'nes_fields' in deployment['alert_action']['notable']:
                for field in deployment['alert_action']['notable']['nes_fields']:
                    if (search.find(field + ' ') != -1):
                        nes_fields_matches.append(field)

    return nes_fields_matches


def map_response_tasks_to_stories(response_tasks):
    sto_res = {}
    for response_task in response_tasks:
        if 'tags' in response_task:
            if 'analytic_story' in response_task['tags']:
                for story in response_task['tags']['analytic_story']:
                    if 'type' in response_task.keys():
                        if response_task['type'] == 'response':
                            task_name = str('ESCU - ' + response_task['name'] + ' - Response Task')
                    else:
                        task_name = str('ESCU - ' + response_task['name'] + ' - Response Task')
                    if not (story in sto_res):
                        sto_res[story] = {task_name}
                    else:
                        sto_res[story].add(task_name)
    return sto_res

def map_baselines_to_stories(baselines):
    sto_bas = {}
    for baseline in baselines:
        if 'tags' in baseline:
            if 'analytic_story' in baseline['tags']:
                for story in baseline['tags']['analytic_story']:
                    if 'type' in baseline.keys():
                        if baseline['type'] == 'batch':
                            baseline_name = str('ESCU - ' + baseline['name'])
                    else:
                        baseline_name = str('ESCU - ' + baseline['name'])
                    if not (story in sto_bas):
                        sto_bas[story] = {baseline_name}
                    else:
                        sto_bas[story].add(baseline_name)
    return sto_bas

def custom_jinja2_enrichment_filter(string, object):
    customized_string = string
    for key in object.keys():
        [key.encode('utf-8') for key in object]
        customized_string = customized_string.replace("%" + key + "%", str(object[key]))

    for key in object['tags'].keys():
        customized_string = customized_string.replace("%" + key + "%", str(object['tags'][key]))

    return customized_string

def add_annotations(detection):
    # used for upstream processing of risk scoring annotations in ECSU
    # this is not currently compatible with newer instances of ESCU (6.3.0+)
    # we are duplicating the code block above for now and just changing variable names to make future
    # changes to this data structure separate from the mappings generation
    # @todo expose the JSON data structure for newer risk type

    annotation_keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist', 'analytic_story', 'observable', 'context', 'impact', 'confidence']
    savedsearch_annotations = {}
    for key in annotation_keys:
        if key == 'mitre_attack':
            if 'mitre_attack_id' in detection['tags']:
                savedsearch_annotations[key] = detection['tags']['mitre_attack_id']
        else:
            if key in detection['tags']:
                savedsearch_annotations[key] = detection['tags'][key]
    detection['savedsearch_annotations'] = savedsearch_annotations

    return detection

def add_rba(detection):

    # removed since this is causing a duplicate bug in ES 6.4+
    # if 'risk_object' in detection['tags']:
    #     detection['risk_object'] = detection['tags']['risk_object']
    # if 'risk_object_type' in detection['tags']:
    #    detection['risk_object_type'] = detection['tags']['risk_object_type']
    if 'risk_score' in detection['tags']:
        detection['risk_score'] = detection['tags']['risk_score']

    # grab risk message
    if 'message' in detection['tags']:
        detection['risk_message'] = detection['tags']['message']

    risk_objects = []
    risk_object_user_types = {'user', 'username', 'email address'}
    risk_object_system_types = {'device', 'endpoint', 'hostname', 'ip address'}
    if 'observable' in detection['tags']:
        # go through each obervable
        for entity in detection['tags']['observable']:
            risk_object = dict()

            # determine if is a user type
            if entity['type'].lower() in risk_object_user_types:
                risk_object['risk_object_type'] = 'user'
                detection['risk_object_type'] = 'user'
                for r in entity['role']:
                    if 'attacker' == r.lower():
                        # if the role is an attacker this entity is also a threat object
                        risk_object['threat_object_field'] = entity['name']
                        risk_object['threat_object_type'] = entity['type'].lower()
                        risk_objects.append(risk_object)

            # determine if is a system type
            elif entity['type'].lower() in risk_object_system_types:
                risk_object['risk_object_type'] = 'system'
                detection['risk_object_type'] = 'system'
                for r in entity['role']:
                    if 'attacker' == r.lower():
                        # if the role is an attacker this entity is also a threat object
                        risk_object['threat_object_field'] = entity['name']
                        risk_object['threat_object_type'] = entity['type'].lower()
                        risk_objects.append(risk_object)

            # if is not a system or user, it is a threat object
            else:
                risk_object['threat_object_field'] = entity['name']
                risk_object['threat_object_type'] = entity['type'].lower()
                risk_objects.append(risk_object)
                continue

            detection['risk_object'] = entity['name']
            risk_object['risk_object_field'] = entity['name']
            risk_object['risk_score'] = detection['risk_score']
            risk_objects.append(risk_object)
    detection['risk'] = risk_objects
    return detection

def prepare_detections(detections, deployments, OUTPUT_PATH):
    for detection in detections:
        # parse out data_models
        data_model = parse_data_models_from_search(detection['search'])
        if data_model:
            detection['data_model'] = data_model

        matched_deployment = get_deployments(detection, deployments)
        detection['deployment'] = matched_deployment
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

        detection = add_annotations(detection)
        detection = add_rba(detection)

        # add additional metadata
        if 'product' in detection['tags']:
            detection['product'] = detection['tags']['product']

        # turn all SAAWS detections
        if (OUTPUT_PATH) == 'dist/saaws':
            detection['disabled'] = 'false'

    return detections

def prepare_baselines(baselines, deployments, OUTPUT_PATH):
    for baseline in baselines:
        data_model = parse_data_models_from_search(baseline['search'])
        if data_model:
            baseline['data_model'] = data_model
        if (OUTPUT_PATH) == 'dist/saaws':
            baseline['disabled'] = 'false'

        matched_deployment = get_deployments(baseline, deployments)
        baseline['deployment'] = matched_deployment

    return baselines

def prepare_response_tasks(response_tasks):
    for response_task in response_tasks:
        if 'search' in response_task:
            data_model = parse_data_models_from_search(response_task['search'])
            if data_model:
                response_task['data_model'] = data_model

    return response_tasks

def prepare_stories(stories, detections, response_tasks, baselines):
    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases, nists
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_kill_chain_phases = {}
    sto_to_ciss = {}
    sto_to_nists = {}
    sto_to_det = {}
    for detection in detections:
        if 'analytic_story' in detection['tags']:
            for story in detection['tags']['analytic_story']:
                if 'type' in detection.keys():
                    if detection['type'] == 'batch':
                        rule_name = str('ESCU - ' + detection['name'] + ' - Rule')
                else:
                    rule_name = str('ESCU - ' + detection['name'] + ' - Rule')

                if story in sto_to_det.keys():
                    sto_to_det[story].add(rule_name)
                else:
                    sto_to_det[story] = {rule_name}

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
                        sto_to_mitre_attack_ids[story] = set(detection['tags']['mitre_attack_id'])

                if 'kill_chain_phases' in detection['tags']:
                    if story in sto_to_kill_chain_phases.keys():
                        for kill_chain in detection['tags']['kill_chain_phases']:
                            sto_to_kill_chain_phases[story].add(kill_chain)
                    else:
                        sto_to_kill_chain_phases[story] = set(detection['tags']['kill_chain_phases'])

                if 'cis20' in detection['tags']:
                    if story in sto_to_ciss.keys():
                        for cis in detection['tags']['cis20']:
                            sto_to_ciss[story].add(cis)
                    else:
                        sto_to_ciss[story] = set(detection['tags']['cis20'])

                if 'nist' in detection['tags']:
                    if story in sto_to_nists.keys():
                        for nist in detection['tags']['nist']:
                            sto_to_nists[story].add(nist)
                    else:
                        sto_to_nists[story] = set(detection['tags']['nist'])

    sto_res = map_response_tasks_to_stories(response_tasks)
    sto_bas = map_baselines_to_stories(baselines)

    for story in stories:
        story['author_name'], story['author_company'] = parse_author_company(story)
        story['lowercase_name'] = story['name'].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        story['detections'] = sorted(sto_to_det[story['name']])
        story['searches'] = story['detections']
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
        if story['name'] in sto_res:
            story['response_tasks'] = sorted(list(sto_res[story['name']]))
            story['searches'] = story['searches'] + story['response_tasks']
            story['workbench_panels'] = []
            for response_task_name in story['response_tasks']:
                s = 'panel://workbench_panel_' + response_task_name[7:].replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
                story['workbench_panels'].append(s)
        if story['name'] in sto_bas:
            story['baselines'] = sorted(list(sto_bas[story['name']]))


        keys = ['mitre_attack', 'kill_chain_phases', 'cis20', 'nist']
        mappings = {}
        for key in keys:
            if key in story:
                mappings[key] = story[key]

        story['mappings'] = mappings

    return stories


def generate_mitre_lookup(OUTPUT_PATH):

    csv_mitre_rows = [["mitre_id", "technique", "tactics", "groups"]]

    lift = attack_client()
    all_enterprise = lift.get_enterprise(stix_format=False)
    enterprise_relationships = lift.get_enterprise_relationships()
    enterprise_groups = lift.get_enterprise_groups()

    for technique in all_enterprise['techniques']:
        apt_groups = []
        for relationship in enterprise_relationships:
            if (relationship['target_ref'] == technique['id']) and relationship['source_ref'].startswith('intrusion-set'):
                for group in enterprise_groups:
                    if relationship['source_ref'] == group['id']:
                        apt_groups.append(group['name'])

        if not ('revoked' in technique):
            if len(apt_groups) == 0:
                apt_groups.append('no')
            csv_mitre_rows.append([technique['technique_id'], technique['technique'], '|'.join(technique['tactic']).replace('-',' ').title(), '|'.join(apt_groups)])

    with open(path.join(OUTPUT_PATH, 'lookups/mitre_enrichment.csv'), 'w', newline='', encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerows(csv_mitre_rows)


def import_objects(VERBOSE, REPO_PATH):
    objects = {
        "stories": load_objects("stories/*.yml", VERBOSE, REPO_PATH),
        "macros": load_objects("macros/*.yml", VERBOSE, REPO_PATH),
        "lookups": load_objects("lookups/*.yml", VERBOSE, REPO_PATH),
        "baselines": load_objects("baselines/*.yml", VERBOSE, REPO_PATH),
        "responses": load_objects("responses/*.yml", VERBOSE, REPO_PATH),
        "response_tasks": load_objects("response_tasks/*.yml", VERBOSE, REPO_PATH),
        "deployments": load_objects("deployments/*.yml", VERBOSE, REPO_PATH),
        "detections": load_objects("detections/*/*.yml", VERBOSE, REPO_PATH),
    }
    objects["detections"].extend(load_objects("detections/*/*/*.yml", VERBOSE, REPO_PATH))

    return objects

def compute_objects(objects, PRODUCT, OUTPUT_PATH):
    if PRODUCT == "SAAWS":
        objects["detections"]  = [object for object in objects["detections"]  if 'Splunk Security Analytics for AWS' in object['tags']['product']]
        objects["stories"] = [object for object in objects["stories"] if 'Splunk Security Analytics for AWS' in object['tags']['product']]
        objects["baselines"] = [object for object in objects["baselines"] if 'Splunk Security Analytics for AWS' in object['tags']['product']]
        objects["response_tasks"] = [object for object in objects["response_tasks"] if 'Splunk Security Analytics for AWS' in object['tags']['product']]

    # only use ESCU detections to the configurations
    objects["detections"] = sorted(filter(lambda d: d['type'].lower() == 'batch', objects["detections"]), key=lambda d: d['name'])
    # only use ESCU stories to the configuration
    objects["stories"] = sorted(filter(lambda s: s['type'].lower() == 'batch', objects["stories"]), key=lambda s: s['name'])

    objects["response_tasks"] = sorted(objects["response_tasks"], key=lambda i: i['name'])
    objects["baselines"] = sorted(objects["baselines"], key=lambda b: b['name'])
    objects["macros"] = sorted(objects["macros"], key=lambda m: m['name'])

    objects["detections"] = prepare_detections(objects["detections"], objects["deployments"], OUTPUT_PATH)
    objects["baselines"] = prepare_baselines(objects["baselines"], objects["deployments"], OUTPUT_PATH)
    objects["response_tasks"] = prepare_response_tasks(objects["response_tasks"])
    objects["stories"] = prepare_stories(objects["stories"], objects["detections"], objects["response_tasks"], objects["baselines"])

    return objects

def get_objects(REPO_PATH, OUTPUT_PATH, PRODUCT, VERBOSE):
    objects = import_objects(VERBOSE, REPO_PATH)
    objects = compute_objects(objects, PRODUCT, OUTPUT_PATH)
    return objects

def main(REPO_PATH, OUTPUT_PATH, PRODUCT, VERBOSE):

    TEMPLATE_PATH = path.join(REPO_PATH, 'bin/jinja2_templates')

    objects = get_objects(REPO_PATH, OUTPUT_PATH, PRODUCT, VERBOSE)

    try:
        if VERBOSE:
            print("generating Mitre lookups")
        generate_mitre_lookup(OUTPUT_PATH)
    except Exception as e:
        print('Error: ' + str(e))
        print("WARNING: Generation of Mitre lookup failed.")
        
    lookups_path = generate_transforms_conf(objects["lookups"], TEMPLATE_PATH, OUTPUT_PATH)
    lookups_path = generate_collections_conf(objects["lookups"], TEMPLATE_PATH, OUTPUT_PATH)
    lookups_files = generate_lookup_files(objects["lookups"], TEMPLATE_PATH, OUTPUT_PATH,REPO_PATH)

    detection_path = generate_savedsearches_conf(objects["detections"], objects["response_tasks"], objects["baselines"], objects["deployments"], TEMPLATE_PATH, OUTPUT_PATH)

    story_path = generate_analytic_story_conf(objects["stories"], objects["detections"], objects["response_tasks"], objects["baselines"], TEMPLATE_PATH, OUTPUT_PATH)

    use_case_lib_path = generate_use_case_library_conf(objects["stories"], objects["detections"], objects["response_tasks"], objects["baselines"], TEMPLATE_PATH, OUTPUT_PATH)

    macros_path = generate_macros_conf(objects["macros"], objects["detections"], TEMPLATE_PATH, OUTPUT_PATH)

    workbench_panels_objects = generate_workbench_panels(objects["response_tasks"], objects["stories"], TEMPLATE_PATH, OUTPUT_PATH)

    # calculate deprecation totals
    deprecated = []
    for d in objects['detections']:
        if 'deprecated' in d:
            deprecated.append(d)

    if VERBOSE:
        print("{0} stories have been successfully written to {1}".format(len(objects["stories"]), story_path))
        print("{0} detections have been successfully written to {1}".format(len(objects["detections"]), detection_path))
        print("{0} detections have been marked deprecated on {1}".format(len(deprecated), detection_path))
        print("{0} response tasks have been successfully written to {1}".format(len(objects["response_tasks"]), detection_path))
        print("{0} baselines have been successfully written to {1}".format(len(objects["baselines"]), detection_path))
        print("{0} macros have been successfully written to {1}".format(len(objects["macros"]), macros_path))
        print("{0} workbench panels have been successfully written to {1}, {2} and {3}".format(len(workbench_panels_objects), OUTPUT_PATH + "/default/es_investigations.conf", OUTPUT_PATH + "/default/workflow_actions.conf", OUTPUT_PATH + "/default/data/ui/panels/*"))
        print("security content generation completed..")


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="generates splunk conf files out of security_content manifests", epilog="""
    This tool converts manifests to the source files to be used by products like Splunk Enterprise.
    It generates the savesearches.conf, analytics_stories.conf files for ES.""")
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")
    parser.add_argument("--product", required=True, default="ESCU", help="package type")

    # parse them
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_PATH = args.output
    VERBOSE = args.verbose
    PRODUCT = args.product

    main(REPO_PATH, OUTPUT_PATH, PRODUCT, VERBOSE)