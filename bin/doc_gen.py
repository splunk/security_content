import glob
import yaml
import argparse
import sys
import re
from os import path, walk, remove
import json
from jinja2 import Environment, FileSystemLoader
import datetime
from stix2 import FileSystemSource
from stix2 import Filter
from pycvesearch import CVESearch

CVESSEARCH_API_URL = 'https://cve.circl.lu'


def load_objects(REPO_PATH, TYPE):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + '/' + TYPE):
        for file in files:
            if file.endswith(".yml") and root == './' + TYPE:
                manifest_files.append((path.join(root, file)))

    objects = []
    for manifest_file in manifest_files:
        object_yaml = dict()
        if VERBOSE:
            print("processing manifest {0}".format(manifest_file))

        with open(manifest_file, 'r') as stream:
            try:
                object = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                print("Error reading {0}".format(manifest_file))
                sys.exit(1)
        object_yaml = object
        objects.append(object_yaml)
    return objects
    
def generate_lookup_dict(lookups):
    lookup_dict = {}
    for lookup in lookups:
        lookup_dict[lookup['name']] = lookup

    return lookup_dict

def generate_macro_dict(macros):
    macro_dict = {}
    for macro in macros:
        macro_dict[macro['name']] = macro

    return macro_dict
    
def parse_and_add_macros(object, macros, lookups):
    macros_found = re.findall('\`([^\s]+)`', object['search'])
    macros_filtered = set()
    for macro in macros_found:
        if not 'cim_' in macro and not 'get_' in macro and not '_filter' in macro and not 'drop_dm_object_name' in macro:
            start = macro.find('(')
            if start != -1:
                macros_filtered.add(macro[:start])
            else:
                macros_filtered.add(macro)

    macro_objects = []
    for macro in list(macros_filtered):
        macro_lookups = parse_and_add_lookups(macros[macro]['definition'], lookups)
        if len(macro_lookups) > 0:
            macros[macro]['lookups'] = macro_lookups
        macro_objects.append(macros[macro])

    new_dict = {}
    new_dict['definition'] = 'search *'
    new_dict['description'] = 'Update this macro to limit the output results to filter out false positives. '
    new_dict['name'] = object['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
    macro_objects.append(new_dict)

    return macro_objects

def parse_and_add_lookups(search_string, lookups):
    lookups_found = re.findall('lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', search_string)
    lookup_objects = []
    for lookup in lookups_found:
        if lookup in lookups:
            lookup_obj = lookups[lookup]
            if not ('fields_list' in lookup_obj):
                csv_file_name = lookup_obj['filename']
                lookup_obj['csv_file_url'] = 'https://github.com/splunk/security_content/blob/develop/lookups/' + csv_file_name

            lookup_objects.append(lookup_obj)


    return lookup_objects


def get_cve_enrichment_new(cve_id):
    cve = CVESearch(CVESSEARCH_API_URL)
    result = cve.id(cve_id)
    cve_enriched = dict()
    cve_enriched['id'] = cve_id
    cve_enriched['cvss'] = result['cvss']
    cve_enriched['summary'] = result['summary']
    return cve_enriched

def get_all_techniques(projects_path):
    path_cti = path.join(projects_path,'cti/enterprise-attack')
    fs = FileSystemSource(path_cti)
    all_techniques = get_techniques(fs)
    return all_techniques

def get_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)

def mitre_attack_object(technique, attack):
    mitre_attack = dict()
    mitre_attack['technique_id'] = technique["external_references"][0]["external_id"]
    mitre_attack['technique'] = technique["name"]

    # process tactics
    tactics = []
    if 'kill_chain_phases' in technique:
        for tactic in technique['kill_chain_phases']:
            if tactic['kill_chain_name'] == 'mitre-attack':
                tactic = tactic['phase_name'].replace('-', ' ')
                tactics.append(tactic.title())

    mitre_attack['tactic'] = tactics
    return mitre_attack

def get_mitre_enrichment_new(attack, mitre_attack_id):
    for technique in attack:
        if mitre_attack_id == technique["external_references"][0]["external_id"]:
            mitre_attack = mitre_attack_object(technique, attack)
            return mitre_attack
    return []

def generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, sorted_detections, messages, VERBOSE):

    stories = load_objects(REPO_PATH, 'stories')
    sorted_stories = sorted(stories, key=lambda i: i['name'])

    # enrich stories with information from detections: data_models, mitre_ids, kill_chain_phases
    sto_to_data_models = {}
    sto_to_mitre_attack_ids = {}
    sto_to_mitre_attacks = {}
    sto_to_kill_chain_phases = {}
    sto_to_det = {}
    for detection in sorted_detections:
        if 'analytic_story' in detection['tags']:
            for story in detection['tags']['analytic_story']:
                if story in sto_to_det.keys():
                    sto_to_det[story]['detections'].append(detection)
                else:
                    sto_to_det[story] = {}
                    sto_to_det[story]['detections'] = []
                    sto_to_det[story]['detections'].append(detection)

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

                if 'mitre_attacks' in detection:
                        sto_to_mitre_attacks[story] = detection['mitre_attacks']

    # add the enrich objects to the story
    for story in sorted_stories:
        story['detections'] = sto_to_det[story['name']]['detections']
        if story['name'] in sto_to_data_models:
            story['data_models'] = sorted(sto_to_data_models[story['name']])
        if story['name'] in sto_to_mitre_attack_ids:
            story['mitre_attack_ids'] = sorted(sto_to_mitre_attack_ids[story['name']])
        if story['name'] in sto_to_mitre_attacks:
            story['mitre_attacks'] = sto_to_mitre_attacks[story['name']]
        if story['name'] in sto_to_kill_chain_phases:
            story['kill_chain_phases'] = sorted(sto_to_kill_chain_phases[story['name']])

    # sort stories into categories
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

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False)

    # write detection navigation
    # first collect datamodels and tactics
    datamodels = []
    tactics = []
    for detection in sorted_detections:
        data_model = detection['datamodel']
        if data_model:
            for d in data_model:
                if d not in datamodels:
                    datamodels.append(d)
        if 'mitre_attacks' in detection:
            for attack in detection['mitre_attacks']:
                for t in attack['tactic']:
                    if t not in tactics:
                        tactics.append(t)

    template = j2_env.get_template('doc_navigation.j2')
    output_path = path.join(OUTPUT_DIR + '/_data/navigation.yml')
    output = template.render(tactics=sorted(tactics), datamodels=sorted(datamodels), categories=sorted(category_names))
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote navigation.yml structure to: {0}".format(output_path))

    # write navigation _pages
    # for datamodels
    template = j2_env.get_template('doc_navigation_pages.j2')
    for datamodel in sorted(datamodels):
        output_path = path.join(OUTPUT_DIR + '/_pages/' + datamodel.lower().replace(" ", "_") + ".md")
        output = template.render(tag=datamodel)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, datamodel))
    # for tactics
    for tactic in sorted(tactics):
        output_path = path.join(OUTPUT_DIR + '/_pages/' + tactic.lower().replace(" ", "_") + ".md")
        output = template.render(tag=tactic)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {1} structure to: {0}".format(output_path, tactic))

    # for story categories
    template = j2_env.get_template('doc_navigation_story_pages.j2')
    for category in categories:
        output_path = path.join(OUTPUT_DIR + '/_pages/' + category['name'].lower().replace(" ", "_") + ".md")
        output = template.render(category=category)
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        messages.append("doc_gen.py wrote _page for: {0} structure to: {1}".format(category['name'], output_path))

    # write stories listing markdown
    template = j2_env.get_template('doc_story_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/stories.md')
    output = template.render(stories=sorted_stories)
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote _pages for story to: {0}".format(output_path))

    # write stories markdown
    template = j2_env.get_template('doc_stories.j2')
    for story in sorted_stories:
        file_name = story['name'].lower().replace(" ","_") + '.md'
        output_path = path.join(OUTPUT_DIR + '/_stories/' + file_name)
        output = template.render(story=story, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} story documentation in markdown to: {1}".format(len(sorted_stories),OUTPUT_DIR + '/_stories/'))

    return sorted_stories, messages


def generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, attack, messages, VERBOSE):
    types = ["endpoint", "application", "cloud", "network", "web", "experimental"]
    manifest_files = []
    for t in types:
        for root, dirs, files in walk(REPO_PATH + '/detections/' + t):
            for file in files:
                if file.endswith(".yml"):
                    manifest_files.append((path.join(root, file)))

    # load lookups and detection objects
    lookup_objects = load_objects(REPO_PATH, 'lookups')
    lookups = generate_lookup_dict(lookup_objects)
    macro_objects = load_objects(REPO_PATH, 'macros')
    macros = generate_macro_dict(macro_objects)

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
                sys.exit(1)
        detection_yaml = object

        # enrich the mitre object
        mitre_attacks = []
        if 'mitre_attack_id' in detection_yaml['tags']:
            for mitre_technique_id in detection_yaml['tags']['mitre_attack_id']:
                mitre_attack = get_mitre_enrichment_new(attack, mitre_technique_id)
                mitre_attacks.append(mitre_attack)
            detection_yaml['mitre_attacks'] = mitre_attacks

        # enrich the cve object
        cves = []
        if 'cve' in detection_yaml['tags']:
            for cve_id in detection_yaml['tags']['cve']:
                cve = get_cve_enrichment_new(cve_id)
                cves.append(cve)
            detection_yaml['cve'] = cves

        # enrich with macros
        detection_yaml['macros'] = parse_and_add_macros(detection_yaml, macros, lookups)

        # enrich with lookups
        detection_lookups = []
        #process lookups in macros first
        for macro in detection_yaml['macros']:
            if 'lookups' in macro:
                for macro_lookup in macro['lookups']:
                    detection_lookups.append(macro_lookup)
        # now any other search lookups
        additional_detection_lookups = parse_and_add_lookups(detection_yaml['search'], lookups)
        if len(additional_detection_lookups) > 0:
            for lookup in additional_detection_lookups:
                detection_lookups.append(lookup)
            detection_yaml['lookups'] = detection_lookups
        detection_yaml['lookups'] = detection_lookups
        
          # sort macros and lookups
        sorted_macros = sorted(detection_yaml['macros'], key=lambda i: i['name'])
        detection_yaml['macros'] = sorted_macros
        sorted_lookups = sorted(detection_yaml['lookups'], key=lambda i: i['name'])
        detection_yaml['lookups'] = sorted_lookups

        # sort macros and lookups
        sorted_macros = sorted(detection_yaml['macros'], key=lambda i: i['name'])
        detection_yaml['macros'] = sorted_macros
        sorted_lookups = sorted(detection_yaml['lookups'], key=lambda i: i['name'])
        detection_yaml['lookups'] = sorted_lookups

        # grab the kind
        detection_yaml['kind'] = manifest_file.split('/')[-2]

        # check if is experimental, add the flag
        if "experimental" == manifest_file.split('/')[2]:
            detection_yaml['experimental'] = True

        # skip baselines and Investigation
        if detection_yaml['type'] == 'Baseline' or detection_yaml['type'] == 'Investigation':
            continue
        else:
            detections.append(detection_yaml)

    # sort our detections
    sorted_detections = sorted(detections, key=lambda i: i['name'])

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                             trim_blocks=False, autoescape=True)

    # write markdown
    template = j2_env.get_template('doc_detections.j2')
    for detection in sorted_detections:
        file_name = detection['date'] + "-" + detection['name'].lower().replace(" ","_") + '.md'
        output_path = path.join(OUTPUT_DIR + '/_posts/' + file_name)
        output = template.render(detection=detection, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} detections documentation in markdown to: {1}".format(len(sorted_detections),OUTPUT_DIR + '/_posts/'))

    # write markdown detection page
    template = j2_env.get_template('doc_detection_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/detections.md')
    output = template.render(detections=sorted_detections, time=datetime.datetime.now())
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote detections.md page to: {0}".format(output_path))

    return sorted_detections, messages

def generate_doc_playbooks(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, messages, VERBOSE):
    manifest_files = []
    for root, dirs, files in walk(REPO_PATH + '/playbooks/'):
        for file in files:
            if file.endswith(".yml"):
                manifest_files.append((path.join(root, file)))

    playbooks = []
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
                sys.exit(1)

        playbooks.append(object)

    sorted_playbooks = sorted(playbooks, key=lambda i: i['name'])

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False, autoescape=True)

    # write markdown
    template = j2_env.get_template('doc_playbooks.j2')
    for playbook in sorted_playbooks:
        file_name = playbook['name'].lower().replace(" ","_") + '.md'
        output_path = path.join(OUTPUT_DIR + '/_playbooks/' + file_name)
        output = template.render(playbook=playbook, detections=sorted_detections, time=datetime.datetime.now())
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    messages.append("doc_gen.py wrote {0} playbook documentation in markdown to: {1}".format(len(sorted_playbooks),OUTPUT_DIR + '/_playbooks/'))

    # write markdown detection page
    template = j2_env.get_template('doc_playbooks_page.j2')
    output_path = path.join(OUTPUT_DIR + '/_pages/playbooks.md')
    output = template.render(playbooks=sorted_playbooks, detections=sorted_detections, time=datetime.datetime.now())
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote playbooks.md page to: {0}".format(output_path))

    return sorted_playbooks, messages


def generate_doc_index(OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, sorted_stories, sorted_playbooks, messages, VERBOSE):

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH), # nosemgrep
                             trim_blocks=False, autoescape=True)

    # write index updated metrics
    template = j2_env.get_template('doc_index.j2')
    output_path = path.join(OUTPUT_DIR + '/index.markdown')
    output = template.render(detection_count=len(sorted_detections), story_count=len(sorted_stories), playbook_count=len(sorted_playbooks))
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    messages.append("doc_gen.py wrote site index page to: {0}".format(output_path))

    return messages

if __name__ == "__main__":

    # grab arguments
    parser = argparse.ArgumentParser(description="Generates documentation from Splunk Security Content", epilog="""
    This generates documention in the form of jekyll site research.splunk.com from Splunk Security Content yamls. """)
    parser.add_argument("-p", "--path", required=True, help="path to security_content repo")
    parser.add_argument("-o", "--output", required=True, help="path to the output directory for the docs")
    parser.add_argument("-v", "--verbose", required=False, default=False, action='store_true', help="prints verbose output")


    # parse themgit stat
    args = parser.parse_args()
    REPO_PATH = args.path
    OUTPUT_DIR = args.output
    VERBOSE = args.verbose

    TEMPLATE_PATH = path.join(REPO_PATH, 'bin/jinja2_templates')

    if VERBOSE:
        print("getting mitre enrichment data from cti")
    techniques = get_all_techniques(REPO_PATH)

    if VERBOSE:
        print("wiping the {0}/_posts/* folder".format(OUTPUT_DIR))

    try:
        for root, dirs, files in walk(OUTPUT_DIR + '/_posts/'):
            for file in files:
                if file.endswith(".md"):
                    remove(OUTPUT_DIR + '/_posts/' + file)
    except OSError as e:
        print("error: %s : %s" % (file, e.strerror))
        sys.exit(1)

    messages = []
    sorted_detections, messages = generate_doc_detections(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, techniques, messages, VERBOSE)
    sorted_stories, messages = generate_doc_stories(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, techniques, sorted_detections, messages, VERBOSE)
    sorted_playbooks, messages = generate_doc_playbooks(REPO_PATH, OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, messages, VERBOSE)
    messages = generate_doc_index(OUTPUT_DIR, TEMPLATE_PATH, sorted_detections, sorted_stories, sorted_playbooks, messages, VERBOSE)

    # print all the messages from generation
    for m in messages:
        print(m)
    print("finished successfully!")
