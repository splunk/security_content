import yaml, json
import csv
from io import StringIO
import re
import os
import shutil

class Yaml2Json():
    '''
    Yaml2Json is a logical port of security-content-api > chalicelib > data_mapper.py
    This module processes YAML files directly within the repo and outputs consolidated JSON.
    '''
    def __init__(self, type, repo_path=None):

        self.repo_path = repo_path

        if type == 'detections' or type == 'stories':
            lookup_objects = self.load_objects('lookups')
            self.lookups = self.generate_lookup_dict(lookup_objects)
            macro_objects = self.load_objects('macros')
            self.macros = self.generate_macro_dict(macro_objects)
            self.baselines = self.load_objects('baselines')
            self.bas_det = self.map_baseline_to_detection(self.baselines)
            self.mitre_enrichment = self.load_mitre_lookup(type)

        if type == 'stories':
            self.detections = self.load_objects('detections')
            self.det_sto = self.map_detection_to_story(self.detections)

        if type == 'baselines':
            macro_objects = self.load_objects('macros')
            self.macros = self.generate_macro_dict(macro_objects)
            lookup_objects = self.load_objects('lookups')
            self.lookups = self.generate_lookup_dict(lookup_objects)

        if type == 'macros':
            lookup_objects = self.load_objects('lookups')
            self.lookups = self.generate_lookup_dict(lookup_objects)


    def get_repo_dir(self):
        if not self.repo_path:
            # this file typically resides in '\bin' one level below the repo
            return os.path.join(os.path.dirname(__file__), '../')
        else:
            return os.path.abspath(self.repo_path)


    def get_type_dir(self, type):
        type_dir_name = str.lower(type)
        return os.path.join(self.get_repo_dir(), type)


    def list_objects(self, type):
        objects = self.load_objects(type)
        total = len(objects)
        content = {type:objects, 'count':total}

        return content


    def load_objects(self, type):

        type_dir = self.get_type_dir(type)
        file_paths = []

        for root, dirnames, filenames in os.walk(type_dir):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                if not 'deprecated' in filepath:
                    filename_w_ext = os.path.basename(filepath)
                    filename, file_extension = os.path.splitext(filename_w_ext)
                    if filename != "" and file_extension == '.yml':
                        file_paths.append(filepath)

        objects = []
        for file_path in file_paths:
            object = self.load_object(file_path, type)
            if object:
                objects.append(object)

        return objects


    def load_object(self, file_path, type):

        with open(file_path, 'r') as stream:
            try:
                file = yaml.safe_load(stream)
            except:
                raise

        # enrich story with detections and responses
        if type == 'stories':
            if not 'type' in file:
                file['type'] = ''

            if file['name'] in self.det_sto:
                file['detections'] = self.det_sto[file['name']]
            else:
                file['detections'] = []
            mitre_attack_id_set = set()
            mitre_attack_technique_set = set()
            mitre_attack_tactics_set = set()
            mitre_attack_groups_set = set()
            for detection in file['detections']:
                if 'tags' in detection:
                    if 'mitre_attack_id' in detection['tags']:
                        mitre_attack_id_set.update(detection['tags']['mitre_attack_id'])
                    if 'mitre_attack_technique' in detection['tags']:
                        mitre_attack_technique_set.update(detection['tags']['mitre_attack_technique'])
                    if 'mitre_attack_tactics' in detection['tags']:
                        mitre_attack_tactics_set.update(detection['tags']['mitre_attack_tactics'])
                    if 'mitre_attack_groups' in detection['tags']:
                        mitre_attack_groups_set.update(detection['tags']['mitre_attack_groups'])
            file['tags']['mitre_attack_id'] = list(mitre_attack_id_set)
            file['tags']['mitre_attack_technique'] = list(mitre_attack_technique_set)
            file['tags']['mitre_attack_tactics'] = list(mitre_attack_tactics_set)
            file['tags']['mitre_attack_groups'] = list(mitre_attack_groups_set)

        # enrich detections with baselines and macros
        if type == 'detections':
            if file['type'] == 'Baseline' or file['type'] == 'Investigation':
                return None
            if file['name'] in self.bas_det:
                file['baselines'] = self.bas_det[file['name']]
            if file['type'] != 'SSA':
                file['macros'] = self.parse_and_add_macros(file)
                lookups = self.parse_and_add_lookups(file['search'])
                if len(lookups) > 0:
                    file['lookups'] = lookups
            technique_array = []
            tactics_array = []
            groups_array = []
            if 'tags' in file:
                if 'mitre_attack_id' in file['tags']:
                    for mitre_attack_id in file['tags']['mitre_attack_id']:
                        if mitre_attack_id in self.mitre_enrichment:
                            obj = self.mitre_enrichment[mitre_attack_id]
                            technique_array.append(obj[0])
                            tactics_array.extend(obj[1])
                            groups_array.extend(obj[2])
            file['tags']['mitre_attack_technique'] = technique_array
            file['tags']['mitre_attack_tactics'] = tactics_array
            file['tags']['mitre_attack_groups'] = groups_array

        if type == 'baselines':
            file['macros'] = self.parse_and_add_macros(file)
            lookups = self.parse_and_add_lookups(file['search'])
            if len(lookups) > 0:
                file['lookups'] = lookups

        return file


    def load_mitre_lookup(self, type):

        with open(os.path.join(self.get_repo_dir(), 'lookups', 'mitre_enrichment.csv')) as csv_file:

            try:
                mitre_enrichment = {}
                reader = csv.DictReader(csv_file)
                for row in reader:
                    mitre_enrichment[row['mitre_id']] = [row['technique'], row['tactics'].split('|'), row['groups'].split('|')]
            except:
                raise

        return mitre_enrichment


    def get_file_name(self, input_str):
        file_name = input_str.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        return file_name


    def map_baseline_to_detection(self, baselines):
        bas_det = dict()
        for baseline in baselines:
            if 'tags' in baseline:
                if 'detections' in baseline['tags']:
                    for detection in baseline['tags']['detections']:
                        if not (detection in bas_det):
                            bas_det[detection] = [baseline]
                        else:
                            bas_det[detection].append(baseline)
        return bas_det


    def map_detection_to_story(self, detections):
        det_sto = dict()
        for detection in detections:
            if 'tags' in detection:
                if 'analytic_story' in detection['tags']:
                    for story in detection['tags']['analytic_story']:
                        if not (story in det_sto):
                            det_sto[story] = [detection]
                        else:
                            det_sto[story].append(detection)
        return det_sto


    def generate_macro_dict(self, macros):
        macro_dict = {}
        for macro in macros:
            macro_dict[macro['name']] = macro

        return macro_dict

    def generate_lookup_dict(self, lookups):
        lookup_dict = {}
        for lookup in lookups:
            lookup_dict[lookup['name']] = lookup

        return lookup_dict


    def parse_and_add_macros(self, object):
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
            lookups = self.parse_and_add_lookups(self.macros[macro]['definition'])
            if len(lookups) > 0:
                self.macros[macro]['lookups'] = lookups
            macro_objects.append(self.macros[macro])

        new_dict = {}
        new_dict['definition'] = 'search *'
        new_dict['description'] = 'Update this macro to limit the output results to filter out false positives. '
        new_dict['name'] = object['name'].replace(' ', '_').replace('-', '_').replace('.', '_').replace('/', '_').lower() + '_filter'
        macro_objects.append(new_dict)

        return macro_objects

    def parse_and_add_lookups(self, search_string):
        lookups_found = re.findall('lookup (?:update=true)?(?:append=t)?\s*([^\s]*)', search_string)
        lookup_objects = []
        for lookup in lookups_found:
            if lookup in self.lookups:
                lookup_obj = self.lookups[lookup]
                if not ('fields_list' in lookup_obj):
                    csv_file_name = lookup_obj['filename']
                    lookup_obj['csv_file_url'] = 'https://security-content.s3-us-west-2.amazonaws.com/lookups/' + csv_file_name

                lookup_objects.append(lookup_obj)

        return lookup_objects


if __name__ == "__main__":
    json_types = []
    # List of all YAML types to search in repo
    yml_types = ['detections', 'baselines', 'lookups', 'macros', 'response_tasks', 'responses', 'stories', 'deployments']
    # output directory name will be same as this filename
    output_dir = os.path.splitext(os.path.basename(__file__))[0]
    print("JSON output directory: " + output_dir)
    # remove any pre-existing output directories
    shutil.rmtree(output_dir, ignore_errors=True)
    print("Remove pre-existing JSON directory")
    # create output directory
    os.mkdir(output_dir)
    print("Created output directory")
    # Generate all YAML types
    for yt in yml_types:
        processor = Yaml2Json(yt)
        with open(os.path.join(output_dir, yt + '.json'), 'w') as json_out:
            # write out YAML type
            json.dump(processor.list_objects(yt), json_out)
            print("Writing %s JSON" % yt)
