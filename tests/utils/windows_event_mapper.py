#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Created on 2021-06-01
# @author: jzadeh
#
# Licensed under the Apache License, Version 2.0 (the "License"): you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# Takes input of json file with named fields corresponding to active directory events
# and merges these with template events defined by attack range samples in /tests/util/data_templates
# the output is a set of events mapped to the template raw data
import argparse
import json

# this is the map to modify for replacement of field values from the input data to the output
input_output_map = {'CommandLine':'process_name', 'ParentBaseFileName':'parent_process_name'}

# some data sets are missing a full path of the process name for LOBLAS testing
process_name_default_prefix = 'C:\\Program Files\\'

# default paths
default_input_file = '/Users/jzadeh/Projects/TR-605-dll-detection-enhancements/security_content/tests/utils/data_templates/detection1_ad_events.json'
default_template_file = '/Users/jzadeh/Projects/TR-605-dll-detection-enhancements/security_content/tests/utils/data_templates/loblas_simple_template.json'

# command line workflow
parser = argparse.ArgumentParser(description='''\
        Script that takes input of json file with named fields corresponding to active directory events
        and merges these with template events defined by attack range samples in /tests/util/data_templates/
        and returns a set of formatted json events.''',
        usage='use "python3 %(prog)s --help" for more information',
        formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument('-i', '--input', default=default_input_file, type=str,
                    help='input json file')
parser.add_argument('-t', '--template', default=default_template_file, type=str,
                    help='raw event template samples used to generate output')
parser.add_argument('-o', '--output', default='generated_events.json', type=str,
                    help='json formatted event output')
parser.set_defaults(block=False, raw=False)
args = parser.parse_args()

# load the single line template data to parse
template_json = []
for line in open(args.template, 'r'):
    template_line = json.loads(line)
    template_json.append(template_line)

print(template_json)
# hack for bypassing extra value error with json not wrapped in list
# https://stackoverflow.com/questions/21058935/python-json-loads-shows-valueerror-extra-data
input_json = []
for line in open(args.input, 'r'):
    formatted_input_line = json.loads(line)

    # mix and merge the data
    for k, v in input_output_map.items():
       new_output_line = template_json
       # print(new_output_line)
       input_key = k
       output_key = v
       input_value = formatted_input_line.get(input_key)
       template_value = template_line.get(output_key)
       new_output_line[output_key][0] = input_value
       #print(new_output_line)


    # input_json.append(formatted_line)
    # for x in input_json:
    #     keys = x.keys()
    #     print(keys)
    #     values = x.values()
    #     print(values)

# grab our template for output
# template_json = json.load(args.template)
# print(template_json)


# for line in input_json:
#     for k, v in input_output_map.items():
#         print(k)
#         print(v)

