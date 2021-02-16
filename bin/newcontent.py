#!/usr/bin/python

'''
Helps you create new Splunk Security Content.
'''

from pathlib import Path
from PyInquirer import prompt, Separator
import os
import getpass
from jinja2 import Environment, FileSystemLoader
import uuid
from datetime import date
from os import path


def create_example(security_content_path,type, TEMPLATE_PATH):
    getpass.getuser()

    if type == 'detection':
        j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                             trim_blocks=True)
        template = j2_env.get_template('detection.j2')
        example_name = getpass.getuser() + '_' + type + '_example.yml'
        output_path = path.join(security_content_path, 'detections/endpoint/' + example_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='Robert Johansson', name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example',
        description='Describe your detection the best way possible, if you need inspiration just look over others.',
        how_to_implement='How would a user implement this detection, describe any TAs, or specific configuration they might require',
        known_false_positives='Although unlikely, some legitimate applications may exhibit this behavior, triggering a false positive.',
        references=['https://wearebob.fandom.com/wiki/Bob','https://en.wikipedia.org/wiki/Dennis_E._Taylor'],
        datamodels=['Endpoint'], search='SPLUNKSPLv1GOESHERE | `' + getpass.getuser() + '_' + type + '_example_filter`',
        type='batch', analytic_story_name='Story Name Goes Here', mitre_attack_id = 'T0000.00',
        kill_chain_phases=['Exploitation'], dataset_url='https://github.com/splunk/attack_data/',
        products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example detection to: {0}".format(output_path))

def new(security_content_path, VERBOSE, type, example_only):

    valid_content_objects = ['detection','workbook','story']
    if type not in valid_content_objects:
        print("ERROR: content type: {0} is not valid, please use: {1}".format(type, str(valid_content_objects)))
        sys.exit(1)

    TEMPLATE_PATH = path.join(security_content_path, 'bin/jinja2_templates')

    if example_only:
        create_example(security_content_path,type, TEMPLATE_PATH)
