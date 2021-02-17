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
    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)

    if type == 'detection':


        # write a detection example
        template = j2_env.get_template('detection.j2')
        detection_name = getpass.getuser() + '_' + type + '_example.yml'
        output_path = path.join(security_content_path, 'detections/endpoint/' + detection_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='Robert Johansson', name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example',
        description='Describe your detection the best way possible, if you need inspiration just look over others.',
        how_to_implement='How would a user implement this detection, describe any TAs, or specific configuration they might require',
        known_false_positives='Although unlikely, some legitimate applications may exhibit this behavior, triggering a false positive.',
        references=['https://wearebob.fandom.com/wiki/Bob','https://en.wikipedia.org/wiki/Dennis_E._Taylor'],
        datamodels=['Endpoint'], search='SPLUNKSPLGOESHERE | `' + getpass.getuser() + '_' + type + '_example_filter`',
        type='batch', analytic_story_name='STORY NAME GOES HERE', mitre_attack_id = 'T1003.01',
        kill_chain_phases=['Exploitation'], dataset_url='https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log',
        products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example detection to: {0}".format(output_path))

        # and a corresponding test files
        template = j2_env.get_template('test.j2')
        test_name = getpass.getuser() + '_' + type + '_example.test.yml'
        output_path = path.join(security_content_path, 'tests/endpoint/' + test_name)
        output = template.render(name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example Unit Test',
        detection_name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example',
        detection_path='detections/endpoint/' + detection_name, pass_condition='| stats count | where count > 0',
        earliest_time='-24h', latest_time='now', file_name='windows-sysmon.log', splunk_source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
        splunk_sourcetype='xmlwineventlog',dataset_url='https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log')
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example test for this detection to: {0}".format(output_path))

    elif type == 'story':
        # write a detection example
        template = j2_env.get_template('story.j2')
        story_name = getpass.getuser() + '_' + type + '_example.yml'
        output_path = path.join(security_content_path, 'stories/' + story_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='Robert Johansson', name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example',
        description='Describe your story the best way possible, if you need inspiration just look over others.',
        narrative='Explain why should a SOC manager or Director care about this use case, if you need inspiration just look over others.',
        references=['https://wearebob.fandom.com/wiki/Bob','https://en.wikipedia.org/wiki/Dennis_E._Taylor'],
        type='batch', analytic_story_name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Example',
        category=['Adversary Tactics'], usecase='Advanced Threat Detection', products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example story to: {0}".format(output_path))

def new(security_content_path, VERBOSE, type, example_only):

    valid_content_objects = ['detection','story']
    if type not in valid_content_objects:
        print("ERROR: content type: {0} is not valid, please use: {1}".format(type, str(valid_content_objects)))
        sys.exit(1)

    TEMPLATE_PATH = path.join(security_content_path, 'bin/jinja2_templates')

    if example_only:
        create_example(security_content_path,type, TEMPLATE_PATH)
