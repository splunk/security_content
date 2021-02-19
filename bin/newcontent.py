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
import sys


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
        sys.exit(0)


    if type == 'detection':
        questions = [
            {
                # get provider
                'type': 'list',
                'message': 'what kind of detection is this',
                'name': 'detection_kind',
                'choices': [
                    {
                        'name': 'endpoint'
                    },
                    {
                        'name': 'cloud'
                    },
                    {
                        'name': 'application'
                    },
                    {
                        'name': 'network'
                    },
                    {
                        'name': 'web'
                    },
                    {
                        'name': 'experimental'
                    },

                ],
                'default': 'endpoint'
            },
            {
                'type': 'input',
                'message': 'enter detection name (Suspicious MSHTA)',
                'name': 'detection_name',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter author name',
                'name': 'detection_author',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter detection description, Markdown is `supported`',
                'name': 'detection_description',
            },
            {
                # get provider
                'type': 'list',
                'message': 'select a detection type (see type details here: https://wiki)',
                'name': 'detection_type',
                'choices': [
                    {
                        'name': 'batch'
                    },
                    {
                        'name': 'streaming'
                    },
                ],
                'default': 'batch'
            },
            {
                # get provider
                'type': 'checkbox',
                'message': 'select the datamodels used in the detection',
                'name': 'datamodels',
                'choices': [
                    {
                        'name': 'Endpoint',
                        'checked': True
                    },
                    {
                        'name': 'Network_Traffic'
                    },
                    {
                        'name': 'Authentication'
                    },
                    {
                        'name': 'Change'
                    },
                    {
                        'name': 'Change_Analysis'
                    },
                    {
                        'name': 'Email'
                    },
                    {
                        'name': 'Network_Resolution'
                    },
                    {
                        'name': 'Network_Traffic'
                    },
                    {
                        'name': 'Network_Sessions'
                    },
                    {
                        'name': 'Updates'
                    },
                    {
                        'name': 'Vulnerabilities'
                    },
                    {
                        'name': 'Web'
                    },
                ],
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter search (spl)',
                'name': 'detection_search',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter a steps how to implement the detection',
                'name': 'how_to_implement',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter any known false positives',
                'name': 'know_false_positives',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter references (urls) the give context to the detection, comma delimited for multiple',
                'name': 'references',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter associated Splunk Analytic Story, comma delimited for multiple',
                'name': 'detection_stories',
            },
            {
                # get api_key
                'type': 'input',
                'message': 'enter MITRE ATT&CK Technique related to the detection, comma delimited for multiple',
                'name': 'mitre_attack_ids',
            },
            {
                # get provider
                'type': 'checkbox',
                'message': 'select kill chain phases related to the detection',
                'name': 'kill_chain_phases',
                'choices': [

                    {
                        'name': 'Reconnaissance'
                    },
                    {
                        'name': 'Intrusion'
                    },
                    {
                        'name': 'Exploitation',
                        'checked': True
                    },
                    {
                        'name': 'Privilege Escalation'
                    },
                    {
                        'name': 'Lateral Movement'
                    },
                    {
                        'name': 'Obfuscation'
                    },
                    {
                        'name': 'Denial of Service'
                    },
                    {
                        'name': 'Exfiltration'
                    },
                ],
            },

            {
                # get api_key
                'type': 'input',
                'message': 'enter attack_data dataset url used for detection testing.',
                'name': 'dataset_url',
            },



        ]

        answers = prompt(questions)
        mitre_attack_id = answers['mitre_attack_ids'].split(',')
        j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)

        if answers['detection_type'] == 'batch':
            answers['products'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
        elif answers['detection_type'] == 'streaming':
            answers['products'] = ['UEBA for Security Cloud']

        # grab some vars for the test
        detection_dataset_url = answers['dataset_url']
        detection_kind = answers['detection_kind']


        # write a detection example
        template = j2_env.get_template('detection.j2')
        detection_name = answers['detection_name']
        detection_file_name =  detection_name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
        output_path = path.join(security_content_path, 'detections/' + detection_kind + '/' + detection_file_name + '.yml')
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author=answers['detection_author'], name=answers['detection_name'],
        description=answers['detection_description'], how_to_implement=answers['how_to_implement'], known_false_positives=answers['know_false_positives'],
        references=answers['references'].split(","),datamodels=answers['datamodels'],
        search= answers['detection_search'] + ' | ' + detection_file_name + '_filter',
        type=answers['detection_type'], analytic_story_name=answers['detection_stories'].split(','), mitre_attack_id = answers['mitre_attack_ids'].split(','),
        kill_chain_phases=answers['kill_chain_phases'], dataset_url=detection_dataset_url,
        products=answers['products'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)

        print("\n> contentctl wrote the detection to: {0}\n".format(output_path))

        questions = [
            {
                'type': 'confirm',
                'message': 'would you like to configure the test file for detection: {0}'.format(answers['detection_name']),
                'name': 'continue',
                'default': True,
            },
            {
                'type': 'input',
                'message': 'enter pass condition for the test of detection: {0}'.format(answers['detection_name']),
                'name': 'pass_condition',
                'default': '| stats count | where count > 0',
                'when': lambda answers: answers['continue'],
            },
            {
                'type': 'input',
                'message': 'enter earliest_time for the test of detection: {0}'.format(answers['detection_name']),
                'name': 'earliest_time',
                'default': '-24h',
                'when': lambda answers: answers['continue'],
            },
            {
                'type': 'input',
                'message': 'enter latest_time for the test of detection: {0}'.format(answers['detection_name']),
                'name': 'latest_time',
                'default': 'now',
                'when': lambda answers: answers['continue'],
            },
            {
                'type': 'input',
                'message': 'enter the file_name of attack_data dataset file',
                'name': 'file_name',
                'default': 'windows-sysmon.log',
                'when': lambda answers: answers['continue'],
            },
            {
                'type': 'input',
                'message': 'enter the Splunk source used in the dataset file',
                'name': 'splunk_source',
                'default': 'XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',
                'when': lambda answers: answers['continue'],
            },
            {
                'type': 'input',
                'message': 'enter the Splunk sourcetype used in the dataset file',
                'name': 'splunk_sourcetype',
                'default': 'xmlwineventlog',
                'when': lambda answers: answers['continue'],
            },
        ]


        answers = prompt(questions)
        if answers['continue']:
            # and a corresponding test files
            template = j2_env.get_template('test.j2')
            test_name = detection_file_name + '.test.yml'
            output_path = path.join(security_content_path, 'tests/' + detection_kind + '/' + test_name)
            output = template.render(name=detection_name + ' Unit Test',
            detection_name=detection_name,
            detection_path='detections/' + detection_kind + '/' + detection_file_name + '.yml', pass_condition=answers['pass_condition'],
            earliest_time=answers['earliest_time'], latest_time=answers['latest_time'], file_name=answers['file_name'],
            splunk_source=answers['splunk_source'],splunk_sourcetype=answers['splunk_sourcetype'],dataset_url=detection_dataset_url)
            with open(output_path, 'w', encoding="utf-8") as f:
                f.write(output)
        else:
            # and a corresponding test files
            template = j2_env.get_template('test.j2')
            test_name = detection_file_name + '.test.yml'
            output_path = path.join(security_content_path, 'tests/' + detection_kind + '/' + test_name)
            output = template.render(name=detection_name + ' Unit Test',
            detection_name=detection_name,
            detection_path='detections/' + detection_kind + '/' + detection_file_name + '.yml', pass_condition='| stats count | where count > 0',
            earliest_time='-24h', latest_time='now', file_name='windows-sysmon.log',
            splunk_source='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational',splunk_sourcetype='xmlwineventlog',dataset_url=detection_dataset_url)
            with open(output_path, 'w', encoding="utf-8") as f:
                f.write(output)
        print("\n> contentctl wrote the test for this detection to: {0}\n".format(output_path))
