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


def detection_wizard(security_content_path,type,TEMPLATE_PATH):
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
            'message': 'enter detection name',
            'name': 'detection_name',
            'default': 'Powershell Encoded Command',
        },
        {
            'type': 'input',
            'message': 'enter author name',
            'name': 'detection_author',
        },
        {
            # get provider
            'type': 'list',
            'message': 'select a detection type',
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
            'default': '| UPDATE_SPL'
        },
        {
            # get api_key
            'type': 'input',
            'message': 'enter MITRE ATT&CK Technique IDs related to the detection, comma delimited for multiple',
            'name': 'mitre_attack_ids',
            'default': 'T1003.002'
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
            # get provider
            'type': 'list',
            'message': 'security_domain for detection',
            'name': 'security_domain',
            'choices': [
                {
                    'name': 'access'
                },
                {
                    'name': 'endpoint'
                },
                {
                    'name': 'network'
                },
                {
                    'name': 'threat'
                },
                {
                    'name': 'identity'
                },
                {
                    'name': 'audit'
                },

            ],
            'default': 'endpoint'
        },
    ]

    answers = prompt(questions)

    mitre_attack_id = [x.strip() for x in answers['mitre_attack_ids'].split(',')]

    print(mitre_attack_id)

    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                     trim_blocks=True)

    if answers['detection_type'] == 'batch':
        answers['products'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
    elif answers['detection_type'] == 'streaming':
        answers['products'] = ['Splunk Behavioral Analytics']

    # grab some vars for the test
    detection_kind = answers['detection_kind']


    # write a detection example
    template = j2_env.get_template('detection.j2')
    detection_name = answers['detection_name']
    detection_file_name =  detection_name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
    output_path = path.join(security_content_path, 'detections/' + detection_kind + '/' + detection_file_name + '.yml')
    output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
    author=answers['detection_author'], name=answers['detection_name'],
    description='UPDATE_DESCRIPTION', how_to_implement='UPDATE_HOW_TO_IMPLEMENT', known_false_positives='UPDATE_KNOWN_FALSE_POSITIVES',
    references='',datamodels=answers['datamodels'],
    search= answers['detection_search'] + ' | `' + detection_file_name + '_filter`',
    type=answers['detection_type'], analytic_story_name='UPDATE_STORY_NAME', mitre_attack_id=mitre_attack_id,
    kill_chain_phases=answers['kill_chain_phases'], dataset_url='UPDATE_DATASET_URL',
    products=answers['products'], security_domain=answers['security_domain'])
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
        earliest_time=answers['earliest_time'], latest_time=answers['latest_time'], file_name='UPDATE_FILE_NAME',
        splunk_source='UPDATE_SPLUNK_SOURCE',splunk_sourcetype='UPDATE_SPLUNK_SOURCETYPE',dataset_url='UPDATE_DATASET_URL')
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    else:
        # and a corresponding test files
        template = j2_env.get_template('test.j2')
        test_name = detection_file_name + '.test.yml'
        output_path = path.join(security_content_path, 'tests/' + detection_kind + '/' + test_name)
        output = template.render(name=detection_name + ' Unit Test',
        detection_name=detection_name,
        detection_path=detection_kind + '/' + detection_file_name + '.yml', pass_condition='| stats count | where count > 0',
        earliest_time='-24h', latest_time='now',file_name='UPDATE_FILE_NAME', splunk_source='UPDATE_SPLUNK_SOURCE',
        splunk_sourcetype='UPDATE_SPLUNK_SOURCETYPE', dataset_url='UPDATE_DATASET_URL' )
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
    print("\n> contentctl wrote the test for this detection to: {0}\n".format(output_path))

def story_wizard(security_content_path,type, TEMPLATE_PATH):
    questions = [
        {
            'type': 'input',
            'message': 'enter story name',
            'name': 'story_name',
            'default': 'Suspicious Powershell Behavior',
        },
        {
            'type': 'input',
            'message': 'enter author name',
            'name': 'story_author',
        },
        {
            'type': 'list',
            'message': 'select a story type',
            'name': 'story_type',
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
            'type': 'checkbox',
            'message': 'select a category',
            'name': 'category',
            'choices': [
                {
                    'name': 'Adversary Tactics',
                    'checked': True
                },
                {
                    'name': 'Account Compromise'
                },
                {
                    'name': 'Unauthorized Software'
                },
                {
                    'name': 'Best Practices'
                },
                {
                    'name': 'Cloud Security'
                },
                {
                    'name': 'Command and Control'
                },
                {
                    'name': 'Lateral Movement'
                },
                {
                    'name': 'Ransomware'
                },
                {
                    'name': 'Privilege Escalation'
                },
                ],
            },
            {
                # get provider
                'type': 'list',
                'message': 'select a use case',
                'name': 'usecase',
                'choices': [
                    {
                        'name': 'Advanced Threat Detection',
                        'checked': True
                    },
                    {
                        'name': 'Security Monitoring'
                    },
                    {
                        'name': 'Compliance'
                    },
                    {
                        'name': 'Insider Threat'
                    },
                    {
                        'name': 'Application Security'
                    },
                    {
                        'name': 'Other'
                    },
            ],
        },
    ]
    answers = prompt(questions)
    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                     trim_blocks=True)
    if answers['story_type'] == 'batch':
        answers['products'] = ['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud']
    elif answers['story_type'] == 'streaming':
        answers['products'] = ['Splunk Behavioral Analytics']

    template = j2_env.get_template('story.j2')
    story_name = answers['story_name']
    story_file_name =  story_name.replace(' ', '_').replace('-','_').replace('.','_').replace('/','_').lower()
    output_path = path.join(security_content_path, 'stories/' + story_file_name + '.yml')
    output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
    author=answers['story_author'], name=answers['story_name'], description='UPDATE_DESCRIPTION',
    narrative='UPDATE_NARRATIVE', references=['https://www.destroyallsoftware.com/talks/wat'],
    type=answers['story_type'], analytic_story_name=answers['story_name'],
    categories=answers['category'], usecase=answers['usecase'], products=answers['products'])
    with open(output_path, 'w', encoding="utf-8") as f:
        f.write(output)
    print("contentctl wrote a example story to: {0}".format(output_path))

def create_example(security_content_path,type, TEMPLATE_PATH):
    getpass.getuser()
    j2_env = Environment(loader=FileSystemLoader(TEMPLATE_PATH),
                         trim_blocks=True)

    if type == 'detection':


        # write a detection example
        template = j2_env.get_template('detection.j2')
        detection_name = getpass.getuser() + '_' + type + '.yml.example'
        output_path = path.join(security_content_path, 'detections/endpoint/' + detection_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='UPDATE_AUTHOR', name=getpass.getuser().capitalize() + ' ' + type.capitalize(),
        description='UPDATE_DESCRIPTION',
        how_to_implement='UPDATE_HOW_TO_IMPLENT',
        known_false_positives='UPDATE_KNOWN_FALSE_POSITIVES',
        references=['https://html5zombo.com/'],
        datamodels=['Endpoint'], search='| UPDATE_SPL | `' + getpass.getuser() + '_' + type + '_filter`',
        type='batch', analytic_story_name=' UPDATE_STORY_NAME', mitre_attack_id = 'T1003.01',
        kill_chain_phases=['Exploitation'], dataset_url='UPDATE_DATASET_URL',
        products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example detection to: {0}".format(output_path))

        # and a corresponding test files
        template = j2_env.get_template('test.j2')
        test_name = getpass.getuser() + '_' + type + '.test.yml.example'
        output_path = path.join(security_content_path, 'tests/endpoint/' + test_name)
        output = template.render(name=getpass.getuser().capitalize() + ' ' + type.capitalize() + ' Unit Test',
        detection_name=getpass.getuser().capitalize() + ' ' + type.capitalize(),
        detection_path='endpoint/' + detection_name, pass_condition='| stats count | where count > 0',
        earliest_time='-24h', latest_time='now', file_name='UPDATE_FILE_NAME', splunk_source='UPDATE_SPLUNK_SOURCE',
        splunk_sourcetype='UPDATE_SPLUNK_SOURCETYPE',dataset_url='UPDATE_DATASET_URL')
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example test for this detection to: {0}".format(output_path))

    elif type == 'story':
        # write a story example
        template = j2_env.get_template('story.j2')
        story_name = getpass.getuser() + '_' + type + '.yml.example'
        output_path = path.join(security_content_path, 'stories/' + story_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='UPDATE_AUTHOR', name=getpass.getuser().capitalize() + ' ' + type.capitalize(),
        description='UPDATE_DESCRIPTION',
        narrative='UPDATE_NARRATIVE',
        references=['https://www.destroyallsoftware.com/talks/wat'],
        type='batch', analytic_story_name=getpass.getuser().capitalize() + ' ' + type.capitalize(),
        categories=['Adversary Tactics'], usecase='Advanced Threat Detection', products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example story to: {0}".format(output_path))

    elif type == 'baseline':
        # write a baseline example
        template = j2_env.get_template('baseline.j2')
        baseline_name = getpass.getuser() + '_' + type + '.yml.example'
        output_path = path.join(security_content_path, 'baselines/' + baseline_name)
        output = template.render(uuid=uuid.uuid1(), date=date.today().strftime('%Y-%m-%d'),
        author='UPDATE_AUTHOR', name=getpass.getuser().capitalize() + ' ' + type.capitalize(),
        description='UPDATE_DESCRIPTION',
        how_to_implement='UPDATE_HOW_TO_IMPLENT',
        known_false_positives='UPDATE_KNOWN_FALSE_POSITIVES',
        references=['https://html5zombo.com/'],
        datamodels=['Endpoint'], search='| UPDATE_SPL',
        type='batch', analytic_story_name='UPDATE_STORY_NAME',
        detection_name = 'UPDATE_DETECTION_NAME', dataset_url='UPDATE_DATASET_URL',
        products=['Splunk Enterprise','Splunk Enterprise Security','Splunk Cloud'])
        with open(output_path, 'w', encoding="utf-8") as f:
            f.write(output)
        print("contentctl wrote a example baseline to: {0}".format(output_path))


def new(security_content_path, VERBOSE, type, example_only):

    valid_content_objects = ['detection','story', 'baseline']
    if type not in valid_content_objects:
        print("ERROR: content type: {0} is not valid, please use: {1}".format(type, str(valid_content_objects)))
        sys.exit(1)

    TEMPLATE_PATH = path.join(security_content_path, 'bin/jinja2_templates')

    if example_only:
        create_example(security_content_path,type, TEMPLATE_PATH)
        sys.exit(0)

    if type == 'detection':
        detection_wizard(security_content_path, type, TEMPLATE_PATH)
    elif type == 'story':
        story_wizard(security_content_path, type, TEMPLATE_PATH)

    print("WARNING do not forget to replace the UPDATE_* values with the correct information on the files!\ncompleted..")
