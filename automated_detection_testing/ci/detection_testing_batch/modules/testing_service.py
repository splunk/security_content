import re
import ansible_runner
import yaml
import uuid
import sys
import os
import time
import requests
from modules.DataManipulation import DataManipulation
from modules import splunk_sdk

from typing import Union
from os.path import relpath
from tempfile import mkdtemp


def test_detection_wrapper(container_name:str, splunk_ip:str, splunk_password:str, splunk_port:int, test_file:str, attack_data_root_folder, wait_on_failure:bool=False)->dict:
    
    uuid_var = str(uuid.uuid4())
    result_test = test_detection(splunk_ip, splunk_port, container_name, splunk_password, test_file, uuid_var, attack_data_root_folder)
    if result_test is None:
        #We failed so early in the process that we could not produce any meaningful result
        raise(Exception("Test execution Error"))    

    #enter = input("Run some tests from [%s] on [%s] - we don't delete until you hit enter :)"%(container_name, test_file))
    # delete test data
    search_string = result_test['detection_result']['search_string']
    
    #search failed if there was an error or the detection failed to produce the expected result
    if wait_on_failure and (result_test['detection_result']['error'] or not result_test['detection_result']['success']):
        wait_on_delete = True
    else:
        wait_on_delete = False
    
    splunk_sdk.delete_attack_data(splunk_ip, splunk_password, splunk_port, wait_on_delete, search_string, test_file)
   

    return result_test    


def test_detection(splunk_ip:str, splunk_port:int, container_name:str, splunk_password:str, test_file:str, uuid_var, attack_data_root_folder)->Union[dict,None]:
    
    test_file_obj = load_file(os.path.join("security_content/", test_file))
    
    
    if not test_file_obj:
        print("Not test_file_obj!")
        raise(Exception("No test file object found for [%s]"%(test_file)))
    #print(test_file_obj)

    # write entry dynamodb
    #aws_service.add_detection_results_in_dynamo_db('eu-central-1', uuid_var , uuid_test, test_file_obj['tests'][0]['name'], test_file_obj['tests'][0]['file'], str(int(time.time())))

    #epoch_time = str(int(time.time()))
    

    abs_folder_path = mkdtemp(prefix="DATA_", dir=attack_data_root_folder)
    #The ansible playbook wants the relative path, so we convert it as required
    folder_name = relpath(abs_folder_path, os.getcwd())

    for attack_data in test_file_obj['tests'][0]['attack_data']:
        url = attack_data['data']
        r = requests.get(url, allow_redirects=True)
        target_file = os.path.join(folder_name, attack_data['file_name'])
        with open(target_file, 'wb') as target:
            target.write(r.content)
        #print(target_file)

        # Update timestamps before replay
        if 'update_timestamp' in attack_data:
            if attack_data['update_timestamp'] == True:
                data_manipulation = DataManipulation()
                data_manipulation.manipulate_timestamp(target_file, attack_data['sourcetype'], attack_data['source'])
        replay_attack_dataset(container_name, splunk_password, folder_name, "main", attack_data['sourcetype'], attack_data['source'], attack_data['file_name'])
    
    #time.sleep(30)
    
    result_test = {}
    test = test_file_obj['tests'][0]
    
    if 'baselines' in test:
        results_baselines = []
        for baseline_obj in test['baselines']:
            baseline_file_name = baseline_obj['file']
            baseline = load_file(os.path.join(os.path.dirname(__file__), '../security_content', baseline_file_name))
            result_obj = dict()
            result_obj['baseline'] = baseline_obj['name']
            result_obj['baseline_file'] = baseline_obj['file']
            print("Making test_baseline_search request to: [%s:%d]"%(splunk_ip, splunk_port))
            result = splunk_sdk.test_baseline_search(splunk_ip, splunk_port, splunk_password, baseline['search'], baseline_obj['pass_condition'], baseline['name'], baseline_obj['file'], baseline_obj['earliest_time'], baseline_obj['latest_time'])
            #we don't seem to be doing anything with this loop... are we supposed to have the following line belwo?
            results_baselines.append(result)

        result_test['baselines_result'] = results_baselines  

    detection_file_name = test['file']
    detection = load_file(os.path.join(os.path.dirname(__file__), '../security_content/detections', detection_file_name))
    print("Making test_detection_search request to: [%s:%d]"%(splunk_ip, splunk_port))
    
    result_detection = splunk_sdk.test_detection_search(splunk_ip, splunk_port, splunk_password, detection['search'], test['pass_condition'], detection['name'], test['file'], test['earliest_time'], test['latest_time'])
    if result_detection['error']:
        print("There was an error running the search: %s"%(result_detection['search_string']))



    result_detection['detection_name'] = test['name']
    result_detection['detection_file'] = test['file']
    result_test['detection_result'] = result_detection
    result_test['attack_data_directory'] = abs_folder_path

    return result_test


def load_file(file_path):
    try:
        
        with open(file_path, 'r', encoding="utf-8") as stream:
            try:
                file = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                raise(Exception("ERROR: parsing YAML for {0}:[{1}]".format(file_path, str(exc))))
    except Exception as e:
        raise(Exception("ERROR: opening {0}:[{1}]".format(file_path, str(e))))
    return file


def update_ESCU_app(container_name, splunk_password):
    print("Update ESCU App. This can take some time")

    ansible_vars = {}
    ansible_vars['ansible_user'] = 'ansible_user'
    ansible_vars['splunk_password'] = splunk_password
    ansible_vars['security_content_path'] = 'security_content'
    
    cmdline = "--connection docker -i %s, -u %s" % (container_name, ansible_vars['ansible_user'])
    runner = ansible_runner.run(private_data_dir=os.path.join(os.path.dirname(__file__), '../'),
                                cmdline=cmdline,
                                roles_path=os.path.join(os.path.dirname(__file__), '../ansible/roles'),
                                playbook=os.path.join(os.path.dirname(__file__), '../ansible/update_escu.yml'),
                                extravars=ansible_vars)
    print("Successfully updated the ESCU App!")


def configure_splunk_vm(container_name, splunk_password):
    ansible_vars = {}
    ansible_vars['splunk_password'] = splunk_password
    ansible_vars['ansible_user'] = 'ansible'

    #BEGIN BLOCK VARS FROM ATTACK_RANGE_LOCAL.CONF
    splunk_url = "https://download.splunk.com/products/splunk/releases/8.0.2/linux/splunk-8.0.2-a7f645ddaf91-Linux-x86_64.tgz"
    # Specify the download URL of Splunk Enterprise

    splunk_binary = "splunk-8.0.2-a7f645ddaf91-Linux-x86_64.tgz"
    # Specify the name of the Splunk Enterprise executable

    s3_bucket_url = "https://attack-range-appbinaries.s3-us-west-2.amazonaws.com"
    # Specify the S3 bucket url from which you want to download the Splunk Apps

    splunk_windows_ta = "splunk-add-on-for-microsoft-windows_800.tgz"
    # Specify the Splunk Windows TA

    splunk_sysmon_ta = "splunk-add-on-for-microsoft-sysmon_1062.tgz"
    # Specify the Splunk Sysmon TA

    splunk_cim_app = "splunk-common-information-model-cim_4180.tgz"
    # Specify the Splunk CIM App

    splunk_escu_app = "DA-ESS-ContentUpdate-latest.tar.gz"
    # Specify the Splunk ESCU App

    splunk_asx_app = "Splunk_ASX-latest.tar.gz"
    # Specify the Splunk ASX App

    splunk_python_app = "python-for-scientific-computing-for-linux-64-bit_200.tgz"
    # Specify the Splunk python for scientific computing dependency that is needed by the MLTK app

    splunk_mltk_app = "splunk-machine-learning-toolkit_510.tgz"
    # Specify the Splunk MLTK App

    splunk_stream_app = "splunk-stream_720.tgz"
    # Specify the Splunk Stream App

    splunk_security_essentials_app = "splunk-security-essentials_310.tgz"
    # Specify the Splunk SSE App

    punchard_custom_visualization = "punchcard-custom-visualization_140.tgz"
    # Specify the Punchard Custom Visualization App

    status_indicator_custom_visualization = "status-indicator-custom-visualization_140.tgz"
    # Specify the Status Indicator Custom Visualization App

    splunk_attack_range_dashboard = "splunk_attack_range_reporting-1.0.5.tar.gz"
    # Specify the Attack Range Dashboard App

    timeline_custom_visualization = "timeline-custom-visualization_140.tgz"
    # Specify the Timeline Custom Visualization App

    splunk_aws_app = "splunk-add-on-for-amazon-web-services_500.tgz"
    # Specify the Splunk AWS App
    # Will be only installed when cloud_attack_range=1
    #END BLOCK VARS FROM ATTACK_RANGE_LOCAL.CONF



    splunk_es_app = 'splunk-enterprise-security_640.spl'
    splunk_es_app_version = re.findall(r'\d+', splunk_es_app)[0]

    #ansible_vars['ansible_python_interpreter'] = "/usr/bin/python3",
    ansible_vars['splunk_admin_password'] = splunk_password
    ansible_vars['splunk_url'] = splunk_url
    ansible_vars['splunk_binary'] = splunk_binary
    ansible_vars['s3_bucket_url'] = s3_bucket_url
    ansible_vars['splunk_escu_app'] = splunk_escu_app
    ansible_vars['splunk_asx_app'] = splunk_asx_app
    ansible_vars['splunk_windows_ta'] = splunk_windows_ta
    ansible_vars['splunk_cim_app'] = splunk_cim_app
    ansible_vars['splunk_sysmon_ta'] = splunk_sysmon_ta
    #ansible_vars['caldera_password'] = '{{ caldera_password }}'
    ansible_vars['splunk_mltk_app'] = splunk_mltk_app
    #ansible_vars['splunk_bots_dataset'] = '{{ splunk_bots_dataset }}'
    ansible_vars['splunk_stream_app'] = splunk_stream_app
    ansible_vars['splunk_python_app'] = splunk_python_app
    #ansible_vars['phantom_app'] = '{{ phantom_app }}'
    #ansible_vars['phantom_server'] = '{{ phantom_server }}'
    #ansible_vars['phantom_server_private_ip'] = '{{ phantom_server_private_ip }}'
    #ansible_vars['phantom_admin_password'] = '{{ phantom_admin_password }}'
    ansible_vars['splunk_security_essentials_app'] = splunk_security_essentials_app
    ansible_vars['punchard_custom_visualization'] = punchard_custom_visualization
    ansible_vars['status_indicator_custom_visualization'] = status_indicator_custom_visualization
    ansible_vars['splunk_attack_range_dashboard'] = splunk_attack_range_dashboard
    ansible_vars['timeline_custom_visualization'] = timeline_custom_visualization
    #ansible_vars['install_mission_control'] = install_mission_control
    #ansible_vars['mission_control_app'] = mission_control_app
    #ansible_vars['install_dsp'] = install_dsp
    #ansible_vars['dsp_client_cert_path'] = dsp_client_cert_path
    #ansible_vars['dsp_node'] = dsp_node
    ansible_vars['splunk_server_private_ip'] = "127.0.0.1"
    ansible_vars['cloud_attack_range'] = '0'

    ansible_vars['install_es'] = '1'
    ansible_vars['install_mltk'] = '0'
    ansible_vars['install_mission_control'] = '0'
    ansible_vars['install_dsp'] = '0'

    ansible_vars['splunk_es_app'] = splunk_es_app
    ansible_vars['splunk_es_app_version'] = splunk_es_app_version
    print(ansible_vars['splunk_es_app_version'])




    cmdline = "--connection docker -i %s, -u %s" % (container_name, ansible_vars['ansible_user'])
    runner = ansible_runner.run(private_data_dir=os.path.join(os.path.dirname(__file__), '../'),
                                cmdline=cmdline,
                                roles_path=os.path.join(os.path.dirname(__file__), '../ansible/roles'),
                                playbook=os.path.join(os.path.dirname(__file__), '../ansible/splunk_server.yml'),
                                extravars=ansible_vars)

def replay_attack_dataset(container_name, splunk_password, folder_name, index, sourcetype, source, out):
    ansible_vars = {}
    ansible_vars['folder_name'] = folder_name
    ansible_vars['ansible_user'] = 'ansible'
    ansible_vars['splunk_password'] = splunk_password
    ansible_vars['out'] = out
    ansible_vars['sourcetype'] = sourcetype
    ansible_vars['source'] = source
    ansible_vars['index'] = index

    cmdline = "--connection docker -i %s, -u %s" % (container_name, ansible_vars['ansible_user'])
    runner = ansible_runner.run(private_data_dir=os.path.join(os.path.dirname(__file__), '../'),
                                cmdline=cmdline,
                                roles_path=os.path.join(os.path.dirname(__file__), '../ansible/roles'),
                                playbook=os.path.join(os.path.dirname(__file__), '../ansible/attack_replay.yml'),
                                extravars=ansible_vars)

