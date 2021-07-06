
import ansible_runner
import yaml
import uuid
import sys
import os
import time
import requests
import re
import csv
import boto3
from botocore.exceptions import ClientError
from modules.DataManipulation import DataManipulation
from modules import splunk_sdk, aws_service


TSTATS_SEARCH = """| tstats count as count values(Processes.action) as action,
values(Processes.cpu_load_percent) as cpu_load_percent,
values(Processes.dest) as dest,
values(Processes.mem_used) as mem_used,
values(Processes.os) as os,
values(Processes.parent_process) as parent_process,
values(Processes.parent_process_exec) as parent_process_exec,
values(Processes.parent_process_id) as parent_process_id,
values(Processes.parent_process_guid) as parent_process_guid,
values(Processes.parent_process_name) as parent_process_name,
values(Processes.parent_process_path) as parent_process_path,
values(Processes.process) as process,
values(Processes.process_current_directory) as process_current_directory,
values(Processes.process_exec) as process_exec,
values(Processes.process_hash) as process_hash,
values(Processes.process_guid) as process_guid,
values(Processes.process_id) as process_id,
values(Processes.process_integrity_level) as process_integrity_level,
values(Processes.process_name) as process_name,
values(Processes.process_path) as process_path,
values(Processes.tag) as tag,
values(Processes.user) as user,
values(Processes.user_id) as user_id,
values(Processes.vendor_product) as vendor_product,
values(host) as host,
values(source) as source,
values(sourcetype) as sourcetype
from datamodel=Endpoint.Processes
where 
"""

TSTATS_INVERSE_SEARCH = """| tstats count as count values(Processes.action) as action,
values(Processes.cpu_load_percent) as cpu_load_percent,
values(Processes.dest) as dest,
values(Processes.mem_used) as mem_used,
values(Processes.os) as os,
values(Processes.parent_process) as parent_process,
values(Processes.parent_process_exec) as parent_process_exec,
values(Processes.parent_process_id) as parent_process_id,
values(Processes.parent_process_guid) as parent_process_guid,
values(Processes.parent_process_name) as parent_process_name,
values(Processes.parent_process_path) as parent_process_path,
values(Processes.process) as process,
values(Processes.process_current_directory) as process_current_directory,
values(Processes.process_exec) as process_exec,
values(Processes.process_hash) as process_hash,
values(Processes.process_guid) as process_guid,
values(Processes.process_id) as process_id,
values(Processes.process_integrity_level) as process_integrity_level,
values(Processes.process_name) as process_name,
values(Processes.process_path) as process_path,
values(Processes.tag) as tag,
values(Processes.user) as user,
values(Processes.user_id) as user_id,
values(Processes.vendor_product) as vendor_product,
values(host) as host,
values(source) as source,
values(sourcetype) as sourcetype
from datamodel=Endpoint.Processes
where NOT(_replace1_)
by _replace2_
"""

def prepare_detection_testing(ssh_key_name, private_key, splunk_ip, splunk_password):
    with open(ssh_key_name, 'w') as file :
        file.write(private_key)
    os.chmod(ssh_key_name, 0o600)

    sys.path.append(os.path.join(os.getcwd(),'security_content/bin'))

    try:
        module = __import__('generate')
        results = module.main(REPO_PATH = 'security_content' , OUTPUT_PATH = 'security_content/dist/escu', PRODUCT = 'ESCU', VERBOSE = 'False' )
    except Exception as e:
        print('Error: ' + str(e))

    update_ESCU_app(splunk_ip, ssh_key_name, splunk_password)


def test_detections(ssh_key_name, private_key, splunk_ip, splunk_password, test_files):
    test_index = 1

    for test_file in test_files:
        test_detection(ssh_key_name, private_key, splunk_ip, splunk_password, test_file, test_index)
        if test_index == 10:
            test_index = 1
        else:
            test_index = test_index + 1

        # delete test data
        splunk_sdk.delete_attack_data(splunk_ip, splunk_password)


def test_detection(ssh_key_name, private_key, splunk_ip, splunk_password, test_file, test_index):
    test_file_obj = load_file(test_file)
    if not test_file_obj:
        return

    print("\nAnalysis of detection: " + test_file_obj['tests'][0]['name'])

    test = test_file_obj['tests'][0]
    detection_file_name = test['file']
    detection = load_file(os.path.join(os.path.dirname(__file__), '../security_content/detections', detection_file_name))
    print("Modify detection")
    detection_search_1, detection_search_2 = modify_detection(detection['search'])

    if detection_search_1 == "ERROR" or detection_search_2 == "ERROR":
        print("ERROR: Detection doesn't use Endpoint.Processes Data Model")
        return

    epoch_time = str(int(time.time()))
    folder_name = "attack_data_" + epoch_time
    os.mkdir(folder_name)

    for attack_data in test_file_obj['tests'][0]['attack_data']:
        url = attack_data['data']
        r = requests.get(url, allow_redirects=True)
        open(folder_name + '/' + attack_data['file_name'], 'wb').write(r.content)

        # Update timestamps before replay
        if 'update_timestamp' in attack_data:
            if attack_data['update_timestamp'] == True:
                data_manipulation = DataManipulation()
                data_manipulation.manipulate_timestamp(folder_name + '/' + attack_data['file_name'], attack_data['sourcetype'], attack_data['source'])

        print("Replay Attack Data")
        replay_attack_dataset(splunk_ip, splunk_password, ssh_key_name, folder_name, 'test' + str(test_index), attack_data['sourcetype'], attack_data['source'], attack_data['file_name'])

    time.sleep(60)

    # result_test = {}


    # if 'baselines' in test:
    #     results_baselines = []
    #     for baseline_obj in test['baselines']:
    #         baseline_file_name = baseline_obj['file']
    #         baseline = load_file(os.path.join(os.path.dirname(__file__), '../security_content', baseline_file_name))
    #         result_obj = dict()
    #         result_obj['baseline'] = baseline_obj['name']
    #         result_obj['baseline_file'] = baseline_obj['file']
    #         result = splunk_sdk.test_baseline_search(splunk_ip, splunk_password, baseline['search'], baseline_obj['pass_condition'], baseline['name'], baseline_obj['file'], baseline_obj['earliest_time'], baseline_obj['latest_time'])
    #     result_test['baselines_result'] = results_baselines  
    

    # result_detection = splunk_sdk.test_detection_search(splunk_ip, splunk_password, detection['search'], test['pass_condition'], detection['name'], test['file'], test['earliest_time'], test['latest_time'])

    # for testing
    print("Run Splunk Search")
    results_1, results_2 = splunk_sdk.run_modified_splunk_search(splunk_ip, splunk_password, detection_search_1, detection_search_2, detection['name'], test['file'], test['earliest_time'], test['latest_time'])
    if len(results_1) > 0 and len(results_2) > 0:
        print("Write Results to csv")
        try:
            with open('test.csv', 'w') as csvfile:
                results_1[0]['malicious'] = "yes"
                field_names = results_1[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=field_names)
                writer.writeheader()
                for data in results_1:
                    data = {k: str(v).encode("utf-8").decode() for k,v in data.items()}
                    data['malicious'] = 'yes'
                    writer.writerow(data)

                for data in results_2:
                    data = {k: str(v).encode("utf-8").decode() for k,v in data.items()}
                    data['malicious'] = 'no'
                    writer.writerow(data)


            detection_name = os.path.splitext(os.path.basename(detection_file_name))[0]

            # Upload the file
            print("S3 upload results")
            s3_client = boto3.client('s3')
            try:
                response = s3_client.upload_file('test.csv', 'security-content-labeled-data', 'endpoint/' + detection_name + '/' + detection_name + '.csv')
            except ClientError as e:
                print(e)
        except Exception as e:
                print(e)
    else:
        print("ERROR: Detection didn't return results")        
 
    # result_detection['detection_name'] = test['name']
    # result_detection['detection_file'] = test['file']
    # result_test['detection_result'] = result_detection


def load_file(file_path):
    try:
        with open(file_path, 'r', encoding="utf-8") as stream:
            try:
                file = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print("ERROR: reading {0}".format(file_path))
                return False
    except Exception as e:
        print("ERROR: reading {0}".format(file_path))
        return False
    return file


def update_ESCU_app(splunk_ip, ssh_key_name, splunk_password):
    print("Update ESCU App. This can take some time")

    ansible_vars = {}
    ansible_vars['ansible_user'] = 'ubuntu'
    ansible_vars['ansible_ssh_private_key_file'] = ssh_key_name
    ansible_vars['splunk_password'] = splunk_password
    ansible_vars['security_content_path'] = 'security_content'

    cmdline = "-i %s, -u ubuntu" % (splunk_ip)
    runner = ansible_runner.run(private_data_dir=os.path.join(os.path.dirname(__file__), '../'),
                                cmdline=cmdline,
                                roles_path=os.path.join(os.path.dirname(__file__), '../ansible/roles'),
                                playbook=os.path.join(os.path.dirname(__file__), '../ansible/update_escu.yml'),
                                extravars=ansible_vars)



def replay_attack_dataset(splunk_ip, splunk_password, ssh_key_name, folder_name, index, sourcetype, source, out):
    ansible_vars = {}
    ansible_vars['folder_name'] = folder_name
    ansible_vars['ansible_user'] = 'ubuntu'
    ansible_vars['ansible_ssh_private_key_file'] = ssh_key_name
    ansible_vars['splunk_password'] = splunk_password
    ansible_vars['out'] = out
    ansible_vars['sourcetype'] = sourcetype
    ansible_vars['source'] = source
    ansible_vars['index'] = index

    cmdline = "-i %s, -u ubuntu" % (splunk_ip)
    runner = ansible_runner.run(private_data_dir=os.path.join(os.path.dirname(__file__), '../'),
                                cmdline=cmdline,
                                roles_path=os.path.join(os.path.dirname(__file__), '../ansible/roles'),
                                playbook=os.path.join(os.path.dirname(__file__), '../ansible/attack_replay.yml'),
                                extravars=ansible_vars)


def modify_detection(splunk_search):

    if splunk_search.startswith('| tstats'):
        if "from datamodel=Endpoint.Processes" in splunk_search:
            regex1 = r'where ([^\|]*)'
            a = re.search(regex1, splunk_search)
            search1 = ""
            if a:
                search1 = str(TSTATS_SEARCH + a.group(1))
            else:
                search1 = "ERROR" 

            regex2 = r'where (.*)by ([^\|]+)'
            b = re.search(regex2, splunk_search)
            search2 = ""
            if b:
                search2 = TSTATS_INVERSE_SEARCH.replace("_replace1_", b.group(1))
                search2 = search2.replace("_replace2_", b.group(2))
            else:
                search2 = "ERROR"         

            return search1, search2

    return "ERROR", "ERROR"