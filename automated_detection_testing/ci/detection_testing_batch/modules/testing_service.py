
import ansible_runner
import yaml
import sys
import os
import time
import requests
from modules.DataManipulation import DataManipulation
from modules import splunk_sdk

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
    result_tests = []
    for test_file in test_files:
        result_test = test_detection(ssh_key_name, private_key, splunk_ip, splunk_password, test_file, test_index)
        result_tests.append(result_test)
        if test_index == 10:
            test_index = 1
        else:
            test_index = test_index + 1

    # delete test data
    splunk_sdk.delete_attack_data(splunk_ip, splunk_password)

    # write results into dynamodb
    # uuid, detection, detection_path, test_file, result, time

    for result_test in result_tests:
        print(result_test)
        if result_test['detection_result']['error']:
            print('Test failed for detection: ' + result_test['detection_result']['detection_name'] + ' ' + result_test['detection_result']['detection_file'])
        else:
            print('Test passed for detection: ' + result_test['detection_result']['detection_name'] + ' ' + result_test['detection_result']['detection_file'])

    return result_tests


def test_detection(ssh_key_name, private_key, splunk_ip, splunk_password, test_file, test_index):
    test_file_obj = load_file("security_content/" + test_file[2:])
    if not test_file_obj:
        return
    #print(test_file_obj)

    epoch_time = str(int(time.time()))
    folder_name = "attack_data_" + epoch_time
    os.mkdir(folder_name)

    for attack_data in test_file_obj['tests'][0]['attack_data']:
        url = attack_data['data']
        r = requests.get(url, allow_redirects=True)
        open(folder_name + '/' + attack_data['file_name'], 'wb').write(r.content)
        print(folder_name + '/' + attack_data['file_name'])

        # Update timestamps before replay
        if 'update_timestamp' in attack_data:
            if attack_data['update_timestamp'] == True:
                data_manipulation = DataManipulation()
                data_manipulation.manipulate_timestamp(folder_name + '/' + attack_data['file_name'], attack_data['sourcetype'], attack_data['source'])

        replay_attack_dataset(splunk_ip, splunk_password, ssh_key_name, folder_name, 'test' + str(test_index), attack_data['sourcetype'], attack_data['source'], attack_data['file_name'])

    time.sleep(60)

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
            result = splunk_sdk.test_baseline_search(splunk_ip, splunk_password, baseline['search'], baseline_obj['pass_condition'], baseline['name'], baseline_obj['file'], baseline_obj['earliest_time'], baseline_obj['latest_time'])
        result_test['baselines_result'] = results_baselines  

    detection_file_name = test['file']
    detection = load_file(os.path.join(os.path.dirname(__file__), '../security_content/detections', detection_file_name))
    result_detection = splunk_sdk.test_detection_search(splunk_ip, splunk_password, detection['search'], test['pass_condition'], detection['name'], test['file'], test['earliest_time'], test['latest_time'])

    result_detection['detection_name'] = test['name']
    result_detection['detection_file'] = test['file']
    result_test['detection_result'] = result_detection

    return result_test


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

