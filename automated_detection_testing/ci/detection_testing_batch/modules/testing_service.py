
import ansible_runner
import yaml
import sys
import os
import time
import requests
from modules.DataManipulation import DataManipulation

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


def test_detection(ssh_key_name, private_key, splunk_ip, splunk_password, test_file, test_index):
    test_file_obj = load_file("security_content/" + test_file)
    #print(test_file_obj)

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

        replay_attack_dataset(splunk_ip, splunk_password, ssh_key_name, folder_name, 'test' + test_index, attack_data['sourcetype'], attack_data['source'], attack_data['file_name'])

    
    if test_index == 10:
        test_index = 1
    else:
        test_index = test_index + 1


def load_file(file_path):
    with open(file_path, 'r', encoding="utf-8") as stream:
        try:
            file = list(yaml.safe_load_all(stream))[0]
        except yaml.YAMLError as exc:
            sys.exit("ERROR: reading {0}".format(file_path))
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

