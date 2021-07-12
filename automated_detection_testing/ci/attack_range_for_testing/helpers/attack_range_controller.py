from shutil import which
import secrets
import string
import os
import logging
import sys
import time

from helpers import aws_service


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def create_random_password():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(10))
    password = '!1' + password + 'n:'
    return password


def configure_attack_range(region, tf_state_store, password, ssh_key_name):
    sys.path.append(os.path.join(os.getcwd(),'attack_range'))

    with open('attack_range/attack_range.conf.template', 'r') as file :
      filedata = file.read()

    filedata = filedata.replace('attack_range_password = Pl3ase-k1Ll-me:p', 'attack_range_password = ' + password)
    filedata = filedata.replace('tf_backend = local', 'tf_backend = remote')
    filedata = filedata.replace('tf_backend_name = threat_research_attack_range', 'tf_backend_name = ' + tf_state_store)
    filedata = filedata.replace('region = us-west-2', 'region = ' + region)
    filedata = filedata.replace('windows_domain_controller = 1', 'windows_domain_controller = 0')
    filedata = filedata.replace('windows_server_join_domain = 1', 'windows_server_join_domain = 0')
    filedata = filedata.replace('range_name = default', 'range_name = dt')
    filedata = filedata.replace('key_name = attack-range-key-pair', 'key_name = ' + ssh_key_name)
    filedata = filedata.replace('private_key_path = ~/.ssh/id_rsa', 'private_key_path = ' + str(os.getcwd() + "/" + ssh_key_name))

    with open('attack_range/attack_range.conf', 'w') as file:
      file.write(filedata)


def build_attack_range(region, tf_state_store, ssh_key_name):

    password = create_random_password()

    configure_attack_range(region, tf_state_store, password, ssh_key_name)

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'build']

    try:
        LOGGER.info(f"Build Attack Range")
        results = module.main(module.sys.argv)
    except Exception as e:
        LOGGER.error('Build Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        sys.exit(1)

    return password


def destroy_attack_range(region, data, tf_state_store):

    password = data['password']
    ssh_key_name = data['ssh_key_name']

    configure_attack_range(region, tf_state_store, password, ssh_key_name)

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']

    try:
        LOGGER.info(f"Destroy Attack Range")
        results = module.main(module.sys.argv)
    except Exception as e:
        LOGGER.error('Build Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        sys.exit(1)
