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


def configure_attack_range_honeypot(region, honeypot_name, password):
    sys.path.append(os.path.join(os.getcwd(),'attack_range_honeypot'))

    with open('attack_range_honeypot/terraform/aws/resources.tf', 'r') as file :
      filedata = file.read()  

    filedata = filedata.replace('[region]', region)
    filedata = filedata.replace('[name]', honeypot_name)

    with open('attack_range_honeypot/terraform/aws/resources.tf', 'w+') as file:
      file.write(filedata)


    with open('attack_range_honeypot/attack_range.conf.template', 'r') as file :
      filedata = file.read()

    filedata = filedata.replace('attack_range_password = asda:?wlflas1234qw?', 'attack_range_password = ' + password)
    filedata = filedata.replace('windows_server = 0', 'windows_server = 1')
    filedata = filedata.replace('region = eu-central-1', 'region = ' + region)
    filedata = filedata.replace('range_name = default', 'range_name = ' + honeypot_name)

    with open('attack_range_honeypot/attack_range.conf', 'w') as file:
      file.write(filedata)

    # check if terraform is installed
    if which('terraform') is None:
        sys.exit(1)
    else:
        # init terraform
        os.system('cd attack_range_honeypot/terraform/aws && terraform init && cd ../../..')


def build_attack_range_honeypot(region, honeypot_name):

    password = create_random_password()

    configure_attack_range_honeypot(region, honeypot_name, password)

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range_honeypot/attack_range.conf', 'build']

    try:
        LOGGER.info(f"Build Attack Range Honeypot")
        results = module.main(module.sys.argv)
    except Exception as e:
        LOGGER.error('Build Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range_honeypot/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        sys.exit(1)

    return password


def destroy_attack_range_honeypot(data):

    region = data['region']
    honeypot_name = data['name']
    password = data['password']

    configure_attack_range_honeypot(region, honeypot_name, password)

    module = __import__('attack_range')
    module.sys.argv = ['attack_range', '--config', 'attack_range_honeypot/attack_range.conf', 'destroy']

    try:
        LOGGER.info(f"Destroy Attack Range Honeypot")
        results = module.main(module.sys.argv)
    except Exception as e:
        LOGGER.error('Build Error: ' + str(e))
        module.sys.argv = ['attack_range', '--config', 'attack_range_honeypot/attack_range.conf', 'destroy']
        module.main(module.sys.argv)
        sys.exit(1)
