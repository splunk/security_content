import os
import sys
import base64
import configparser
import time
import yaml
import argparse
from modules.ssa_utils import *
from modules.utils import manipulate_spl
from modules.streams_service_api_helper import DSPApi


def main(args):
    parser = argparse.ArgumentParser()
    parser.add_argument('detection', nargs='+', type=str, help='detection yaml to be checked')
    opts = parser.parse_args(args)

    api = get_api()
    if api is None:
        print("No valid tokens found")
        sys.exit(-1)

    results = {}
    for detection_path in opts.detection:
        if not os.path.exists(detection_path):
            print(f"File {detection_path} does not exist")
            continue

        with open(detection_path, 'rt') as f:
            detection = yaml.safe_load(f)
        name = os.path.basename(detection_path)

        spl = manipulate_spl(api, detection['search'], None)
        if spl is None:
            results[name] = 'failed to manipulate SPL'
            continue

        upl = api.compile_spl(spl)
        if upl is None:
            results[name] = 'failed to compile SPL'
            continue

        validated_upl = api.validate_upl(upl)
        if validated_upl is None:
            results[name] = 'failed to validate UPL'
            continue

        results[name] = 'success'

    for name, result in results.items():
        if result == 'success':
            print(f"{name}: {result}")

    for name, result in results.items():
        if result != 'success':
            print(f"{name} FAILED!!: {result}")


def get_api():
    for token in get_scloud_tokens():
        env, tenant, good = parse_token(token)
        if good:
            return DSPApi(env, tenant, token)


def parse_token(token):
    def decode(s):
        def pad(t):
            return t + '=' * (len(t) % 4)
        return json.loads(base64.b64decode(pad(s)))

    header, payload, signature = token.split('.')
    payload_data = decode(payload)
    for k in sorted(payload_data.keys()):
        print(f"token.payload.{k} = {payload_data[k]}")

    token_env = payload_data['iss'].split('.')[-4]
    print(f"token env: {token_env}")

    token_tenant = payload_data['tenant']
    print(f"token tenant: {token_tenant}")

    valid_for = payload_data['exp'] - int(time.time())
    if valid_for > 60:
        print("Token is good")
        token_good = True
    else:
        print("Token is expired")
        token_good = False

    return token_env, token_tenant, token_good


def get_scloud_tokens():
    tokens = []
    config = configparser.ConfigParser()
    context_path = os.path.expanduser('~/.scloud_context')
    config.read(context_path)
    config.sections()
    for section in config.sections():
        token = config[section].get('access_token')
        if token is not None:
            tokens.append(token.strip('"'))
    return tokens


if __name__ == '__main__':
    main(sys.argv[1:])