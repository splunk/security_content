import os
from os import path
import sys
import argparse

from helpers import github_service, aws_service, attack_range_controller


ATTACK_RANGE_STATE_STORE = "attack-range-state-store"



def main(args):

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-a", "--action", required=True, help="action")

    args = parser.parse_args()
    action = args.action

    if action == "build":
        response = aws_service.get_entry_database(name)
        if not response:
            github_service.clone_honeypot_project()
            #ssh_key_name, key_material = aws_service.create_key_pair(region)
            aws_service.create_tf_state_store(name, region)
            aws_service.create_entry_database(region, name, "building")
            password = attack_range_controller.build_attack_range_honeypot(region, name)
            aws_service.update_entry_database(name, password, "running")

    elif action == "destroy":
        data = aws_service.get_entry_database(name)
        if data:
            github_service.clone_honeypot_project()
            attack_range_controller.destroy_attack_range_honeypot(data)
            aws_service.delete_entry_database(name)
            aws_service.delete_tf_state_store(data['region'], name)
        
    elif action == "rebuild":


if __name__ == "__main__":
    main(sys.argv[1:])