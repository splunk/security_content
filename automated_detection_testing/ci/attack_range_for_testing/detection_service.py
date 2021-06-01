import os
from os import path
import sys
import argparse
import time
import shutil

from modules.github_service import GithubService


DT_ATTACK_RANGE_STATE_STORE = "dt-attack-range-tf-state-store"
DT_ATTACK_RANGE_STATE = "dt-attack-range-state"
REGION = "eu-central-1"
NAME = "detection-testing-attack-range"


def main(args):

    parser = argparse.ArgumentParser(description="CI Detection Testing")
    parser.add_argument("-a", "--action", required=True, help="action")

    args = parser.parse_args()
    action = args.action

    if action == "build":
        build_dt_attack_range()

    elif action == "destroy":
        destroy_dt_attack_range()
        
    elif action == "rebuild":
        destroy_dt_attack_range()
        shutil.rmtree('attack_range')
        time.sleep(60)
        build_dt_attack_range()


def build_dt_attack_range():
    github_service.clone_attack_range_project()
    aws_service.create_tf_state_store(DT_ATTACK_RANGE_STATE_STORE, REGION)
    aws_service.create_db_database(DT_ATTACK_RANGE_STATE, REGION)
    ssh_key_name, key_material = aws_service.create_key_pair(REGION)
    time.sleep(10)
    aws_service.create_entry_database(REGION, DT_ATTACK_RANGE_STATE, NAME, "building", ssh_key_name, key_material)
    password = attack_range_controller.build_attack_range(REGION, DT_ATTACK_RANGE_STATE_STORE, ssh_key_name)
    aws_service.update_entry_database(REGION, DT_ATTACK_RANGE_STATE, NAME, password, "running")   


def destroy_dt_attack_range():
    data = aws_service.get_entry_database(REGION, DT_ATTACK_RANGE_STATE, NAME)
    github_service.clone_attack_range_project()
    attack_range_controller.destroy_attack_range(REGION, data, DT_ATTACK_RANGE_STATE_STORE)
    aws_service.delete_db_database(DT_ATTACK_RANGE_STATE, REGION)
    aws_service.delete_tf_state_store(REGION, DT_ATTACK_RANGE_STATE_STORE)


if __name__ == "__main__":
    main(sys.argv[1:])