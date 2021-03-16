
import git
import os
import logging
from os import path
import yaml
import glob
import sys


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

SECURITY_CONTENT_URL = f"https://github.com/splunk/security_content"


class GithubService:

    def __init__(self, security_content_branch):
        self.security_content_branch = security_content_branch
        self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, f"security_content", f"develop")
        self.security_content_repo_obj.git.checkout(security_content_branch)

    def clone_project(self, url, project, branch):
        LOGGER.info(f"Clone Security Content Project")
        repo_obj = git.Repo.clone_from(url, project, branch=branch)
        return repo_obj


    def get_changed_test_files_ssa(self):
        branch1 = self.security_content_branch
        branch2 = 'develop'
        g = git.Git('security_content')
        differ = g.diff('--name-only', branch1, branch2)
        changed_files = differ.splitlines()

        changed_ssa_test_files = []

        tests = self.read_security_content_test_files()

        for file_path in changed_files:
            # added or changed test files
            if file_path.startswith('tests'):
                if os.path.basename(file_path).startswith('ssa'):
                    changed_ssa_test_files.append(file_path)

            # changed detections


        return changed_ssa_test_files

    
    def load_objects(self, file_path):
        files = []
        manifest_files = 'security_content/' + file_path
        for file in sorted(glob.glob(manifest_files)):
            files.append(self.load_file(file))
        return files


    def load_file(self, file_path):
        with open(file_path, 'r', encoding="utf-8") as stream:
            try:
                file = list(yaml.safe_load_all(stream))[0]
            except yaml.YAMLError as exc:
                print(exc)
                sys.exit("ERROR: reading {0}".format(file_path))
        return file


    def read_security_content_test_files(self):
        tests = self.load_objects("tests/*/*.yml")
        print(len(tests))
        return tests