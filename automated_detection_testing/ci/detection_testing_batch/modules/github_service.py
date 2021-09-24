
import git
import os
import logging
import glob
import subprocess


# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)

SECURITY_CONTENT_URL = "https://github.com/splunk/security_content"


class GithubService:

    def __init__(self, security_content_branch, PR_number = None):
        self.security_content_branch = security_content_branch
        self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, f"security_content", f"develop")
        if PR_number:
            subprocess.call(["git", "-C", "security_content/", "fetch", "origin", "refs/pull/%d/head:%s"%(PR_number, security_content_branch)])

        self.security_content_repo_obj.git.checkout(security_content_branch)

    def clone_project(self, url, project, branch):
        LOGGER.info(f"Clone Security Content Project")
        repo_obj = git.Repo.clone_from(url, project, branch=branch)
        return repo_obj

    def get_changed_test_files(self):
        branch1 = self.security_content_branch
        branch2 = 'develop'
        g = git.Git('security_content')
        changed_test_files = []

        if branch1 != 'develop':
            differ = g.diff('--name-status', branch2 + '...' + branch1)
            changed_files = differ.splitlines()

            for file_path in changed_files:
                # added or changed test files
                if file_path.startswith('A') or file_path.startswith('M'):
                    if 'tests' in file_path:
                        if not os.path.basename(file_path).startswith('ssa') and os.path.basename(file_path).endswith('.test.yml'):
                            if file_path not in changed_test_files:
                                changed_test_files.append(file_path)

                    # changed detections
                    if 'detections' in file_path:
                        if not os.path.basename(file_path).startswith('ssa') and os.path.basename(file_path).endswith('.yml'):
                            file_path_base = os.path.splitext(file_path)[0].replace('detections', 'tests') + '.test'
                            file_path_new = file_path_base + '.yml'
                            if file_path_new not in changed_test_files:
                                changed_test_files.append(file_path_new)

        return changed_test_files



