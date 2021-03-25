
import git
import os
import logging


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

        for file_path in changed_files:
            # added or changed test files
            if file_path.startswith('tests'):
                if os.path.basename(file_path).startswith('ssa'):
                    if file_path not in changed_ssa_test_files:
                        changed_ssa_test_files.append(file_path)

            # changed detections
            if file_path.startswith('detections'):
                if os.path.basename(file_path).startswith('ssa'):
                    file_path_base = os.path.splitext(file_path)[0].replace('detections', 'tests') + '.test'
                    file_path_new = file_path_base + '.yml'
                    if not os.path.exists(file_path_new):
                        file_path_new = file_path_base + '.yaml'
                    if file_path_new not in changed_ssa_test_files:
                        changed_ssa_test_files.append(file_path_new)

        return changed_ssa_test_files


