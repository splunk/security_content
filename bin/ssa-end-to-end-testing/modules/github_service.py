
import git


SECURITY_CONTENT_URL = f"https://github.com/splunk/security_content"


class GithubService:

    def __init__(self, security_content_branch):
        self.security_content_branch = security_content_branch
        self.security_content_repo_obj = self.clone_project(SECURITY_CONTENT_URL, f"security_content", security_content_branch)


    def clone_project(self, url, project, branch):
        repo_obj = git.Repo.clone_from(url, project, branch=branch)
        return repo_obj


    def get_changed_test_files_ssa(self):
        changedFiles = [ item.a_path for item in self.security_content_repo_obj.index.diff(None)]
        print(changedFiles)