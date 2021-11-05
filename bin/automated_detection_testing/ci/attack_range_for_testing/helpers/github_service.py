import git
import os
import logging

from helpers import aws_service

# Logger
logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOGGER = logging.getLogger(__name__)


def clone_attack_range_project():
    LOGGER.info(f"Clone Attack Range Project")
    O_AUTH_TOKEN_GITHUB = aws_service.get_secret("github_token")
    repo_obj = git.Repo.clone_from('https://' + O_AUTH_TOKEN_GITHUB + ':x-oauth-basic@github.com/splunk/attack_range', "attack_range", branch='develop')
    return repo_obj