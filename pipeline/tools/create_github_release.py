'''
A simple python script to create a Github Release with release notes and DA-ESS-ContentUpdate-latest.tar.gz
Usage: python create_github_release.py "${{ secrets.GITHUB_TOKEN }}" "$CI_COMMIT_TAG"
${{ secrets.GITHUB_TOKEN }} - Access token to Security Content Github Repo
$CI_COMMIT_TAG - Variable with tag name

'''

import os
import requests
import json
import sys

# Constants
REPO = "splunk/security_content"
RELEASE_NOTES_FILE = '/builds/threat-research/security_content/artifacts/release_notes.txt'
TAR_FILE = '/builds/threat-research/security_content/artifacts/DA-ESS-ContentUpdate-latest.tar.gz'

# Read release notes from file
def read_release_notes(file_path):
    with open(file_path, 'r') as file:
        return file.read()

# Create a GitHub release
def create_release(repo, token, tag, release_notes):
    url = f'https://api.github.com/repos/{repo}/releases'
    headers = {
        'Authorization': f'token {token}',
        'Content-Type': 'application/json'
    }
    data = {
        'tag_name': tag,
        'target_commitish': "develop",
        'name': tag,
        'body': release_notes,
        'draft': False,
        'prerelease': False
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 201:
        upload_url = response.json()['upload_url'].replace('{?name,label}', '')
        return upload_url
    else:
        print(f"Error creating release: {response.json()}")
        return None

# Upload the tar file to the release
def upload_asset(upload_url, token, file_path):
    file_name = os.path.basename(file_path)
    headers = {
        'Authorization': f'token {token}',
        'Content-Type': 'application/gzip'
    }
    with open(file_path, 'rb') as f:
        response = requests.post(f"{upload_url}?name={file_name}", headers=headers, data=f)
        if response.status_code == 201:
            print(f"Uploaded {file_name} successfully")
        else:
            print(f"Error uploading {file_name}: {response.json()}")

def main():
    if len(sys.argv) != 3:
        print("Usage: python create_github_release.py <token> <tag>")
        sys.exit(1)

    token = sys.argv[1]
    tag = sys.argv[2]

    release_notes = read_release_notes(RELEASE_NOTES_FILE)
    upload_url = create_release(REPO, token, tag, release_notes)
    if upload_url:
        upload_asset(upload_url, token, TAR_FILE)

if __name__ == '__main__':
    main()