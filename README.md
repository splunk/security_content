
| branch | build status |
| ---    | ---          |
| develop| [![develop status](https://circleci.com/gh/splunk/security-content/tree/develop.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/develop)|
| master | [![master status](https://circleci.com/gh/splunk/security-content/tree/master.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/master)|

# security-content
Contains a collection of security stories with their corresponding detection, investigative, contexual and support splunk searches

# Consumption
Can be consumed using:
* API (https://api.splunksecuritycontent.com)
* CLI

# Structure
`src/` - splunk content app source files, includes lookups, binaries, and defaul config files

# Developing

For getting pre-commit checks, install the hooks see below for steps:
1. Install circleci [CLI Tool](https://circleci.com/docs/2.0/local-cli/#installation)
2. create virtualenv and install requirements: `virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`
3. install pre-commit `pre-commit install`

To test a local change to CI or build make sure you are running docker and then
`circleci local execute -e GITHUB_TOKEN=$GITHUB_TOKEN --branch <your branch>`

