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
1. create virtualenv and install requirements: `virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`
2. install pre-commit `pre-commit install`
