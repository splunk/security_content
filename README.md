security-content ![security-content](static/logo.png)
=====

Contains a collection of security stories with their corresponding detection, investigative, contexual and support splunk searches

| branch | build status |
| ---    | ---          |
| develop| [![develop status](https://circleci.com/gh/splunk/security-content/tree/develop.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/develop)|
| master | [![master status](https://circleci.com/gh/splunk/security-content/tree/master.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/master)|

# Usage
Can be consumed using:

#### [DA-ESS-ContentUpdate Splunk App](https://github.com/splunk/security-content/releases)
Grab the latest release and install it the Splunk Application

#### [API](https://github.com/splunk/security-content-api)
`curl https://g7jbilqdth.execute-api.us-west-2.amazonaws.com/api/`

#### [CLI](https://github.com/splunk/security-content-api/blob/master/content-update.py)
`python content-update.py -o $SPLUNK_HOME/etc/apps/DA-ESS-ContentUpdate --splunk_user admin --splunk_password xxxx`

# Writing Content
Make sure you followed step 1 to 3 under [developing](https://github.com/splunk/security-content#developing) before starting.

1. select which content [piece](https://github.com/splunk/security-content#content-parts) you want to write.
2. copy a example and edit to your needs, make sure you at minium write a [story](stories/), [detection](detections/) and [investigation](investigations/)
3. make a pull request .. if CI failed refer to troubleshooting

# Security Content layout
![](static/structure.png)

#### Content Parts
* [stories/](stories/) - contains all analytics stories/use cases for ESCU
* [detections/](detections/) - splunk, uba and phantom detections that power stories
* [investigations/](investigations/) - splunk, and phantom investigation content that are used in stories
* [responses/](responses/) - automated splunk and phantom responses that are used in stories
* [baselines/](baselines/) - phantom and Splunk baseline needed to support detections in stories

#### Supporting parts
* [package/](package/) - splunk content app source files, includes lookups, binaries, and defaul config files
* [bin/](bin/) - where all binaries to produce, and test content lives




# Docs

* [docs/](docs/) - documentation for all of the spec files
* [spec/](spec/) - location of all spec files that describe ESCU content

# Developing
For getting pre-commit checks, install the hooks see below for steps:

1. create virtualenv and install requirements: `virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`
2. install pre-commit `pre-commit install`
3. Install circleci [CLI Tool](https://circleci.com/docs/2.0/local-cli/#installation)

To test a local change to CI or build make sure you are running docker and then
`circleci local execute -e GITHUB_TOKEN=$GITHUB_TOKEN --branch <your branch>`

To generate docs from schema automatically
1. install https://github.com/adobe/jsonschema2md
2. `jsonschema2md -d spec/v2/detections.json.spec -o docs`

# Troubleshooting
Our CI pipeline

# Todo's
* build cli for interacting and developing