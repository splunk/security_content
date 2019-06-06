security-content ![security-content](static/logo.png)
=====
Contains a collection of security analytic stories with their corresponding detection, investigation, and responses. The content here is packaged and shipped as part of the Splunk Enterprise Security Content Updates. 

| branch | build status |
| ---    | ---          |
| develop| [![develop status](https://circleci.com/gh/splunk/security-content/tree/develop.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/develop)|
| master | [![master status](https://circleci.com/gh/splunk/security-content/tree/master.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/master)|

# Usage
Can be consumed using:

#### [Splunk App](https://github.com/splunk/security-content/releases)
grab the latest release of DA-ESS-ContentUpdate and install it in a Splunk Enterprise server (search head).

#### [API](https://github.com/splunk/security-content-api)
`curl https://g7jbilqdth.execute-api.us-west-2.amazonaws.com/api/`

#### [CLI](https://github.com/splunk/security-content-api/blob/master/content-update.py)
`python content-update.py -o $SPLUNK_HOME/etc/apps/DA-ESS-ContentUpdate --splunk_user admin --splunk_password xxxx`

# Writing Content
Make sure you followed step 1 to 3 under [developing](https://github.com/splunk/security-content#developing) before starting. 

1. select which content [piece](https://github.com/splunk/security-content#content-parts) you want to write. 
2. copy an example and edit to your needs, most  sure you at minium write a [story](stories/), [detection](detections/) and [investigation](investigations/)
3. make a pull request .. if CI failed refer to [troubleshooting](https://github.com/splunk/security-content#troubleshooting)


# Security Content Layout
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
#### Our Automated Tests
1. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L27) validates that the content was written to spec using [`validate.py`](https://github.com/splunk/security-content/blob/runstory/bin/generate.py), to run validation manually execute: `python bin/generate.py --path . --output package --storiesv1 --use_case_lib -v` 
2. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L60) generates splunk configuration files using [`generate.py`](https://github.com/splunk/security-content/blob/develop/bin/generate.py). If you want to export splunk conf files manually from the content run: `python bin/generate.py --path . --output package --storiesv1 --use_case_lib -v` 
3. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L107) builds a DA-ESS-ContentUpdate splunk package using the [Splunk Packaging Toolkit](http://dev.splunk.com/view/packaging-toolkit/SP-CAAAE9V) 
4. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L145) tests the newly produce package using [Splunk Appinspect](http://dev.splunk.com/view/appinspect/SP-CAAAE9U)

# Todo's
* build cli for interacting and developing