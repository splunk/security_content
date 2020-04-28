 
 
 
# Splunk Security Content
![security-content](docs/static/logo.png) 
=====

| branch | build status |
| ---    | ---          |
| develop| [![develop status](https://circleci.com/gh/splunk/security-content/tree/develop.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/develop)|
| master | [![master status](https://circleci.com/gh/splunk/security-content/tree/master.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/master)|

Welcome to the Splunk Security Research Team's Security Content Exchange! 

This project gives you access to our repository of Analytic Stories--themed security guides that contain that provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats. 

While this content is available via Splunk Enterprise Security and Enterprise Security Content Updates (https://splunkbase.splunk.com/app/3449/), we have now made it available as an open-source project (which you just found--hi!). The Security Research Content Exchange was designed to bring the community together to improve our collective defenses. By sharing research and analytics, we can help the entire industry craft more effective strategies. This project provides a mechanism to facilitate this exchange. 


# Usage
The Splunk Security Content Exchange can be used via:

#### [Splunk App](https://github.com/splunk/security-content/releases)
Grab the latest release of DA-ESS-ContentUpdate and install it on a Splunk Enterprise server (search head).

#### [API](https://docs.splunkresearch.com/?version=latest)
```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api",
  "available_endpoints": [
    "/stories",
    "/detections",
    "/investigations",
    "/baselines",
    "/responses",
    "/package"
  ]
}
```
# How to Get Started

While you you can configure each detection individually, the real power lies in running the Analytic Stories end-to-end. Using the Analytic Story Execution (ASX) app (https://github.com/splunk/analytic_story_execution), you can funnel the results to investigations, reducing the need for manual intervention. When available, you can automatically trigger reponses, as well. The alerts you'll get include context (history, correlations, etc.), so they help you better understand their importance. The net effect is a more efficient workflow, as well as more comprehensive, effective defenses.

Follow the instructions below to get started.

# What's in an Analytic Story?
[Analytic Stories](https://github.com/splunk/security-content/blob/develop/docs/stories_categories.md) and their corresponding searches are composed of **.yml** files (manifests) and associated .conf files. The stories reside in [/stories](https://github.com/splunk/security-content/tree/develop/stories) and the searches live in [/detections](https://github.com/splunk/security-content/tree/develop/detections). 

Manifests contain a number of mandatory and optional fields. You can see the full field list for each piece of content [here](https://github.com/splunk/security-content/tree/develop/docs#spec-documentation).

# Customize to your Environment

After release [1.0.46](https://github.com/splunk/security-content/releases) we introduced a concept of input(pre-filter) and output(post-filter) macros for each of our detection search. The intention behind introducing these macros is primarily to help our users to update the macro definition “once” and those changes will be applicable across all detections that leverage that macro and  local to your Splunk Environment.

**input(pre-filter):** This macro is to  specify your environment-specific configurations (index, source, sourcetype, etc.) to get the specific data sources that you would like to bring in. Replace the macro definition with configurations for your Splunk environment.

**output(post-filter):** This macro is to  specify your environment-specific values (eg: dest, user), to filter out known false positives.. Replace the macro definition with values that you’d like to exclude from detection results. Think of this as a whitelisting/blacklisting using macros.

Note: we are currently working on coming up with a better naming convention and making this consistent across all our detections, investigations and baselines. Suggestions are welcomed :stuck_out_tongue:

# Execute an Analytic Story

Install the latest version of [Splunk Analytic Story Execution] 
(https://github.com/splunk/analytic_story_execution/releases) on the same search head as ESCU. This Splunk application will help the analyst do the following:

1. Execute an analytic story in an adhoc mode and view the results.
2. Schedule all the detection searches in an analytic story.
3. Update security-content via an API
 

# Writing Content
Before you begin, follow the steps to install **dependencies and pre-commit hooks** under ["Developing"](https://github.com/splunk/security-content#developing). 

1. Select the content [piece](https://github.com/splunk/security-content#content-parts) you want to write. 
2. Copy an example and edit it to suit your needs. At a minimum, you must write a [story](stories/), [a detection search](detections/), and an [investigative search](investigations/).
3. Make a pull request. The pull request will trigger CircleCI, a continuous-integration app thatintegrates with a VCS and automatically runs a series of steps every time that it detects a change to your repository. A CircleCI build consists of a series of steps, usually Dependencies, Testing, and Deployment. If your tests pass, you're good to go! If the CircleCI check fails, refer to [troubleshooting](https://github.com/splunk/security-content#troubleshooting).  

For a more detailed explanation on how to contribute to the project, please see ["Contributing"](#Contributing)

# Security Content Layout
![](docs/static/structure.png)

#### Content Parts
* [stories/](stories/): All Analytic Stories 
* [detections/](detections/): Splunk Enterprise, Splunk UBA, and Splunk Phantom detections that power Analytic Stories
* [investigations/](investigations/): Splunk Enterprise and Splunk Phantom investigative searches and playbooks employed by Analytic Stories
* [responses/](responses/): Automated Splunk Enterprise and Splunk Phantom responses triggered by Analytic Stories
* [baselines/](baselines/): Splunk Phantom and Splunk Enterprise baseline searches needed to support detection searches in Analytic Stories

#### Supporting Parts
* [package/](package/): Splunk content app-source files, including lookups, binaries, and default config files
* [bin/](bin/): All binaries required to produce and test content

# Docs
* [docs/](docs/): Documentation for all spec files
* [spec/](spec/): All spec files that describe the security content

# Developing
##### Dependecies and Pre-Commit Hooks
Install project dependecies and tests that run before content is committed:

1. Create virtualenv and install requirements: `virtualenv venv && source venv/bin/activate && pip install -r requirements.txt`.
2. Install `pre-commit install`.

##### CI Tools
Tools that help with testing CI jobs:

1. Install CircleCI [CLI Tool](https://circleci.com/docs/2.0/local-cli/).
2. To test a local change to CircleCI or build, make sure you are running Docker, then enter
`circleci local execute -e GITHUB_TOKEN=$GITHUB_TOKEN --branch <your branch>`.

##### Generate Docs from Schema 
To automatically generate docs from schema:

1. Install https://github.com/adobe/jsonschema2md.
2. Enter `jsonschema2md -d spec/v2/detections.spec.json -o docs`.

# Troubleshooting

### Our Automated Tests
1. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L27) validates that the content was written to spec using [`validate.py`](https://github.com/splunk/security-content/blob/runstory/bin/generate.py). To run validation manually, run: `python bin/validate.py --path . --verbose`.
2. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L60) generates Splunk configuration files using [`generate.py`](https://github.com/splunk/security-content/blob/develop/bin/generate.py). If you want to export Splunk .conf files manually from the content, run `python bin/generate.py --path . --output package --verbose`.
3. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L107) builds a DA-ESS-ContentUpdate Splunk package using the [Splunk Packaging Toolkit](http://dev.splunk.com/view/packaging-toolkit/SP-CAAAE9V). 
4. [CI](https://github.com/splunk/security-content/blob/44946063173f7bc9921f0da0aa62139c084d1c51/.circleci/config.yml#L145) tests the newly produced package using [Splunk Appinspect](http://dev.splunk.com/view/appinspect/SP-CAAAE9U).

* note that [requirements.txt](https://github.com/splunk/security-content/blob/develop/requirements.txt) hard codes the versions for packages we use [dependabot](https://dependabot.com/) to make sure we safely always upgrade to the latest versions. 

## Customize to Your Environment
Release 1.0.46 introduced input(pre-filter) and output(post-filter) macros for each of our detection searches. These macros let you update a macro definition once and then apply the new definition across all detections that leverage that macro. These changes will be local to your Splunk environment.

input(pre-filter): This macro specifies your environment-specific configurations (index, source, sourcetype, etc.) to get the specific data sources that you require. Replace the macro definition with configurations for your Splunk environment.
output(post-filter): This macro specifies your environment-specific values (dest, user, etc,), to filter out known false positives. Replace the macro definition with values that you'd like to exclude from detection results. Think of this as whitelisting/blacklisting using macros.
Note: Coming soon is an improved naming convention that will be consistent across all of our detections, investigations, and baselines.

## Support
Please use the [GitHub Issue Tracker](https://github.com/splunk/security-content/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Post a question to [Splunk Answers](http://answers.splunk.com)
* Join the [#security-research](https://splunk-usergroups.slack.com/messages/C1RH09ERM/) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)
* If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can also open a support case on the https://www.splunk.com/ support portal

## Contributing
We welcome feedback and contributions from the community! Please see our [contribution guidelines](docs/CONTRIBUTING.md) for more information on how to get involved. 

# To Dos
* Build CLI for interacting and developing
