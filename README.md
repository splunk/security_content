</p>
<p align="center">
    <a href="https://github.com/splunk/security_content/releases">
        <img src="https://img.shields.io/github/v/release/splunk/security_content" /></a>
    <a href="https://github.com/splunk/security_content/actions/workflows/build-and-validate.yml/badge.svg?branch=develop">
        <img src="https://img.shields.io/github/workflow/status/splunk/security_content/build-and-validate/develop" /></a>
    <a href="https://github.com/splunk/security_content">
        <img src="https://security-content.s3-us-west-2.amazonaws.com/reporting/detection_count.svg" /></a>
    <a href="https://github.com/splunk/security_content">
        <img src="https://security-content.s3-us-west-2.amazonaws.com/reporting/detection_coverage.svg" /></a>
    <a href="https://github.com/splunk/security_content">
        <img src="https://img.shields.io/github/downloads/splunk/security_content/total" /></a>
    <a href="https://github.com/splunk/security_content/graphs/contributors" alt="Contributors">
        <img src="https://img.shields.io/github/contributors/splunk/security_content" /></a>
    <a href="https://github.com/splunk/security_content/stargazers">
        <img src="https://img.shields.io/github/stars/splunk/security_content?style=social" /></a>
</p>


# Splunk Security Content
![security_content](docs/static/logo.png)
=====

Welcome to the Splunk Security Content

This project gives you access to our repository of Analytic Stories, security guides that provide background on tactics, techniques and procedures (TTPs), mapped to the MITRE ATT&CK Framework, the Lockheed Martin Cyber Kill Chain, and CIS Controls. They include Splunk searches, machine learning algorithms and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

# Get Content🛡
The latest Splunk Security Content can be obtained via:

#### [SSE App](https://splunkbase.splunk.com/app/3435/)
Grab the latest release of Splunk Security Essentials App and install it on a Splunk instance. You can download it from [splunkbase](https://splunkbase.splunk.com/app/3435/), it is a Splunk Supported App. SSE Splunk app today supports push updates for security content release, this is the **preferred way** to get content!

#### [ESCU App](https://github.com/splunk/security_content/releases)
Grab the latest release of DA-ESS-ContentUpdate.spl and install it on a Splunk instance. Alternatively, you can download it from [splunkbase](https://splunkbase.splunk.com/app/3449/), it is currently a Splunk Supported App.

#### [API](https://docs.splunkresearch.com/?version=latest)
```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

# Usage 🧰
### contentctl.py
The Content Control tool allows you to manipulate Splunk Security Content via the following actions:

0. **init** - Initilialize a new repo from scratch so you can easily add your own content to a custom application.  Note that this requires a large number of command line arguments, so use python _contentctl.py init --help_ for documentation around those arguments.
1. **new_content** - Creates new content (detection, story, baseline)
2. **validate** - Validates written content
3. **generate** - Generates a deployment package for different platforms (splunk_app)
4. **build** - Builds an application suitable for deployment on a search head using Slim, the Splunk Packaging Toolkit
5. **inspect** - Uses a local version of appinspect to ensure that the app you built meets basic quality standards.
6. **cloud_deploy** - Using ACS, deploy your custom app to a running Splunk Cloud Instance.
7. **convert** - Convert a detection rule with sigma syntax to a Splunk SPL detection

### pre-requisites
Make sure you use python version 3.9.

```
git clone git@github.com:splunk/security_content.git
cd security_content
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```
### Architecture details for the tooling
- [WIKI](https://github.com/splunk/security_content/wiki/Security-Content-Code)

### create a new detection
`python contentctl.py -p . new_content -t detection`

for a more indepth write up on how to write content see our [guide](https://github.com/splunk/security_content/wiki/Developing-Content).

### validate security content
`python contentctl.py -p . validate -pr ESCU`

### generate a splunk app from current content
`python contentctl.py -p . generate -o dist/escu -pr ESCU`

### convert a Sigma search into a Splunk detection
Detection rule using tstats and cim datamodel:
`python contentctl.py -p . convert -dm cim -o detections/endpoint/ -dp dev/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml`

Detection rule using raw:
`python contentctl.py -p . convert -dm raw -o detections/endpoint/ -dp dev/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml`

Detection rule converted to Windows Security Event Code 4688:
`python contentctl.py -p . convert -dm raw -lo "Windows Security 4688" -o detections/endpoint/ -dp dev/endpoint/attempted_credential_dump_from_registry_via_reg_exe.yml`

# MITRE ATT&CK ⚔️
### Detection Coverage
To view an up-to-date detection coverage map for all the content tagged with MITRE techniques visit: [https://mitremap.splunkresearch.com/](https://mitremap.splunkresearch.com/) under the **Detection Coverage** layer. Below is a snapshot in time of what technique we currently have some detection coverage for. The darker the shade of blue the more detections we have for this particular technique. This map is automatically updated on every release and generated from the [generate-coverage-map.py](https://github.com/splunk/security_content/blob/develop/bin/generate-coverage-map.py).

![](docs/mitre-map/coverage.png)

# Customize to your Environment 🏗
Customize your content to change how [often detections run](https://github.com/splunk/security_content/wiki/Customize-to-Your-Environment#customizing-scheduling-and-alert-actions-with-deployments), or what the right source type for [sysmon](https://github.com/splunk/security_content/wiki/Customize-to-Your-Environment#customizing-source-types-with-macros) in your environment is please follow this [guide](https://github.com/splunk/security_content/wiki/Customize-to-Your-Environment).  

# What's in an Analytic Story? 🗺
A complete use case, specifically built to detect, investigate, and respond to a specific threat like [Credential Dumping](https://github.com/splunk/security_content/blob/develop/stories/credential_dumping.yml) or [Ransomware](https://github.com/splunk/security_content/blob/develop/stories/ransomware.yml). A group of detections and a response make up an analytic story, they are associated with the tag `analytic_story: <name>`.  

# Content Parts 🧩

* [detections/](detections/): Contains all 209 detection searches to-date and growing.
* [stories/](stories/): All Analytic Stories that are group detections or also known as Use Cases
* [deployments/](deployments/): Configuration for the schedule and alert action for all content
* [playbooks/](playbooks/): Incident Response Playbooks/Workflow for responding to a specific Use Case or Threat.
* [baselines/](baselines/): Searches that must be executed before a detection runs. It is specifically useful for collecting data on a system before running your detection on the collected data.
* [investigations/](investigations/): Investigations to further analysis the output from detections.
* [dashboards/](dashboards/): JSON definitions of Mission Control dashboards, to be used as a response task. Currently not used.
* [macros/](macros/): Implements Splunk’s search macros, shortcuts to commonly used search patterns like sysmon source type. More on how macros are used to customize content below.
* [lookups/](lookups/): Implements Splunk’s lookup, usually to provide a list of static values like commonly used ransomware extensions.
* [security_content_automation/](security_content_automation/): It contains script for enriching detection with relevant supported TAs and also contains script for publishing release build to [Pre-QA artifactory](https://repo.splunk.com/artifactory/Solutions/DA/Pre-QA/) on every tag release.



# Contribution 🥰
We welcome feedback and contributions from the community! Please see our [contributing to the project](https://github.com/splunk/security_content/wiki/Contributing-to-the-Project) for more information on how to get involved.

## Support 💪
If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can open a support case on the https://www.splunk.com/ support portal.

Please use the [GitHub Issue Tracker](https://github.com/splunk/security_content/issues) to submit bugs or feature requests using the templates to the Threat Research team directly.

If you have questions or need support, you can:

* Post a question to [Splunk Answers](http://answers.splunk.com)
* Join the [#security-research](https://splunk-usergroups.slack.com/archives/C1S5BEF38) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)



## License
Copyright 2022 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
