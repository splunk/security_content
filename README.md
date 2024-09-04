</p>
<p align="center">
    <a href="https://github.com/splunk/security_content/releases">
        <img src="https://img.shields.io/github/v/release/splunk/security_content" /></a>
    <a href="https://github.com/splunk/security_content/actions/workflows/build.yml/badge.svg?branch=develop">
        <img src="https://github.com/splunk/security_content/actions/workflows/build.yml/badge.svg?branch=develop" /></a>
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

**Note:** We have sister projects that enable us to build the industry's best security content. These projects are the Splunk Attack Range, an attack simulation lab built around Splunk, and Contentctl, the tool that enables us to build, test, and package our content for distribution.

- [Splunk Attack Range](https://github.com/splunk/attack_range): An attack simulation lab built around Splunk.
- [Contentctl](https://github.com/splunk/contentctl): The tool that enables us to build, test, and package our content for distribution.
- [Attack data](https://github.com/splunk/attack_data): The is a collection of attack data that is used to test our content.

# Get Content🛡
The latest Splunk Security Content can be obtained via:
 
### 🌐 [Website](https://research.splunk.com/)

Best way to discover and access our content is by using the [research.splunk.com](https://research.splunk.com/) website.

### 🖥️ [Splunk Enterprise Security (ES) Content Update](https://docs.splunk.com/Documentation/ES/latest/Admin/Usecasecontentlibrary?#Update_the_Analytic_Stories)

Splunk security content ships as part of ESCU directly into, if you are an ES user, good news, you already have it!

### 📦 [ESCU App](https://github.com/splunk/security_content/releases)

To manually download the latest release of Splunk Security Content (named DA-ESS-ContentUpdate.spl), you can visit the [splunkbase](https://splunkbase.splunk.com/app/3449/) page or the [release page](https://github.com/splunk/security_content/releases) on GitHub.

# Tools 🧰
The key tool that drives our content development is [contentctl](https://github.com/splunk/contentctl). Contentctl offers the following features:

- Creating new detections
- Validating the correctness of all necessary components for detections
- Testing detections
- Generating deployable apps from detections

To learn more about contentctl and its capabilities, please visit the [contentctl repository](https://github.com/splunk/contentctl).

# MITRE ATT&CK ⚔️
### Detection Coverage
To view an up-to-date detection coverage map for all the content tagged with MITRE techniques visit: [https://mitremap.splunkresearch.com/](https://mitremap.splunkresearch.com/) under the **Detection Coverage** layer. Below is a snapshot in time of what technique we currently have some detection coverage for.

![](docs/mitre-map/coverage.png)

# Content Parts 🧩

* [detections/](detections/): Contains all detection searches to-date and growing.
* [stories/](stories/): All Analytic Stories that are group detections or also known as Use Cases
* [deployments/](deployments/): Configuration for the schedule and alert action for all content
* [playbooks/](playbooks/): Incident Response Playbooks/Workflow for responding to a specific Use Case or Threat.
* [baselines/](baselines/): Searches that must be executed before a detection runs. It is specifically useful for collecting data on a system before running your detection on the collected data.
* [investigations/](investigations/): Investigations to further analyze the output from detections. For more information, you can refer to the [Splunk Enterprise Security documentation on timelines](https://docs.splunk.com/Documentation/ES/7.3.0/User/Timelines).
* [macros/](macros/): Implements Splunk’s search macros, shortcuts to commonly used search patterns like sysmon source type. More on how macros are used to customize content below.
* [lookups/](lookups/): Implements Splunk’s lookup, usually to provide a list of static values like commonly used ransomware extensions.
* [data_sources/](data_sources/): Defines the data sources, the necessary TA or App to collect them and the fields provided that can be used by the detections.

# Getting Started 🚀

Follow these steps to get started with Splunk Security Content.

1. Clone this repository using `git clone https://github.com/splunk/security_content.git`
2. Navigate to the repository directory using `cd security_content`
3. Install contentctl using `pip install contentctl` to install the latest version of contentctl, this is a pre-requisite to validate, build and test the content like the Splunk Threat Research team

🚨 NOTE: If you are just getting started with managing your Splunk detection as code, we recommend that you keep the YAML structure of the detections as close as possible to the original structure of the detections. This will make it easier to manage your detections and will also make it easier to contribute to the Splunk Security Content project.

# Elements of a detection.yml:

Here is a quick overview of the elements of a detection with an explanation
| Key | Type | Description |
|-----------------------|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| name | <str> | Name of the detection, this is the name that will be displayed in the Splunk UI |
| id | <int> | Unique identifier for the detection, UUID |
| version | <int> | Version of the detection, update this every time a change is made to the file |
| date | <str> | Date of the detection, update this every time a change is made to the file |
| author | <str> | Author of the detection |
| type | <str> | Type of the detection (TTP, Anomaly, Baseline, Hunting, Correlation) |
| status | <str> | Status of the detection (Production, Experimental, Deprecated) |
| data_source | <list> | Reference to the data source that the detection is based, use the name from the data_sources/ folder |
| description | <str> | Description of the detection |
| search | <str> | Splunk search to be executed, this is the core of the detection. Detections can be either written against the sourcetype or in tstats if the data is normalized. Sourcetype based searches begin with an input macro, core search logic and end with a filter macro. The input macro is used to specify the index and sourcetype and the _filter macro is used to filter out the false positives. |
| how_to_implement | <str> | Details on how to implement the detection |
| known_false_positives | <str> | Details on known false positives triggered in this detection. |
| references | <list> | List of references to the MITRE ATT&CK, details of attack vector, blog posts, vulnerabilities, etc. |
| tags | | |
| analytic_story | <list> | Name of the analytic story that the detection is part of |
| asset_type | <str> | Which assets are monitored by this detection (Endpoint, Network, AWS Tenant, Azure Tenant, etc.) |
| confidence | <int> | Confidence level of the detection |
| cve | <list> | List of CVEs that are related to the detection |
| impact | <int> | A number between 0-100 that represents the impact of the detection |
| message | <str> | The risk message that will be displayed in the Splunk Enterprise Security |
| mitre_attack_id | <list> | List of MITRE ATT&CK IDs that are related to the detection |
| observable | <list> | List of observables that are related to the detection |
| name | <str> | Field name of the observable |
| type | <str> | Type of the observable (User, Endpoint, File, Process Name) |
| role | <list> | Role of the observable (Victim, Attacker) |
| product | <list> | List of products that are related to the detection (Splunk Enterprise Security, Splunk Enterprise) |
| required_fields | <list> | List of required fields that are needed to execute the detection |
| risk_score | <int> | A number between 0-100 that represents the risk score of the detection |
| security_domain | <str> | The security domain that the detection is related to (Network, Endpoint, Cloud, etc.) |
| tests | | |
| name | <str> | Name of the test |
| attack_data | <url> | URL to the attack data that is used to test the detection |
| data | <str> | Data of the attack |
| source | <str> | Source of the attack |
| sourcetype | <str> | Sourcetype from the attack |

# Elements of a analytics_story.yml:

# Your Markdown Title

Some introductory text or description.

| Key        | Type   | Description                                                                                       |
|------------|--------|---------------------------------------------------------------------------------------------------|
| name       | <str>  | Name of the analytic story                                                                        |
| id         | <int>  | Unique identifier for the analytic story, UUID                                                    |
| version    | <int>  | Version of the analytic story, update this every time a change is made to the file                |
| date       | <str>  | Date of the analytic story                                                                        |
| author     | <str>  | Author of the analytic story                                                                      |
| description| <str>  | Description of the analytic story                                                                 |
| narrative  | <str>  | Narrative of the analytic story                                                                   |
| references | <list> | List of references to the analytic story                                                          |
| tags       |        |                                                                                                   |
| category   | <list> | List of categories that the analytic story is related to                                          |
| product    | <list> | List of products that the analytic story is related to                                            |
| usecase    | <str>  | Usecase of the analytic story (Advanced Persistent Threat, Cloud, Vulnerability, Malware, etc.)   |

More text or content can follow here.
# Recommendations

- 🚨 NOTE: If you are just getting started with managing your Splunk detection as code, we recommend that you keep the YAML structure of the detections as close as possible to the original structure of the detections. This will make it easier to manage your detections and will also make it easier to contribute back to the community by creating a pull request to the Splunk Security Content project.

- In order to build an content app that specific for your organization, we strongly recommend that you start with keeping only the detections that are related to your organization and remove other yamls that are not related to your organization. This includes selecting detections, stories, macros, lookups that are used by the detection ymls.

- If your detections are using macros and lookups, please make sure that you have the same macros and lookups in those directories.. This will ensure that the content app is self-contained and does not rely on external files.


# Contribution 🥰
We welcome feedback and contributions from the community! Please see our [contributing to the project](./.github/CONTRIBUTING.md) for more information on how to get involved.

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
