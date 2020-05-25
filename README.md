


# Splunk Security Content
![security-content](docs/static/logo.png)
=====

| branch | build status |
| ---    | ---          |
| develop| [![develop status](https://circleci.com/gh/splunk/security-content/tree/develop.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/develop)|
| master | [![master status](https://circleci.com/gh/splunk/security-content/tree/master.svg?style=svg&circle-token=67ad1fa7779c57d7e5bcfc42bd617baf607ec269)](https://circleci.com/gh/splunk/security-content/tree/master)|

Welcome to the Splunk Security Content

This project gives you access to our repository of Analytic Stories that are security guides which provide background on TTPs, mapped to the MITRE framework, the Lockheed Martin Kill Chain, and CIS controls. They include Splunk searches, machine-learning algorithms, and Splunk Phantom playbooks (where available)—all designed to work together to detect, investigate, and respond to threats.

# Usage
The Splunk Security Content can be used via:

#### [Splunk App](https://github.com/splunk/security-content/releases)
Grab the latest release of DA-ESS-ContentUpdate and install it on a Splunk Enterprise instance.

#### [API](https://docs.splunkresearch.com/?version=latest)
```
curl -s https://content.splunkresearch.com | jq
{
  "hello": "welcome to Splunks Research security content api"
}
```

#### [GitHub Workflow](https://github.com/splunk/security-content/wiki/2.-Installation-and-Usage)
Create your customized version of Security Content by forking this project and following this guide.

# What's in an Analytic Story?
[Analytic Stories](https://github.com/splunk/security-content/blob/develop/docs/stories_categories.md) and their corresponding searches are composed of **.yml** files (manifests) and associated .conf files. The stories reside in [/stories](https://github.com/splunk/security-content/tree/develop/stories) and the searches live in [/detections](https://github.com/splunk/security-content/tree/develop/detections).

Manifests contain a number of mandatory and optional fields. You can see the full field list for each piece of content [here](https://github.com/splunk/security-content/tree/develop/docs#spec-documentation).

# Customize to your Environment

After release [1.0.46](https://github.com/splunk/security-content/releases) we introduced a concept of **input(pre-filter)** and **output(post-filter)** macros for each of our detection search. The intention behind introducing these macros is primarily to help our users to update the macro definition “once” and those changes will be applicable across all detections that leverage that macro and  local to your Splunk Environment.

**input(pre-filter):** This macro is to  specify your environment-specific configurations (index, source, sourcetype, etc.) to get the specific data sources that you would like to bring in. Replace the macro definition with configurations for your Splunk environment. For example the [sysmon](macros/sysmon.yml) **input macro** can be modified to the local splunk deployments index or sourcetype.

**output(post-filter):** This macro is to  specify your environment-specific values (eg: dest, user), to filter out known false positives.. Replace the macro definition with values that you’d like to exclude from detection results. Think of this as a whitelisting/blacklisting using macros. A good example


# Execute an Analytic Story

Download and install the latest version of [Splunk Analytic Story Execution]
(https://github.com/splunk/analytic_story_execution/releases). This Splunk application will help the user do the following:

1. Execute an analytic story in an adhoc mode and view the results.
2. Schedule all the detection searches in an analytic story.
3. Update security-content via an API


# Writing Content
Before you begin, follow the steps to install **dependencies and pre-commit hooks** under ["Developing"](https://github.com/splunk/security-content#developing).

# Security Content

#### Content Parts
* [stories/](stories/): All Analytic Stories
* [detections/](detections/): Splunk Enterprise, Splunk UBA, and Splunk Phantom detections that power Analytic Stories
* [response_tasks/](response_tasks/): Splunk Enterprise and Splunk Phantom investigative searches and playbooks employed by Analytic Stories
* [responses/](responses/): Automated Splunk Enterprise and Splunk Phantom responses triggered by Analytic Stories
* [baselines/](baselines/): Splunk Phantom and Splunk Enterprise baseline searches needed to support detection searches in Analytic Stories

#### Supporting Parts
* [package/](package/): Splunk content app-source files, including lookups, binaries, and default config files
* [bin/](bin/): All binaries required to produce and test content

# Contribution
We welcome feedback and contributions from the community! Please see our [contribution guidelines](docs/CONTRIBUTING.md) for more information on how to get involved.

## Support
Please use the [GitHub Issue Tracker](https://github.com/splunk/security-content/issues) to submit bugs or request features.

If you have questions or need support, you can:

* Post a question to [Splunk Answers](http://answers.splunk.com)
* Join the [#security-research](https://splunk-usergroups.slack.com/messages/C1RH09ERM/) room in the [Splunk Slack channel](http://splunk-usergroups.slack.com)
* If you are a Splunk Enterprise customer with a valid support entitlement contract and have a Splunk-related question, you can also open a support case on the https://www.splunk.com/ support portal
