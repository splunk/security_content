---
title: "GitHub Actions Disable Security Workflow"
excerpt: "Compromise Software Supply Chain
, Supply Chain Compromise
"
categories:
  - Cloud
last_modified_at: 2022-04-04
toc: true
toc_label: ""
tags:
  - Compromise Software Supply Chain
  - Supply Chain Compromise
  - Initial Access
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search detects a disabled security workflow in GitHub Actions. An attacker can disable a security workflow in GitHub actions to hide malicious code in it.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud

- **Last Updated**: 2022-04-04
- **Author**: Patrick Bareiss, Splunk
- **ID**: 0459f1a5-c0ac-4987-82d6-65081209f854


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Compromise Software Supply Chain | Initial Access |

| [T1195](https://attack.mitre.org/techniques/T1195/) | Supply Chain Compromise | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Actions on Objectives


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">

* PR.DS
* PR.AC
* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 13



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```
`github` workflow_run.event=push OR workflow_run.event=pull_request 
| stats values(workflow_run.name) as workflow_run.name by workflow_run.head_commit.id workflow_run.event workflow_run.head_branch workflow_run.head_commit.author.email workflow_run.head_commit.author.name workflow_run.head_commit.message workflow_run.head_commit.timestamp workflow_run.head_repository.full_name workflow_run.head_repository.owner.id workflow_run.head_repository.owner.login workflow_run.head_repository.owner.type 
| rename workflow_run.head_commit.author.name as user, workflow_run.head_commit.author.email as user_email, workflow_run.head_repository.full_name as repository, workflow_run.head_branch as branch 
| search NOT workflow_run.name=*security-testing* 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `github_actions_disable_security_workflow_filter`
```

#### Macros
The SPL above uses the following Macros:
* [github](https://github.com/splunk/security_content/blob/develop/macros/github.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **github_actions_disable_security_workflow_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* workflow_run.event
* workflow_run.name
* workflow_run.head_commit.id
* workflow_run.event workflow_run.head_branch
* workflow_run.head_commit.author.email
* workflow_run.head_commit.author.name
* workflow_run.head_commit.message
* workflow_run.head_commit.timestamp
* workflow_run.head_repository.full_name
* workflow_run.head_repository.owner.id
* workflow_run.head_repository.owner.login
* workflow_run.head_repository.owner.type


#### How To Implement
You must index GitHub logs. You can follow the url in reference to onboard GitHub logs. Sometimes GitHub logs are truncated, make sure to disable it in props.conf. Replace *security-testing* with the name of your security testing workflow in GitHub Actions.

#### Known False Positives
unknown

#### Associated Analytic story
* [Dev Sec Ops](/stories/dev_sec_ops)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 27.0 | 30 | 90 | Security Workflow is disabled in branch $branch$ for repository $repository$ |


#### Reference

* [https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html](https://www.splunk.com/en_us/blog/tips-and-tricks/getting-github-data-with-webhooks.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/github_actions_disable_security_workflow/github_actions_disable_security_workflow.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.002/github_actions_disable_security_workflow/github_actions_disable_security_workflow.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/cloud/github_actions_disable_security_workflow.yml) \| *version*: **1**