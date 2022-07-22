---
title: "Monitor for Unauthorized Software"
last_modified_at: 2017-09-15
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Actions on Objectives
  - Command & Control
  - Installation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Identify and investigate prohibited/unauthorized software or processes that may be concealing malicious behavior within your environment. 

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2017-09-15
- **Author**: David Dorsey, Splunk
- **ID**: 8892a655-6205-43f7-abba-06460e38c8ae

#### Narrative

It is critical to identify unauthorized software and processes running on enterprise endpoints and determine whether they are likely to be malicious. This Analytic Story requires the user to populate the Interesting Processes table within Enterprise Security with prohibited processes. An included support search will augment this data, adding information on processes thought to be malicious. This search requires data from endpoint detection-and-response solutions, endpoint data sources (such as Sysmon), or Windows Event Logs--assuming that the Active Directory administrator has enabled process tracking within the System Event Audit Logs.\
It is important to investigate any software identified as suspicious, in order to understand how it was installed or executed. Analyzing authentication logs or any historic notable events might elicit additional investigative leads of interest. For best results, schedule the search to run every two weeks. 

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Prohibited Software On Endpoint](/deprecated/prohibited_software_on_endpoint/) | None| Hunting |
| [Attacker Tools On Endpoint](/endpoint/attacker_tools_on_endpoint/) | [Match Legitimate Name or Location](/tags/#match-legitimate-name-or-location), [Masquerading](/tags/#masquerading), [OS Credential Dumping](/tags/#os-credential-dumping), [Active Scanning](/tags/#active-scanning)| TTP |

#### Reference

* [https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/monitor_for_unauthorized_software.yml) \| *version*: **1**