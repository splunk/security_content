---
title: "Possible Browser Pass View Parameter"
excerpt: "Credentials from Web Browsers
, Credentials from Password Stores
"
categories:
  - Endpoint
last_modified_at: 2021-11-22
toc: true
toc_label: ""
tags:
  - Credentials from Web Browsers
  - Credentials from Password Stores
  - Credential Access
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This analytic will detect if a suspicious process contains a commandline parameter related to a web browser credential dumper. This technique is used by Remcos RAT malware which uses the Nirsoft webbrowserpassview.exe application to dump web browser credentials. Remcos uses the "/stext" command line to dump the credentials in text format. This Hunting query is a good indicator of hosts suffering from possible Remcos RAT infection. Since the hunting query is based on the parameter command and the possible path where it will save the text credential information, it may catch normal tools that are using the same command and behavior.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-11-22
- **Author**: Teoderick Contreras, Splunk
- **ID**: 8ba484e8-4b97-11ec-b19a-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | Credentials from Web Browsers | Credential Access |

| [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores | Credential Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process  IN ("*/stext *", "*/shtml *", "*/LoadPasswordsIE*", "*/LoadPasswordsFirefox*", "*/LoadPasswordsChrome*", "*/LoadPasswordsOpera*", "*/LoadPasswordsSafari*" , "*/UseOperaPasswordFile*", "*/OperaPasswordFile*","*/stab*", "*/scomma*", "*/stabular*", "*/shtml*", "*/sverhtml*", "*/sxml*", "*/skeepass*" ) AND Processes.process IN ("*\\temp\\*", "*\\users\\public\\*", "*\\programdata\\*") by Processes.dest Processes.user Processes.parent_process_name Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.original_file_name 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `possible_browser_pass_view_parameter_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that **possible_browser_pass_view_parameter_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Processes.dest
* Processes.user
* Processes.parent_process_name
* Processes.parent_process
* Processes.original_file_name
* Processes.process_name
* Processes.process
* Processes.process_id
* Processes.parent_process_path
* Processes.process_path
* Processes.parent_process_id


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Known False Positives
False positive is quite limited. Filter is needed

#### Associated Analytic story
* [Remcos](/stories/remcos)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 16.0 | 40 | 40 | suspicious process $process_name$ contains commandline $process$ on $dest$ |


#### Reference

* [https://www.nirsoft.net/utils/web_browser_password.html](https://www.nirsoft.net/utils/web_browser_password.html)
* [https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/](https://app.any.run/tasks/df0baf9f-8baf-4c32-a452-16562ecb19be/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/web_browser_pass_view/sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/web_browser_pass_view/sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/possible_browser_pass_view_parameter.yml) \| *version*: **1**