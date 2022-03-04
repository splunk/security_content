---
title: "Winword Spawning PowerShell"
excerpt: "Phishing, Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-12
toc: true
toc_label: ""
tags:
  - Phishing
  - Initial Access
  - Spearphishing Attachment
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The following detection identifies Microsoft Word spawning PowerShell. Typically, this is not common behavior and not default with winword.exe. Winword.exe will generally be found in the following path `C:\Program Files\Microsoft Office\root\Office16` (version will vary). PowerShell spawning from winword.exe is common for a spearphishing attachment and is actively used. Albeit, the command executed will most likely be encoded and captured via another detection. During triage, review parallel processes and identify any files that may have been written.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-12
- **Author**: Michael Haag, Splunk
- **ID**: b2c950b8-9be2-11eb-8658-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name="winword.exe" `process_powershell` by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `winword_spawning_powershell_filter`
```

#### Macros
The SPL above uses the following Macros:
* [process_powershell](https://github.com/splunk/security_content/blob/develop/macros/process_powershell.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

Note that `winword_spawning_powershell_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives should be limited, but if any are present, filter as needed.

#### Associated Analytic story
* [Spearphishing Attachments](/stories/spearphishing_attachments)


#### Kill Chain Phase
* Exploitation



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | $parent_process_name$ on $dest$ by $user$ launched the following powershell process: $process_name$ which is very common in spearphishing attacks |


Note that risk score is calculated base on the following formula: `(Impact * Confidence)/100`



#### Reference

* [https://redcanary.com/threat-detection-report/techniques/powershell/](https://redcanary.com/threat-detection-report/techniques/powershell/)
* [https://attack.mitre.org/techniques/T1566/001/](https://attack.mitre.org/techniques/T1566/001/)
* [https://app.any.run/tasks/b79fa381-f35c-4b3e-8d02-507e7ee7342f/](https://app.any.run/tasks/b79fa381-f35c-4b3e-8d02-507e7ee7342f/)
* [https://app.any.run/tasks/181ac90b-0898-4631-8701-b778a30610ad/](https://app.any.run/tasks/181ac90b-0898-4631-8701-b778a30610ad/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/winword_spawning_powershell.yml) \| *version*: **2**