---
title: "Office Product Spawning MSHTA"
excerpt: "Phishing, Spearphishing Attachment"
categories:
  - Endpoint
last_modified_at: 2021-04-26
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

The following detection identifies the latest behavior utilized by different malware families (including TA551, IcedID). This detection identifies any Windows Office Product spawning `mshta.exe`. In malicious instances, the command-line of `mshta.exe` will contain the `hta` file locally, or a URL to the remote destination. In addition, Threat Research has released a detections identifying suspicious use of `mshta.exe`. In this instance, we narrow our detection down to the Office suite as a parent process. During triage, review all file modifications. Capture and analyze any artifacts on disk. The Office Product, or `mshta.exe` will have reached out to a remote destination, capture and block the IPs or domain. Review additional parallel processes for further activity.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-04-26
- **Author**: Michael Haag, Splunk
- **ID**: 6078fa20-a6d2-11eb-b662-acde48001122


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1566](https://attack.mitre.org/techniques/T1566/) | Phishing | Initial Access |

| [T1566.001](https://attack.mitre.org/techniques/T1566/001/) | Spearphishing Attachment | Initial Access |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.parent_process_name IN ("winword.exe","excel.exe","powerpnt.exe","mspub.exe","visio.exe") `process_mshta` by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `office_product_spawning_mshta_filter`
```

#### Associated Analytic Story
* [Spearphishing Attachments](/stories/spearphishing_attachments)
* [IcedID](/stories/icedid)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

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


#### Kill Chain Phase
* Exploitation


#### Known False Positives
No false positives known. Filter as needed.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 63.0 | 70 | 90 | office parent process $parent_process_name$ will execute a suspicious child process $process_name$ with process id $process_id$ in host $dest$ |




#### Reference

* [https://redcanary.com/threat-detection-report/threats/TA551/](https://redcanary.com/threat-detection-report/threats/TA551/)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_macros.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_macros.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/office_product_spawning_mshta.yml) \| *version*: **2**