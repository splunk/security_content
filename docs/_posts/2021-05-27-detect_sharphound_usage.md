---
title: "Detect SharpHound Usage"
excerpt: "Domain Account, Local Account, Domain Trust Discovery, Domain Groups, Local Groups"
categories:
  - Endpoint
last_modified_at: 2021-05-27
toc: true
tags:
  - TTP
  - T1087.002
  - Domain Account
  - Discovery
  - T1087.001
  - Local Account
  - Discovery
  - T1482
  - Domain Trust Discovery
  - Discovery
  - T1069.002
  - Domain Groups
  - Discovery
  - T1069.001
  - Local Groups
  - Discovery
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Reconnaissance
---



#### Description

The following analytic identifies SharpHound binary usage by using the `OriginalFileName` from Sysmon. In addition to renaming the PE, other coverage is available to detect command-line arguments. This particular analytic only looks for the OriginalFileName of `SharpHound.exe`. It is possible older instances of SharpHound.exe have different original filenames. Dependent upon the operator, the code may be re-compiled and the attributes removed or changed to anything else. During triage, review the metadata of the binary in question. Review parallel processes for suspicious behavior. Identify the source of this binary.

- **ID**: dd04b29a-beed-11eb-87bc-acde48001122
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-05-27
- **Author**: Michael Haag, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Domain Account | Discovery || [T1087.001](https://attack.mitre.org/techniques/T1087/001/) | Local Account | Discovery || [T1482](https://attack.mitre.org/techniques/T1482/) | Domain Trust Discovery | Discovery || [T1069.002](https://attack.mitre.org/techniques/T1069/002/) | Domain Groups | Discovery || [T1069.001](https://attack.mitre.org/techniques/T1069/001/) | Local Groups | Discovery |


#### Search

```
`sysmon` EventID=1 (OriginalFileName=SharpHound.exe process_name!=sharphound.exe) 
| stats count min(_time) as firstTime max(_time) as lastTime by Computer, User, parent_process_name, process_name, OriginalFileName, process_path, CommandLine Product 
| rename Computer as dest 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `detect_sharphound_usage_filter`
```

#### Associated Analytic Story
* [Discovery Techniques](/stories/discovery_techniques)
* [Ransomware](/stories/ransomware)


#### How To Implement
To successfully implement this search, you need to be ingesting logs with the process name, parent process, and command-line executions from your endpoints. If you are using Sysmon, you must have at least version 6.0.4 of the Sysmon TA.

#### Required field
* _time
* dest
* User
* parent_process_name
* process_name
* OriginalFileName
* process_path
* CommandLine
* Product


#### Kill Chain Phase
* Reconnaissance


#### Known False Positives
False positives should be limited as this is specific to a file attribute not used by anything else. Filter as needed.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 24.0 | 30 | 80 |



#### Reference

* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)
* [https://thedfirreport.com/?s=bloodhound](https://thedfirreport.com/?s=bloodhound)
* [https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
* [https://github.com/BloodHoundAD/SharpHound3](https://github.com/BloodHoundAD/SharpHound3)
* [https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1059.001/T1059.001.md#atomic-test-2---run-bloodhound-from-local-disk)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log)


_version_: 1