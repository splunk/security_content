---
title: "Clop Common Exec Parameter"
excerpt: "User Execution"
categories:
  - Endpoint
last_modified_at: 2021-03-17
toc: true
tags:
  - TTP
  - T1204
  - User Execution
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Obfuscation
---



#### Description

The following analytics are designed to identifies some CLOP ransomware variant that using arguments to execute its main code or feature of its code. In this variant if the parameter is &#34;runrun&#34;, CLOP ransomware will try to encrypt files in network shares and if it is &#34;temp.dat&#34;, it will try to read from some stream pipe or file start encrypting files within the infected local machines. This technique can be also identified as an anti-sandbox technique to make its code non-responsive since it is waiting for some parameter to execute properly.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-03-17
- **Author**: Teoderick Contreras, Splunk


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1204](https://attack.mitre.org/techniques/T1204/) | User Execution | Execution |


#### Search

```

| tstats `security_content_summariesonly` values(Processes.process) as cmdline values(Processes.parent_process_name) as parent_process values(Processes.process_name) count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process_name != "*temp.dat*" Processes.process = "*runrun*" OR Processes.process = "*temp.dat*" by Processes.dest Processes.user Processes.parent_process Processes.process_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `clop_common_exec_parameter_filter`
```

#### Associated Analytic Story
* [Clop Ransomware](_stories/clop_ransomware)


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` node.

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
* Obfuscation


#### Known False Positives
Operators can execute third party tools using these parameters.



#### RBA

| Risk Score  | Impact      | Confidence   |
| ----------- | ----------- |--------------|
| 100.0 | 100 | 100 |



#### Reference

* [https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html](https://www.fireeye.com/blog/threat-research/2020/10/fin11-email-campaigns-precursor-for-ransomware-data-theft.html)
* [https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html](https://blog.virustotal.com/2020/11/keep-your-friends-close-keep-ransomware.html)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_b/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_b/windows-sysmon.log)


_version_: 1