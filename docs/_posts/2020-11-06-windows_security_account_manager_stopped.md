---
title: "Windows Security Account Manager Stopped"
excerpt: "Service Stop"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
tags:
  - TTP
  - T1489
  - Service Stop
  - Impact
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Delivery
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

The search looks for a Windows Security Account Manager (SAM) was stopped via command-line. This is consistent with Ryuk infections across a fleet of endpoints.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2020-11-06
- **Author**: Rod Soto, Jose Hernandez, Splunk
- **ID**: 69c12d59-d951-431e-ab77-ec426b8d65e6


#### ATT&CK

| ID          | Technique   | Tactic       |
| ----------- | ----------- |--------------|
| [T1489](https://attack.mitre.org/techniques/T1489/) | Service Stop | Impact |



#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Processes WHERE ("Processes.process_name"="net*.exe" "Processes.process"="*stop \"samss\"*") BY "Processes.dest", "Processes.user", "Processes.process" 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(lastTime)` 
| `security_content_ctime(firstTime)` 
| `windows_security_account_manager_stopped_filter`
```

#### Associated Analytic Story
* [Ryuk Ransomware](/stories/ryuk_ransomware)


#### How To Implement
You must be ingesting data that records the process-system activity from your hosts to populate the Endpoint Processes data-model object. If you are using Sysmon, you will need a Splunk Universal Forwarder on each endpoint from which you want to collect data.

#### Required field
* _time
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.user


#### Kill Chain Phase
* Delivery


#### Known False Positives
SAM is a critical windows service, stopping it would cause major issues on an endpoint this makes false positive rare. AlthoughNo false positives have been identified.



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 70.0 | 70 | 100 | The Windows Security Account Manager (SAM) was stopped via cli by $user$ on $dest$ by this command: $processs$ |



#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/ryuk/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_security_account_manager_stopped.yml) \| *version*: **1**