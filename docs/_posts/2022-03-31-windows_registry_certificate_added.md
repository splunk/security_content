---
title: "Windows Registry Certificate Added"
excerpt: "Install Root Certificate
, Subvert Trust Controls
"
categories:
  - Endpoint
last_modified_at: 2022-03-31
toc: true
toc_label: ""
tags:
  - Install Root Certificate
  - Subvert Trust Controls
  - Defense Evasion
  - Defense Evasion
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies installation of a root CA certificate by monitoring the registry. The base paths may be found [here](https://gist.github.com/mattifestation/75d6117707bcf8c26845b3cbb6ad2b6b/raw/ae65ef15c706140ffc2e165615204e20f2903028/RootCAInstallationDetection.xml). In short, there are specific certificate registry paths that will be written to (SetValue) when a new certificate is added. The high-fidelity events to pay attention to are SetValue events where the TargetObject property ends with "<THUMBPRINT_VALUE>\Blob" as this indicates the direct installation or modification of a root certificate binary blob. The other high fidelity reference will be which process is making the registry modifications. There are very few processes that modify these day to day, therefore monitoring for all to start (hunting) provides a great beginning.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2022-03-31
- **Author**: Michael Haag, Splunk
- **ID**: 5ee98b2f-8b9e-457a-8bdc-dd41aaba9e87


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1553.004](https://attack.mitre.org/techniques/T1553/004/) | Install Root Certificate | Defense Evasion |

| [T1553](https://attack.mitre.org/techniques/T1553/) | Subvert Trust Controls | Defense Evasion |

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

* DE.CM



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">

* CIS 3
* CIS 5
* CIS 16



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">


</div>
</details>

#### Search 

```

| tstats `security_content_summariesonly` count from datamodel=Endpoint.Registry where Registry.registry_path IN ("*\\certificates\\*") AND Registry.registry_value_name="Blob" by _time span=1h Registry.dest Registry.user Registry.registry_path Registry.registry_value_name Registry.process_guid Registry.registry_key_name Registry.registry_value_data 
| `drop_dm_object_name(Registry)` 
| join process_guid _time [
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes by _time span=1h Processes.process_id Processes.process_name Processes.process Processes.dest Processes.process_guid 
| `drop_dm_object_name(Processes)`] 
| table _time dest user process_name process process_guid registry_path registry_value_name registry_value_data registry_key_name 
| `windows_registry_certificate_added_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)

> :information_source:
> **windows_registry_certificate_added_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest
* Processes.process_id
* Processes.process_name
* Processes.process
* Processes.dest
* Processes.process_guid


#### How To Implement
To successfully implement this search you need to be ingesting information on process that include the name of the process responsible for the changes from your endpoints into the `Endpoint` datamodel in the `Processes` and `Registry` node. In addition, confirm the latest CIM App 4.20 or higher is installed and the latest TA for the endpoint product.

#### Known False Positives
False positives will be limited to a legitimate business applicating consistently adding new root certificates to the endpoint. Filter by user, process, or thumbprint.

#### Associated Analytic story
* [Windows Drivers](/stories/windows_drivers)
* [Windows Registry Abuse](/stories/windows_registry_abuse)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 42.0 | 60 | 70 | A root certificate was added on $dest$. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec](https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec)
* [https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1553.004](https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1553.004)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.002/atomic_red_team/certblob_windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1587.002/atomic_red_team/certblob_windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/windows_registry_certificate_added.yml) \| *version*: **1**