---
title: "Set Default PowerShell Execution Policy To Unrestricted or Bypass"
excerpt: "Command and Scripting Interpreter, PowerShell"
categories:
  - Endpoint
last_modified_at: 2020-11-06
toc: true
toc_label: ""
tags:
  - Command and Scripting Interpreter
  - Execution
  - PowerShell
  - Execution
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for changes of the ExecutionPolicy in the registry to the values &#34;unrestricted&#34; or &#34;bypass,&#34; which allows the execution of malicious scripts.

- **Type**: TTP
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2020-11-06
- **Author**: Patrick Bareiss, Splunk
- **ID**: c2590137-0b08-4985-9ec5-6ae23d92f63d


#### [ATT&CK](https://attack.mitre.org/)

| ID          | Technique   | Tactic         |
| ----------- | ----------- |--------------- |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | Execution |

| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Execution |

#### Search

```

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Registry where Registry.registry_path=*Software\\Microsoft\\Powershell\\1\\ShellIds\\Microsoft.PowerShell* Registry.registry_key_name=ExecutionPolicy (Registry.registry_value_name=Unrestricted OR Registry.registry_value_name=Bypass) by Registry.registry_path Registry.registry_key_name Registry.registry_value_name Registry.dest 
| `drop_dm_object_name(Registry)` 
| `security_content_ctime(firstTime)`
|`security_content_ctime(lastTime)` 
| `set_default_powershell_execution_policy_to_unrestricted_or_bypass_filter`
```

#### Associated Analytic Story
* [Malicious PowerShell](/stories/malicious_powershell)
* [Credential Dumping](/stories/credential_dumping)
* [HAFNIUM Group](/stories/hafnium_group)


#### How To Implement
You must be ingesting data that records process activity from your hosts to populate the Endpoint data model in the Registry node. You must also be ingesting logs with the fields registry_path, registry_key_name, and registry_value_name from your endpoints.

#### Required field
* _time
* Registry.registry_path
* Registry.registry_key_name
* Registry.registry_value_name
* Registry.dest


#### Kill Chain Phase
* Installation
* Actions on Objectives


#### Known False Positives
Administrators may attempt to change the default execution policy on a system for a variety of reasons. However, setting the policy to &#34;unrestricted&#34; or &#34;bypass&#34; as this search is designed to identify, would be unusual. Hits should be reviewed and investigated as appropriate.


#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 48.0 | 60 | 80 | A registry modification in $registry_path$ with reg key $registry_key_name$ and reg value $registry_value_name$ in host $dest$ |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)

* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_execution_policy/windows-sysmon.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_execution_policy/windows-sysmon.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/set_default_powershell_execution_policy_to_unrestricted_or_bypass.yml) \| *version*: **6**