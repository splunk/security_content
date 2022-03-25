---
title: "Detect Mimikatz Via PowerShell And EventCode 4703"
excerpt: "LSASS Memory
"
categories:
  - Deprecated
last_modified_at: 2019-02-27
toc: true
toc_label: ""
tags:
  - LSASS Memory
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

This search looks for PowerShell requesting privileges consistent with credential dumping. Deprecated, looks like things changed from a logging perspective.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/object-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud


- **Last Updated**: 2019-02-27
- **Author**: Rico Valdez, Splunk
- **ID**: 98917be2-bfc8-475a-8618-a9bb06575188


#### [ATT&CK](https://attack.mitre.org/)

| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | LSASS Memory | Credential Access |

#### Search

```
`wineventlog_security` signature_id=4703 Process_Name=*powershell.exe 
| rex field=Message "Enabled Privileges:\s+(?<privs>\w+)\s+Disabled Privileges:" 
| where privs="SeDebugPrivilege" 
| stats count min(_time) as firstTime max(_time) as lastTime by dest, Process_Name, privs, Process_ID, Message 
| rename privs as "Enabled Privilege" 
| rename Process_Name as process 
|  `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)` 
| `detect_mimikatz_via_powershell_and_eventcode_4703_filter`
```

#### Macros
The SPL above uses the following Macros:
* [wineventlog_security](https://github.com/splunk/security_content/blob/develop/macros/wineventlog_security.yml)
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

Note that `detect_mimikatz_via_powershell_and_eventcode_4703_filter` is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* signature_id
* Process_Name
* Message
* dest
* Process_ID


#### How To Implement
You must be ingesting Windows Security logs. You must also enable the account change auditing here: http://docs.splunk.com/Documentation/Splunk/7.0.2/Data/MonitorWindowseventlogdata. Additionally, this search requires you to enable your Group Management Audit Logs in your Local Windows Security Policy and to be ingesting those logs.  More information on how to enable them can be found here: http://whatevernetworks.com/auditing-group-membership-changes-in-active-directory/. Finally, please make sure that the local administrator group name is "Administrators" to be able to look for the right group membership changes.

#### Known False Positives
The activity may be legitimate. PowerShell is often used by administrators to perform various tasks, and it's possible this event could be generated in those cases. In these cases, false positives should be fairly obvious and you may need to tweak the search to eliminate noise.

#### Associated Analytic story
* [Cloud Federated Credential Abuse](/stories/cloud_federated_credential_abuse)


#### Kill Chain Phase
* Actions on Objectives



#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 25.0 | 50 | 50 | tbd |




#### Reference


#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [`replay.py`](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/deprecated/detect_mimikatz_via_powershell_and_eventcode_4703.yml) \| *version*: **2**