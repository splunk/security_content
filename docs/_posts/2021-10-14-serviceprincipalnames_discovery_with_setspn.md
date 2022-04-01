---
title: "ServicePrincipalNames Discovery with SetSPN"
excerpt: "Kerberoasting
"
categories:
  - Endpoint
last_modified_at: 2021-10-14
toc: true
toc_label: ""
tags:
  - Kerberoasting
  - Credential Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies `setspn.exe` usage related to querying the domain for Service Principle Names. typically, this is a precursor activity related to kerberoasting or the silver ticket attack. \
What is a ServicePrincipleName? \
A service principal name (SPN) is a unique identifier of a service instance. SPNs are used by Kerberos authentication to associate a service instance with a service logon account. This allows a client application to request that the service authenticate an account even if the client does not have the account name.\
Example usage includes the following \
1. setspn -T offense -Q */* 1. setspn -T attackrange.local -F -Q MSSQLSvc/* 1. setspn -Q */* > allspns.txt 1. setspn -q \
Values \
1. -F = perform queries at the forest, rather than domain level 1. -T = perform query on the specified domain or forest (when -F is also used) 1. -Q = query for existence of SPN \
During triage, review parallel processes for further suspicious activity.

- **Type**: [TTP](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)- **Datasource**: [Splunk Add-on for Sysmon](https://splunkbase.splunk.com/app/5709)
- **Last Updated**: 2021-10-14
- **Author**: Michael Haag, Splunk
- **ID**: ae8b3efc-2d2e-11ec-8b57-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1558.003](https://attack.mitre.org/techniques/T1558/003/) | Kerberoasting | Credential Access |

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

| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where `process_setspn` (Processes.process="*-t*" AND Processes.process="*-f*") OR (Processes.process="*-q*" AND Processes.process="**/**") OR (Processes.process="*-q*") OR (Processes.process="*-s*") by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.original_file_name Processes.process Processes.process_id Processes.parent_process_id 
| `drop_dm_object_name(Processes)` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)`
| `serviceprincipalnames_discovery_with_setspn_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)
* [security_content_summariesonly](https://github.com/splunk/security_content/blob/develop/macros/security_content_summariesonly.yml)
* [process_setspn](https://github.com/splunk/security_content/blob/develop/macros/process_setspn.yml)

Note that **serviceprincipalnames_discovery_with_setspn_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

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
False positives may be caused by Administrators resetting SPNs or querying for SPNs. Filter as needed.

#### Associated Analytic story
* [Active Directory Discovery](/stories/active_directory_discovery)
* [Active Directory Kerberos Attacks](/stories/active_directory_kerberos_attacks)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 80.0 | 80 | 100 | An instance of $parent_process_name$ spawning $process_name$ was identified on endpoint $dest$ by user $user$ attempting to identify service principle names. |


#### Reference

* [https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names](https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names)
* [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting)
* [https://strontic.github.io/xcyclopedia/library/setspn.exe-5C184D581524245DAD7A0A02B51FD2C2.html](https://strontic.github.io/xcyclopedia/library/setspn.exe-5C184D581524245DAD7A0A02B51FD2C2.html)
* [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
* [https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spn-setspn-syntax.aspx](https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spn-setspn-syntax.aspx)
* [https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
* [https://blog.zsec.uk/paving-2-da-wholeset/](https://blog.zsec.uk/paving-2-da-wholeset/)
* [https://msitpros.com/?p=3113](https://msitpros.com/?p=3113)
* [https://adsecurity.org/?p=3466](https://adsecurity.org/?p=3466)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/atomic_red_team/windows-sysmon_setspn.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/atomic_red_team/windows-sysmon_setspn.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/serviceprincipalnames_discovery_with_setspn.yml) \| *version*: **1**