---
title: "VMware Workspace ONE Freemarker Server-side Template Injection"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Web
last_modified_at: 2022-05-19
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2022-22954
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_us/products/cyber-security.html){: .btn .btn--success}

#### Description

The following analytic identifies the server side template injection related to CVE-2022-22954. Based on the scanning activity across the internet and proof of concept code available the template injection occurs at catalog-portal/ui/oauth/verify?error=&deviceudid=. Upon triage, review parallel processes and VMware logs. Following the deviceudid= may be a command to be executed. Capture any file creates and review modified files on disk.

- **Type**: [Anomaly](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2022-05-19
- **Author**: Michael Haag, Splunk
- **ID**: 9e5726fe-8fde-460e-bd74-cddcf6c86113


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

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
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2022-22954](https://nvd.nist.gov/vuln/detail/CVE-2022-22954) | VMware Workspace ONE Access and Identity Manager contain a remote code execution vulnerability due to server-side template injection. A malicious actor with network access can trigger a server-side template injection that may result in remote code execution. | 10.0 |



</div>
</details>

#### Search 

```

| tstats count from datamodel=Web where Web.http_method IN ("GET") Web.url="*/catalog-portal/ui/oauth/verify?error=&deviceudid=*" AND Web.url="*freemarker.template.utility.Execute*" by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest sourcetype 
| `drop_dm_object_name("Web")` 
| `security_content_ctime(firstTime)` 
| `security_content_ctime(lastTime)` 
| `vmware_workspace_one_freemarker_server_side_template_injection_filter`
```

#### Macros
The SPL above uses the following Macros:
* [security_content_ctime](https://github.com/splunk/security_content/blob/develop/macros/security_content_ctime.yml)

> :information_source:
> **vmware_workspace_one_freemarker_server-side_template_injection_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* Web.http_method
* Web.url
* Web.url_length
* Web.src
* Web.dest
* Web.http_user_agent


#### How To Implement
To successfully implement this search, you need to be ingesting web or proxy logs, or ensure it is being filled by a proxy like device, into the Web Datamodel. For additional filtering, allow list private IP space or restrict by known good.

#### Known False Positives
False positives may be present if the activity is blocked or was not successful. Filter known vulnerablity scanners. Filter as needed.

#### Associated Analytic story
* [VMware Server Side Injection and Privilege Escalation](/stories/vmware_server_side_injection_and_privilege_escalation)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 49.0 | 70 | 70 | An attempt to exploit a VMware Server Side Injection CVE-2022-22954 on $dest$ has occurred. |


> :information_source:
> The Risk Score is calculated by the following formula: Risk Score = (Impact * Confidence/100). Initial Confidence and Impact is set by the analytic author. 

#### Reference

* [https://www.cisa.gov/uscert/sites/default/files/publications/CISA_CSA_Threat_Actors_Chaining_VMware_Unpatched_Vulnerabilities_for_Full_System_Control.pdf](https://www.cisa.gov/uscert/sites/default/files/publications/CISA_CSA_Threat_Actors_Chaining_VMware_Unpatched_Vulnerabilities_for_Full_System_Control.pdf)
* [https://github.com/wvu/metasploit-framework/blob/master/modules/exploits/linux/http/vmware_workspace_one_access_cve_2022_22954.rb](https://github.com/wvu/metasploit-framework/blob/master/modules/exploits/linux/http/vmware_workspace_one_access_cve_2022_22954.rb)
* [https://github.com/sherlocksecurity/VMware-CVE-2022-22954](https://github.com/sherlocksecurity/VMware-CVE-2022-22954)
* [https://www.vmware.com/security/advisories/VMSA-2022-0011.html](https://www.vmware.com/security/advisories/VMSA-2022-0011.html)
* [https://attackerkb.com/topics/BDXyTqY1ld/cve-2022-22954/rapid7-analysis](https://attackerkb.com/topics/BDXyTqY1ld/cve-2022-22954/rapid7-analysis)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/vmware/vmware_scanning_pan_threat.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/vmware/vmware_scanning_pan_threat.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/web/vmware_workspace_one_freemarker_server_side_template_injection.yml) \| *version*: **1**