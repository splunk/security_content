---
title: "Windows Discovery Techniques"
last_modified_at: 2021-03-04
toc: true
tags:
  - Splunk Behavioral Analytics
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Monitors for behaviors associated with adversaries discovering objects in the environment that can be leveraged in the progression of the attack.

- **ID**: f7aba570-7d59-11eb-825e-acde48001122
- **Product**: Splunk Behavioral Analytics, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-03-04
- **Author**: Michael Hart, Splunk

#### Narrative

Attackers may not have much if any insight into their target's environment before the initial compromise.  Once a foothold has been established, attackers will start enumerating objects in the environment (accounts, services, network shares, etc.) that can be used to achieve their objectives.  This Analytic Story provides searches to help identify activities consistent with adversaries gaining knowledge of compromised Windows environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules](/endpoint/reconnaissance_and_access_to_accounts_groups_and_policies_via_powersploit_modules/) | None | TTP |
| [Reconnaissance and Access to Accounts and Groups via Mimikatz modules](/endpoint/reconnaissance_and_access_to_accounts_and_groups_via_mimikatz_modules/) | None | TTP |
| [Reconnaissance and Access to Active Directoty Infrastructure via PowerSploit modules](/endpoint/reconnaissance_and_access_to_active_directoty_infrastructure_via_powersploit_modules/) | None | TTP |
| [Reconnaissance and Access to Computers and Domains via PowerSploit modules](/endpoint/reconnaissance_and_access_to_computers_and_domains_via_powersploit_modules/) | None | TTP |
| [Reconnaissance and Access to Computers via Mimikatz modules](/endpoint/reconnaissance_and_access_to_computers_via_mimikatz_modules/) | None | TTP |
| [Reconnaissance and Access to Operating System Elements via PowerSploit modules](/endpoint/reconnaissance_and_access_to_operating_system_elements_via_powersploit_modules/) | None | TTP |
| [Reconnaissance and Access to Processes and Services via Mimikatz modules](/endpoint/reconnaissance_and_access_to_processes_and_services_via_mimikatz_modules/) | None | TTP |
| [Reconnaissance and Access to Shared Resources via Mimikatz modules](/endpoint/reconnaissance_and_access_to_shared_resources_via_mimikatz_modules/) | None | TTP |
| [Reconnaissance and Access to Shared Resources via PowerSploit modules](/endpoint/reconnaissance_and_access_to_shared_resources_via_powersploit_modules/) | None | TTP |
| [Reconnaissance of Access and Persistence Opportunities via PowerSploit modules](/endpoint/reconnaissance_of_access_and_persistence_opportunities_via_powersploit_modules/) | None | TTP |
| [Reconnaissance of Connectivity via PowerSploit modules](/endpoint/reconnaissance_of_connectivity_via_powersploit_modules/) | None | TTP |
| [Reconnaissance of Credential Stores and Services via Mimikatz modules](/endpoint/reconnaissance_of_credential_stores_and_services_via_mimikatz_modules/) | None | TTP |
| [Reconnaissance of Defensive Tools via PowerSploit modules](/endpoint/reconnaissance_of_defensive_tools_via_powersploit_modules/) | None | TTP |
| [Reconnaissance of Privilege Escalation Opportunities via PowerSploit modules](/endpoint/reconnaissance_of_privilege_escalation_opportunities_via_powersploit_modules/) | None | TTP |
| [Reconnaissance of Process or Service Hijacking Opportunities via Mimikatz modules](/endpoint/reconnaissance_of_process_or_service_hijacking_opportunities_via_mimikatz_modules/) | None | TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://cyberd.us/penetration-testing](https://cyberd.us/penetration-testing)
* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_discovery_techniques.yml) \| *version*: **1**