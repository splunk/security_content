---
title: "Windows Discovery Techniques"
last_modified_at: 2021-03-04
toc: true
toc_label: ""
tags:
  - Splunk Behavioral Analytics
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitors for behaviors associated with adversaries discovering objects in the environment that can be leveraged in the progression of the attack.

- **Product**: Splunk Behavioral Analytics, Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2021-03-04
- **Author**: Michael Hart, Splunk
- **ID**: f7aba570-7d59-11eb-825e-acde48001122

#### Narrative

Attackers may not have much if any insight into their target's environment before the initial compromise.  Once a foothold has been established, attackers will start enumerating objects in the environment (accounts, services, network shares, etc.) that can be used to achieve their objectives.  This Analytic Story provides searches to help identify activities consistent with adversaries gaining knowledge of compromised Windows environments.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Reconnaissance and Access to Accounts Groups and Policies via PowerSploit modules](/endpoint/reconnaissance_and_access_to_accounts_groups_and_policies_via_powersploit_modules/) | [Valid Accounts](/tags/#valid-accounts), [Account Discovery](/tags/#account-discovery), [Domain Policy Modification](/tags/#domain-policy-modification) | TTP |
| [Reconnaissance and Access to Accounts and Groups via Mimikatz modules](/endpoint/reconnaissance_and_access_to_accounts_and_groups_via_mimikatz_modules/) | [Valid Accounts](/tags/#valid-accounts), [Account Discovery](/tags/#account-discovery), [Domain Policy Modification](/tags/#domain-policy-modification) | TTP |
| [Reconnaissance and Access to Active Directoty Infrastructure via PowerSploit modules](/endpoint/reconnaissance_and_access_to_active_directoty_infrastructure_via_powersploit_modules/) | [Trusted Relationship](/tags/#trusted-relationship), [Domain Trust Discovery](/tags/#domain-trust-discovery), [Gather Victim Network Information](/tags/#gather-victim-network-information), [Gather Victim Org Information](/tags/#gather-victim-org-information), [Active Scanning](/tags/#active-scanning) | TTP |
| [Reconnaissance and Access to Computers and Domains via PowerSploit modules](/endpoint/reconnaissance_and_access_to_computers_and_domains_via_powersploit_modules/) | [Gather Victim Host Information](/tags/#gather-victim-host-information), [Gather Victim Network Information](/tags/#gather-victim-network-information), [Account Discovery](/tags/#account-discovery) | TTP |
| [Reconnaissance and Access to Computers via Mimikatz modules](/endpoint/reconnaissance_and_access_to_computers_via_mimikatz_modules/) | [Gather Victim Host Information](/tags/#gather-victim-host-information) | TTP |
| [Reconnaissance and Access to Operating System Elements via PowerSploit modules](/endpoint/reconnaissance_and_access_to_operating_system_elements_via_powersploit_modules/) | [Process Discovery](/tags/#process-discovery), [File and Directory Discovery](/tags/#file-and-directory-discovery), [Software](/tags/#software), [Network Service Scanning](/tags/#network-service-scanning), [Query Registry](/tags/#query-registry), [System Service Discovery](/tags/#system-service-discovery), [Windows Management Instrumentation](/tags/#windows-management-instrumentation), [Gather Victim Host Information](/tags/#gather-victim-host-information), [Software Discovery](/tags/#software-discovery) | TTP |
| [Reconnaissance and Access to Processes and Services via Mimikatz modules](/endpoint/reconnaissance_and_access_to_processes_and_services_via_mimikatz_modules/) | [System Service Discovery](/tags/#system-service-discovery), [Network Service Scanning](/tags/#network-service-scanning), [Process Discovery](/tags/#process-discovery) | TTP |
| [Reconnaissance and Access to Shared Resources via Mimikatz modules](/endpoint/reconnaissance_and_access_to_shared_resources_via_mimikatz_modules/) | [Remote Services](/tags/#remote-services), [Data from Network Shared Drive](/tags/#data-from-network-shared-drive), [Network Share Discovery](/tags/#network-share-discovery), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Reconnaissance and Access to Shared Resources via PowerSploit modules](/endpoint/reconnaissance_and_access_to_shared_resources_via_powersploit_modules/) | [Remote Services](/tags/#remote-services), [Data from Network Shared Drive](/tags/#data-from-network-shared-drive), [Network Share Discovery](/tags/#network-share-discovery), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Reconnaissance of Access and Persistence Opportunities via PowerSploit modules](/endpoint/reconnaissance_of_access_and_persistence_opportunities_via_powersploit_modules/) | [Scheduled Task/Job](/tags/#scheduled-task/job), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Valid Accounts](/tags/#valid-accounts), [Create or Modify System Process](/tags/#create-or-modify-system-process), [Boot or Logon Autostart Execution](/tags/#boot-or-logon-autostart-execution), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |
| [Reconnaissance of Connectivity via PowerSploit modules](/endpoint/reconnaissance_of_connectivity_via_powersploit_modules/) | [Remote Services](/tags/#remote-services), [Data from Network Shared Drive](/tags/#data-from-network-shared-drive), [Network Share Discovery](/tags/#network-share-discovery), [SMB/Windows Admin Shares](/tags/#smb/windows-admin-shares) | TTP |
| [Reconnaissance of Credential Stores and Services via Mimikatz modules](/endpoint/reconnaissance_of_credential_stores_and_services_via_mimikatz_modules/) | [Account Manipulation](/tags/#account-manipulation), [Domain Properties](/tags/#domain-properties), [Valid Accounts](/tags/#valid-accounts), [Credentials](/tags/#credentials), [Gather Victim Network Information](/tags/#gather-victim-network-information), [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Gather Victim Identity Information](/tags/#gather-victim-identity-information), [Network Trust Dependencies](/tags/#network-trust-dependencies) | TTP |
| [Reconnaissance of Defensive Tools via PowerSploit modules](/endpoint/reconnaissance_of_defensive_tools_via_powersploit_modules/) | [Software](/tags/#software), [Vulnerability Scanning](/tags/#vulnerability-scanning), [Gather Victim Host Information](/tags/#gather-victim-host-information), [Active Scanning](/tags/#active-scanning) | TTP |
| [Reconnaissance of Privilege Escalation Opportunities via PowerSploit modules](/endpoint/reconnaissance_of_privilege_escalation_opportunities_via_powersploit_modules/) | [Exploitation for Privilege Escalation](/tags/#exploitation-for-privilege-escalation), [Valid Accounts](/tags/#valid-accounts), [Account Manipulation](/tags/#account-manipulation) | TTP |
| [Reconnaissance of Process or Service Hijacking Opportunities via Mimikatz modules](/endpoint/reconnaissance_of_process_or_service_hijacking_opportunities_via_mimikatz_modules/) | [Create or Modify System Process](/tags/#create-or-modify-system-process), [Process Injection](/tags/#process-injection), [Hijack Execution Flow](/tags/#hijack-execution-flow) | TTP |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://cyberd.us/penetration-testing](https://cyberd.us/penetration-testing)
* [https://attack.mitre.org/software/S0521/](https://attack.mitre.org/software/S0521/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/windows_discovery_techniques.yml) \| *version*: **1**