---
title: "Active Directory Kerberos Attacks"
last_modified_at: 2022-02-02
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Network_Traffic
  - Actions on Objectives
  - Exploitation
  - Installation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Kerberos based attacks within with Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint), [Network_Traffic](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkTraffic)
- **Last Updated**: 2022-02-02
- **Author**: Mauricio Velazco, Splunk
- **ID**: 38b8cf16-8461-11ec-ade1-acde48001122

#### Narrative

Kerberos, initially named after Cerberus, the three-headed dog in Greek mythology, is a network authentication protocol that allows computers and users to prove their identity through a trusted third-party. This trusted third-party issues Kerberos tickets using symmetric encryption to allow users access to services and network resources based on their privilege level. Kerberos is the default authentication protocol used on Windows Active Directory networks since the introduction of Windows Server 2003. With Kerberos being the backbone of Windows authentication, it is commonly abused by adversaries across the different phases of a breach including initial access, privilege escalation, defense evasion, credential access, lateral movement, etc.\ This Analytic Story groups detection use cases in which the Kerberos protocol is abused. Defenders can leverage these analytics to detect and hunt for adversaries engaging in Kerberos based attacks.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Disabled Kerberos Pre-Authentication Discovery With Get-ADUser](/endpoint/disabled_kerberos_pre-authentication_discovery_with_get-aduser/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting)| TTP |
| [Disabled Kerberos Pre-Authentication Discovery With PowerView](/endpoint/disabled_kerberos_pre-authentication_discovery_with_powerview/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting)| TTP |
| [Kerberoasting spn request with RC4 encryption](/endpoint/kerberoasting_spn_request_with_rc4_encryption/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting)| TTP |
| [Kerberos Pre-Authentication Flag Disabled in UserAccountControl](/endpoint/kerberos_pre-authentication_flag_disabled_in_useraccountcontrol/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting)| TTP |
| [Kerberos Pre-Authentication Flag Disabled with PowerShell](/endpoint/kerberos_pre-authentication_flag_disabled_with_powershell/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [AS-REP Roasting](/tags/#as-rep-roasting)| TTP |
| [Kerberos Service Ticket Request Using RC4 Encryption](/endpoint/kerberos_service_ticket_request_using_rc4_encryption/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Golden Ticket](/tags/#golden-ticket)| TTP |
| [Kerberos TGT Request Using RC4 Encryption](/endpoint/kerberos_tgt_request_using_rc4_encryption/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material)| TTP |
| [Kerberos User Enumeration](/endpoint/kerberos_user_enumeration/) | [Gather Victim Identity Information](/tags/#gather-victim-identity-information), [Email Addresses](/tags/#email-addresses)| Anomaly |
| [Mimikatz PassTheTicket CommandLine Parameters](/endpoint/mimikatz_passtheticket_commandline_parameters/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket)| TTP |
| [Multiple Users Failing To Authenticate From Host Using Kerberos](/endpoint/multiple_users_failing_to_authenticate_from_host_using_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [PetitPotam Suspicious Kerberos TGT Request](/endpoint/petitpotam_suspicious_kerberos_tgt_request/) | [OS Credential Dumping](/tags/#os-credential-dumping)| TTP |
| [Rubeus Command Line Parameters](/endpoint/rubeus_command_line_parameters/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket), [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting), [AS-REP Roasting](/tags/#as-rep-roasting)| TTP |
| [Rubeus Kerberos Ticket Exports Through Winlogon Access](/endpoint/rubeus_kerberos_ticket_exports_through_winlogon_access/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material), [Pass the Ticket](/tags/#pass-the-ticket)| TTP |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | [Kerberoasting](/tags/#kerberoasting)| TTP |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | [Kerberoasting](/tags/#kerberoasting)| TTP |
| [Suspicious Kerberos Service Ticket Request](/endpoint/suspicious_kerberos_service_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts)| TTP |
| [Suspicious Ticket Granting Ticket Request](/endpoint/suspicious_ticket_granting_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts)| Hunting |
| [Unknown Process Using The Kerberos Protocol](/endpoint/unknown_process_using_the_kerberos_protocol/) | [Use Alternate Authentication Material](/tags/#use-alternate-authentication-material)| TTP |
| [Unusual Number of Kerberos Service Tickets Requested](/endpoint/unusual_number_of_kerberos_service_tickets_requested/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting)| Anomaly |
| [Windows Computer Account Created by Computer Account](/endpoint/windows_computer_account_created_by_computer_account/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets)| TTP |
| [Windows Computer Account Requesting Kerberos Ticket](/endpoint/windows_computer_account_requesting_kerberos_ticket/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets)| TTP |
| [Windows Computer Account With SPN](/endpoint/windows_computer_account_with_spn/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets)| TTP |
| [Windows Disabled Users Failing To Authenticate Kerberos](/endpoint/windows_disabled_users_failing_to_authenticate_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Windows Get-AdComputer Unconstrained Delegation Discovery](/endpoint/windows_get-adcomputer_unconstrained_delegation_discovery/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [Windows Invalid Users Failed Authentication via Kerberos](/endpoint/windows_invalid_users_failed_authentication_via_kerberos/) | [Password Spraying](/tags/#password-spraying), [Brute Force](/tags/#brute-force)| Anomaly |
| [Windows Kerberos Local Successful Logon](/endpoint/windows_kerberos_local_successful_logon/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets)| TTP |
| [Windows PowerView Constrained Delegation Discovery](/endpoint/windows_powerview_constrained_delegation_discovery/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [Windows PowerView Kerberos Service Ticket Request](/endpoint/windows_powerview_kerberos_service_ticket_request/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting)| TTP |
| [Windows PowerView SPN Discovery](/endpoint/windows_powerview_spn_discovery/) | [Steal or Forge Kerberos Tickets](/tags/#steal-or-forge-kerberos-tickets), [Kerberoasting](/tags/#kerberoasting)| TTP |
| [Windows PowerView Unconstrained Delegation Discovery](/endpoint/windows_powerview_unconstrained_delegation_discovery/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [Unusual Number of Computer Service Tickets Requested](/endpoint/unusual_number_of_computer_service_tickets_requested/) | [Valid Accounts](/tags/#valid-accounts)| Hunting |

#### Reference

* [https://en.wikipedia.org/wiki/Kerberos_(protocol)](https://en.wikipedia.org/wiki/Kerberos_(protocol))
* [https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/2a32282e-dd48-4ad9-a542-609804b02cc9)
* [https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html](https://m0chan.github.io/2019/07/31/How-To-Attack-Kerberos-101.html)
* [https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/](https://stealthbits.com/blog/cracking-active-directory-passwords-with-as-rep-roasting/)
* [https://attack.mitre.org/techniques/T1558/003/](https://attack.mitre.org/techniques/T1558/003/)
* [https://attack.mitre.org/techniques/T1550/003/](https://attack.mitre.org/techniques/T1550/003/)
* [https://attack.mitre.org/techniques/T1558/004/](https://attack.mitre.org/techniques/T1558/004/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_kerberos_attacks.yml) \| *version*: **1**