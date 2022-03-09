---
title: "Active Directory Discovery"
last_modified_at: 2021-08-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
  - Reconnaissance
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with Discovery and Reconnaissance within with Active Directory environments.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-08-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 8460679c-2b21-463e-b381-b813417c32f2

#### Narrative

Discovery consists of techniques an adversay uses to gain knowledge about an internal environment or network. These techniques provide adversaries with situational awareness and allows them to have the necessary information before deciding how to act or who/what to target next.\
Once an attacker obtains an initial foothold in an Active Directory environment, she is forced to engage in Discovery techniques in the initial phases of a breach to better understand and navigate the target network. Some examples include but are not limited to enumerating domain users, domain admins, computers, domain controllers, network shares, group policy objects, domain trusts, etc.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [AdsiSearcher Account Discovery](/endpoint/adsisearcher_account_discovery/) | None| TTP |
| [Domain Account Discovery with Dsquery](/endpoint/domain_account_discovery_with_dsquery/) | None| Hunting |
| [Domain Account Discovery With Net App](/endpoint/domain_account_discovery_with_net_app/) | None| TTP |
| [Domain Account Discovery with Wmic](/endpoint/domain_account_discovery_with_wmic/) | None| TTP |
| [Domain Controller Discovery with Nltest](/endpoint/domain_controller_discovery_with_nltest/) | None| TTP |
| [Domain Controller Discovery with Wmic](/endpoint/domain_controller_discovery_with_wmic/) | None| Hunting |
| [Domain Group Discovery with Adsisearcher](/endpoint/domain_group_discovery_with_adsisearcher/) | None| TTP |
| [Domain Group Discovery With Dsquery](/endpoint/domain_group_discovery_with_dsquery/) | None| Hunting |
| [Domain Group Discovery With Net](/endpoint/domain_group_discovery_with_net/) | None| Hunting |
| [Domain Group Discovery With Wmic](/endpoint/domain_group_discovery_with_wmic/) | None| Hunting |
| [DSQuery Domain Discovery](/endpoint/dsquery_domain_discovery/) | None| TTP |
| [Elevated Group Discovery With Net](/endpoint/elevated_group_discovery_with_net/) | None| TTP |
| [Elevated Group Discovery with PowerView](/endpoint/elevated_group_discovery_with_powerview/) | None| Hunting |
| [Elevated Group Discovery With Wmic](/endpoint/elevated_group_discovery_with_wmic/) | None| TTP |
| [Get ADDefaultDomainPasswordPolicy with Powershell](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell/) | None| Hunting |
| [Get ADDefaultDomainPasswordPolicy with Powershell Script Block](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell_script_block/) | None| Hunting |
| [Get ADUser with PowerShell](/endpoint/get_aduser_with_powershell/) | None| Hunting |
| [Get ADUser with PowerShell Script Block](/endpoint/get_aduser_with_powershell_script_block/) | None| Hunting |
| [Get ADUserResultantPasswordPolicy with Powershell](/endpoint/get_aduserresultantpasswordpolicy_with_powershell/) | None| TTP |
| [Get ADUserResultantPasswordPolicy with Powershell Script Block](/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block/) | None| TTP |
| [Get DomainPolicy with Powershell](/endpoint/get_domainpolicy_with_powershell/) | None| TTP |
| [Get DomainPolicy with Powershell Script Block](/endpoint/get_domainpolicy_with_powershell_script_block/) | None| TTP |
| [Get-DomainTrust with PowerShell](/endpoint/get-domaintrust_with_powershell/) | None| TTP |
| [Get-DomainTrust with PowerShell Script Block](/endpoint/get-domaintrust_with_powershell_script_block/) | None| TTP |
| [Get DomainUser with PowerShell](/endpoint/get_domainuser_with_powershell/) | None| TTP |
| [Get DomainUser with PowerShell Script Block](/endpoint/get_domainuser_with_powershell_script_block/) | None| TTP |
| [Get-ForestTrust with PowerShell](/endpoint/get-foresttrust_with_powershell/) | None| TTP |
| [Get-ForestTrust with PowerShell Script Block](/endpoint/get-foresttrust_with_powershell_script_block/) | None| TTP |
| [Get WMIObject Group Discovery](/endpoint/get_wmiobject_group_discovery/) | None| Hunting |
| [Get WMIObject Group Discovery with Script Block Logging](/endpoint/get_wmiobject_group_discovery_with_script_block_logging/) | None| Hunting |
| [GetAdComputer with PowerShell](/endpoint/getadcomputer_with_powershell/) | None| Hunting |
| [GetAdComputer with PowerShell Script Block](/endpoint/getadcomputer_with_powershell_script_block/) | None| Hunting |
| [GetAdGroup with PowerShell](/endpoint/getadgroup_with_powershell/) | None| Hunting |
| [GetAdGroup with PowerShell Script Block](/endpoint/getadgroup_with_powershell_script_block/) | None| Hunting |
| [GetCurrent User with PowerShell](/endpoint/getcurrent_user_with_powershell/) | None| Hunting |
| [GetCurrent User with PowerShell Script Block](/endpoint/getcurrent_user_with_powershell_script_block/) | None| Hunting |
| [GetDomainComputer with PowerShell](/endpoint/getdomaincomputer_with_powershell/) | None| TTP |
| [GetDomainComputer with PowerShell Script Block](/endpoint/getdomaincomputer_with_powershell_script_block/) | None| TTP |
| [GetDomainController with PowerShell](/endpoint/getdomaincontroller_with_powershell/) | None| Hunting |
| [GetDomainController with PowerShell Script Block](/endpoint/getdomaincontroller_with_powershell_script_block/) | None| TTP |
| [GetDomainGroup with PowerShell](/endpoint/getdomaingroup_with_powershell/) | None| TTP |
| [GetDomainGroup with PowerShell Script Block](/endpoint/getdomaingroup_with_powershell_script_block/) | None| TTP |
| [GetLocalUser with PowerShell](/endpoint/getlocaluser_with_powershell/) | None| Hunting |
| [GetLocalUser with PowerShell Script Block](/endpoint/getlocaluser_with_powershell_script_block/) | None| Hunting |
| [GetNetTcpconnection with PowerShell](/endpoint/getnettcpconnection_with_powershell/) | None| Hunting |
| [GetNetTcpconnection with PowerShell Script Block](/endpoint/getnettcpconnection_with_powershell_script_block/) | None| Hunting |
| [GetWmiObject Ds Computer with PowerShell](/endpoint/getwmiobject_ds_computer_with_powershell/) | None| TTP |
| [GetWmiObject Ds Computer with PowerShell Script Block](/endpoint/getwmiobject_ds_computer_with_powershell_script_block/) | None| TTP |
| [GetWmiObject Ds Group with PowerShell](/endpoint/getwmiobject_ds_group_with_powershell/) | None| TTP |
| [GetWmiObject Ds Group with PowerShell Script Block](/endpoint/getwmiobject_ds_group_with_powershell_script_block/) | None| TTP |
| [GetWmiObject DS User with PowerShell](/endpoint/getwmiobject_ds_user_with_powershell/) | None| TTP |
| [GetWmiObject DS User with PowerShell Script Block](/endpoint/getwmiobject_ds_user_with_powershell_script_block/) | None| TTP |
| [GetWmiObject User Account with PowerShell](/endpoint/getwmiobject_user_account_with_powershell/) | None| Hunting |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/getwmiobject_user_account_with_powershell_script_block/) | None| Hunting |
| [Local Account Discovery with Net](/endpoint/local_account_discovery_with_net/) | None| Hunting |
| [Local Account Discovery With Wmic](/endpoint/local_account_discovery_with_wmic/) | None| Hunting |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | None| Hunting |
| [Network Connection Discovery With Arp](/endpoint/network_connection_discovery_with_arp/) | None| Hunting |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | None| Hunting |
| [Network Connection Discovery With Netstat](/endpoint/network_connection_discovery_with_netstat/) | None| Hunting |
| [Network Discovery Using Route Windows App](/endpoint/network_discovery_using_route_windows_app/) | None| Hunting |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | None| TTP |
| [Password Policy Discovery with Net](/endpoint/password_policy_discovery_with_net/) | None| Hunting |
| [PowerShell Get LocalGroup Discovery](/endpoint/powershell_get_localgroup_discovery/) | None| Hunting |
| [Powershell Get LocalGroup Discovery with Script Block Logging](/endpoint/powershell_get_localgroup_discovery_with_script_block_logging/) | None| Hunting |
| [Remote System Discovery with Adsisearcher](/endpoint/remote_system_discovery_with_adsisearcher/) | None| TTP |
| [Remote System Discovery with Dsquery](/endpoint/remote_system_discovery_with_dsquery/) | None| Hunting |
| [Remote System Discovery with Net](/endpoint/remote_system_discovery_with_net/) | None| Hunting |
| [Remote System Discovery with Wmic](/endpoint/remote_system_discovery_with_wmic/) | None| TTP |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | None| TTP |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | None| TTP |
| [System User Discovery With Query](/endpoint/system_user_discovery_with_query/) | None| Hunting |
| [System User Discovery With Whoami](/endpoint/system_user_discovery_with_whoami/) | None| Hunting |
| [User Discovery With Env Vars PowerShell](/endpoint/user_discovery_with_env_vars_powershell/) | None| Hunting |
| [User Discovery With Env Vars PowerShell Script Block](/endpoint/user_discovery_with_env_vars_powershell_script_block/) | None| Hunting |
| [Wmic Group Discovery](/endpoint/wmic_group_discovery/) | None| Hunting |

#### Reference

* [https://attack.mitre.org/tactics/TA0007/](https://attack.mitre.org/tactics/TA0007/)
* [https://adsecurity.org/?p=2535](https://adsecurity.org/?p=2535)
* [https://attack.mitre.org/techniques/T1087/001/](https://attack.mitre.org/techniques/T1087/001/)
* [https://attack.mitre.org/techniques/T1087/002/](https://attack.mitre.org/techniques/T1087/002/)
* [https://attack.mitre.org/techniques/T1087/003/](https://attack.mitre.org/techniques/T1087/003/)
* [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)
* [https://attack.mitre.org/techniques/T1201/](https://attack.mitre.org/techniques/T1201/)
* [https://attack.mitre.org/techniques/T1069/001/](https://attack.mitre.org/techniques/T1069/001/)
* [https://attack.mitre.org/techniques/T1069/002/](https://attack.mitre.org/techniques/T1069/002/)
* [https://attack.mitre.org/techniques/T1018/](https://attack.mitre.org/techniques/T1018/)
* [https://attack.mitre.org/techniques/T1049/](https://attack.mitre.org/techniques/T1049/)
* [https://attack.mitre.org/techniques/T1033/](https://attack.mitre.org/techniques/T1033/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/active_directory_discovery.yml) \| *version*: **1**