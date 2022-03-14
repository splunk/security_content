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
| [AdsiSearcher Account Discovery](/endpoint/adsisearcher_account_discovery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Domain Account Discovery with Dsquery](/endpoint/domain_account_discovery_with_dsquery/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| Hunting |
| [Domain Account Discovery With Net App](/endpoint/domain_account_discovery_with_net_app/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Domain Account Discovery with Wmic](/endpoint/domain_account_discovery_with_wmic/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Domain Controller Discovery with Nltest](/endpoint/domain_controller_discovery_with_nltest/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [Domain Controller Discovery with Wmic](/endpoint/domain_controller_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [Domain Group Discovery with Adsisearcher](/endpoint/domain_group_discovery_with_adsisearcher/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [Domain Group Discovery With Dsquery](/endpoint/domain_group_discovery_with_dsquery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [Domain Group Discovery With Net](/endpoint/domain_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [Domain Group Discovery With Wmic](/endpoint/domain_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [DSQuery Domain Discovery](/endpoint/dsquery_domain_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Elevated Group Discovery With Net](/endpoint/elevated_group_discovery_with_net/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [Elevated Group Discovery with PowerView](/endpoint/elevated_group_discovery_with_powerview/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [Elevated Group Discovery With Wmic](/endpoint/elevated_group_discovery_with_wmic/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [Get ADDefaultDomainPasswordPolicy with Powershell](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery)| Hunting |
| [Get ADDefaultDomainPasswordPolicy with Powershell Script Block](/endpoint/get_addefaultdomainpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery)| Hunting |
| [Get ADUser with PowerShell](/endpoint/get_aduser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| Hunting |
| [Get ADUser with PowerShell Script Block](/endpoint/get_aduser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| Hunting |
| [Get ADUserResultantPasswordPolicy with Powershell](/endpoint/get_aduserresultantpasswordpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery)| TTP |
| [Get ADUserResultantPasswordPolicy with Powershell Script Block](/endpoint/get_aduserresultantpasswordpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery)| TTP |
| [Get DomainPolicy with Powershell](/endpoint/get_domainpolicy_with_powershell/) | [Password Policy Discovery](/tags/#password-policy-discovery)| TTP |
| [Get DomainPolicy with Powershell Script Block](/endpoint/get_domainpolicy_with_powershell_script_block/) | [Password Policy Discovery](/tags/#password-policy-discovery)| TTP |
| [Get-DomainTrust with PowerShell](/endpoint/get-domaintrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Get-DomainTrust with PowerShell Script Block](/endpoint/get-domaintrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Get DomainUser with PowerShell](/endpoint/get_domainuser_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Get DomainUser with PowerShell Script Block](/endpoint/get_domainuser_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [Get-ForestTrust with PowerShell](/endpoint/get-foresttrust_with_powershell/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Get-ForestTrust with PowerShell Script Block](/endpoint/get-foresttrust_with_powershell_script_block/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Get WMIObject Group Discovery](/endpoint/get_wmiobject_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [Get WMIObject Group Discovery with Script Block Logging](/endpoint/get_wmiobject_group_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [GetAdComputer with PowerShell](/endpoint/getadcomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [GetAdComputer with PowerShell Script Block](/endpoint/getadcomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [GetAdGroup with PowerShell](/endpoint/getadgroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [GetAdGroup with PowerShell Script Block](/endpoint/getadgroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| Hunting |
| [GetCurrent User with PowerShell](/endpoint/getcurrent_user_with_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [GetCurrent User with PowerShell Script Block](/endpoint/getcurrent_user_with_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [GetDomainComputer with PowerShell](/endpoint/getdomaincomputer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [GetDomainComputer with PowerShell Script Block](/endpoint/getdomaincomputer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [GetDomainController with PowerShell](/endpoint/getdomaincontroller_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [GetDomainController with PowerShell Script Block](/endpoint/getdomaincontroller_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [GetDomainGroup with PowerShell](/endpoint/getdomaingroup_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [GetDomainGroup with PowerShell Script Block](/endpoint/getdomaingroup_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [GetLocalUser with PowerShell](/endpoint/getlocaluser_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [GetLocalUser with PowerShell Script Block](/endpoint/getlocaluser_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [GetNetTcpconnection with PowerShell](/endpoint/getnettcpconnection_with_powershell/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [GetNetTcpconnection with PowerShell Script Block](/endpoint/getnettcpconnection_with_powershell_script_block/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [GetWmiObject Ds Computer with PowerShell](/endpoint/getwmiobject_ds_computer_with_powershell/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [GetWmiObject Ds Computer with PowerShell Script Block](/endpoint/getwmiobject_ds_computer_with_powershell_script_block/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [GetWmiObject Ds Group with PowerShell](/endpoint/getwmiobject_ds_group_with_powershell/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [GetWmiObject Ds Group with PowerShell Script Block](/endpoint/getwmiobject_ds_group_with_powershell_script_block/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Domain Groups](/tags/#domain-groups)| TTP |
| [GetWmiObject DS User with PowerShell](/endpoint/getwmiobject_ds_user_with_powershell/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [GetWmiObject DS User with PowerShell Script Block](/endpoint/getwmiobject_ds_user_with_powershell_script_block/) | [Domain Account](/tags/#domain-account), [Account Discovery](/tags/#account-discovery)| TTP |
| [GetWmiObject User Account with PowerShell](/endpoint/getwmiobject_user_account_with_powershell/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [GetWmiObject User Account with PowerShell Script Block](/endpoint/getwmiobject_user_account_with_powershell_script_block/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [Local Account Discovery with Net](/endpoint/local_account_discovery_with_net/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [Local Account Discovery With Wmic](/endpoint/local_account_discovery_with_wmic/) | [Account Discovery](/tags/#account-discovery), [Local Account](/tags/#local-account)| Hunting |
| [Net Localgroup Discovery](/endpoint/net_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [Network Connection Discovery With Arp](/endpoint/network_connection_discovery_with_arp/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [Network Connection Discovery With Net](/endpoint/network_connection_discovery_with_net/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [Network Connection Discovery With Netstat](/endpoint/network_connection_discovery_with_netstat/) | [System Network Connections Discovery](/tags/#system-network-connections-discovery)| Hunting |
| [Network Discovery Using Route Windows App](/endpoint/network_discovery_using_route_windows_app/) | [System Network Configuration Discovery](/tags/#system-network-configuration-discovery), [Internet Connection Discovery](/tags/#internet-connection-discovery)| Hunting |
| [NLTest Domain Trust Discovery](/endpoint/nltest_domain_trust_discovery/) | [Domain Trust Discovery](/tags/#domain-trust-discovery)| TTP |
| [Password Policy Discovery with Net](/endpoint/password_policy_discovery_with_net/) | [Password Policy Discovery](/tags/#password-policy-discovery)| Hunting |
| [PowerShell Get LocalGroup Discovery](/endpoint/powershell_get_localgroup_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [Powershell Get LocalGroup Discovery with Script Block Logging](/endpoint/powershell_get_localgroup_discovery_with_script_block_logging/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |
| [Remote System Discovery with Adsisearcher](/endpoint/remote_system_discovery_with_adsisearcher/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [Remote System Discovery with Dsquery](/endpoint/remote_system_discovery_with_dsquery/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [Remote System Discovery with Net](/endpoint/remote_system_discovery_with_net/) | [Remote System Discovery](/tags/#remote-system-discovery)| Hunting |
| [Remote System Discovery with Wmic](/endpoint/remote_system_discovery_with_wmic/) | [Remote System Discovery](/tags/#remote-system-discovery)| TTP |
| [ServicePrincipalNames Discovery with PowerShell](/endpoint/serviceprincipalnames_discovery_with_powershell/) | [Kerberoasting](/tags/#kerberoasting)| TTP |
| [ServicePrincipalNames Discovery with SetSPN](/endpoint/serviceprincipalnames_discovery_with_setspn/) | [Kerberoasting](/tags/#kerberoasting)| TTP |
| [System User Discovery With Query](/endpoint/system_user_discovery_with_query/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [System User Discovery With Whoami](/endpoint/system_user_discovery_with_whoami/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [User Discovery With Env Vars PowerShell](/endpoint/user_discovery_with_env_vars_powershell/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [User Discovery With Env Vars PowerShell Script Block](/endpoint/user_discovery_with_env_vars_powershell_script_block/) | [System Owner/User Discovery](/tags/#system-owner/user-discovery)| Hunting |
| [Wmic Group Discovery](/endpoint/wmic_group_discovery/) | [Permission Groups Discovery](/tags/#permission-groups-discovery), [Local Groups](/tags/#local-groups)| Hunting |

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