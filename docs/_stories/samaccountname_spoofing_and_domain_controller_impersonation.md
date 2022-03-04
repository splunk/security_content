---
title: "sAMAccountName Spoofing and Domain Controller Impersonation"
last_modified_at: 2021-12-20
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Endpoint
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor for activities and techniques associated with the exploitation of the sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287) vulnerabilities.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Endpoint](https://docs.splunk.com/Documentation/CIM/latest/User/Endpoint)
- **Last Updated**: 2021-12-20
- **Author**: Mauricio Velazco, Splunk
- **ID**: 0244fdee-61be-11ec-900e-acde48001122

#### Narrative

On November 9, 2021, Microsoft released patches to address two vulnerabilities that affect Windows Active Directory networks, sAMAccountName Spoofing (CVE-2021-42278) and Domain Controller Impersonation (CVE-2021-42287). On December 10, 2021, security researchers Charlie Clark and Andrew Schwartz released a blog post where they shared how to weaponise these vulnerabilities in a target network an the initial detection opportunities. When successfully exploited, CVE-2021-42278 and CVE-2021-42287 allow an adversary, who has stolen the credentials of a low priviled domain user, to obtain a Kerberos Service ticket for a Domain Controller computer account. The only requirement is to have network connectivity to a domain controller. This attack vector effectivelly allows attackers to escalate their privileges in an Active Directory from a regular domain user account and take control of a domain controller. While patches have been released to address these vulnerabilities, deploying detection controls for this attack may help help defenders identify attackers attempting exploitation.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Suspicious Computer Account Name Change](/endpoint/suspicious_computer_account_name_change/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts)| TTP |
| [Suspicious Kerberos Service Ticket Request](/endpoint/suspicious_kerberos_service_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts)| TTP |
| [Suspicious Ticket Granting Ticket Request](/endpoint/suspicious_ticket_granting_ticket_request/) | [Valid Accounts](/tags/#valid-accounts), [Domain Accounts](/tags/#domain-accounts)| Hunting |

#### Reference

* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278)
* [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287)
* [https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html](https://exploit.ph/cve-2021-42287-cve-2021-42278-weaponisation.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/samaccountname_spoofing_and_domain_controller_impersonation.yml) \| *version*: **1**