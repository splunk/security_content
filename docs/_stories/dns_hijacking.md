---
title: "DNS Hijacking"
last_modified_at: 2020-02-04
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Network_Resolution
  - Actions on Objectives
  - Command & Control
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Secure your environment against DNS hijacks with searches that help you detect and investigate unauthorized changes to DNS records.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Network_Resolution](https://docs.splunk.com/Documentation/CIM/latest/User/NetworkResolution)
- **Last Updated**: 2020-02-04
- **Author**: Bhavin Patel, Splunk
- **ID**: 8169f17b-ef68-4b59-aa28-586907301221

#### Narrative

Dubbed the Achilles heel of the Internet (see https://www.f5.com/labs/articles/threat-intelligence/dns-is-still-the-achilles-heel-of-the-internet-25613), DNS plays a critical role in routing web traffic but is notoriously vulnerable to attack. One reason is its distributed nature. It relies on unstructured connections between millions of clients and servers over inherently insecure protocols.\
The gravity and extent of the importance of securing DNS from attacks is undeniable. The fallout of compromised DNS can be disastrous. Not only can hackers bring down an entire business, they can intercept confidential information, emails, and login credentials, as well. \
On January 22, 2019, the US Department of Homeland Security 2019's Cybersecurity and Infrastructure Security Agency (CISA) raised awareness of some high-profile DNS hijacking attacks against infrastructure, both in the United States and abroad. It issued Emergency Directive 19-01 (see https://cyber.dhs.gov/ed/19-01/), which summarized the activity and required government agencies to take the following four actions, all within 10 days: \
1. For all .gov or other agency-managed domains, audit public DNS records on all authoritative and secondary DNS servers, verify that they resolve to the intended location or report them to CISA.\
1. Update the passwords for all accounts on systems that can make changes to each agency 2019's DNS records.\
1. Implement multi-factor authentication (MFA) for all accounts on systems that can make changes to each agency's 2019 DNS records or, if impossible, provide CISA with the names of systems, the reasons why MFA cannot be enabled within the required timeline, and an ETA for when it can be enabled.\
1. CISA will begin regular delivery of newly added certificates to Certificate Transparency (CT) logs for agency domains via the Cyber Hygiene service. Upon receipt, agencies must immediately begin monitoring CT log data for certificates issued that they did not request. If an agency confirms that a certificate was unauthorized, it must report the certificate to the issuing certificate authority and to CISA. Of course, it makes sense to put equivalent actions in place within your environment, as well. \
In DNS hijacking, the attacker assumes control over an account or makes use of a DNS service exploit to make changes to DNS records. Once they gain access, attackers can substitute their own MX records, name-server records, and addresses, redirecting emails and traffic through their infrastructure, where they can read, copy, or modify information seen. They can also generate valid encryption certificates to help them avoid browser-certificate checks. In one notable attack on the Internet service provider, GoDaddy, the hackers altered Sender Policy Framework (SPF) records a relatively minor change that did not inflict excessive damage but allowed for more effective spam campaigns.\
The searches in this Analytic Story help you detect and investigate activities that may indicate that DNS hijacking has taken place within your environment.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Clients Connecting to Multiple DNS Servers](/deprecated/clients_connecting_to_multiple_dns_servers/) | [Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](/tags/#exfiltration-over-unencrypted/obfuscated-non-c2-protocol)| TTP |
| [DNS Query Requests Resolved by Unauthorized DNS Servers](/deprecated/dns_query_requests_resolved_by_unauthorized_dns_servers/) | [DNS](/tags/#dns)| TTP |
| [DNS record changed](/deprecated/dns_record_changed/) | [DNS](/tags/#dns)| TTP |
| [Detect hosts connecting to dynamic domain providers](/network/detect_hosts_connecting_to_dynamic_domain_providers/) | [Drive-by Compromise](/tags/#drive-by-compromise)| TTP |

#### Reference

* [https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html](https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html)
* [https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/](https://umbrella.cisco.com/blog/2013/04/15/on-the-trail-of-malicious-dynamic-dns-domains/)
* [http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/](http://www.noip.com/blog/2014/07/11/dynamic-dns-can-use-2/)
* [https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html](https://www.splunk.com/blog/2015/08/04/detecting-dynamic-dns-domains-in-splunk.html)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/dns_hijacking.yml) \| *version*: **1**