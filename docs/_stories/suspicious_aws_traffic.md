---
title: "Suspicious AWS Traffic"
last_modified_at: 2018-05-07
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Command & Control
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Leverage these searches to monitor your AWS network traffic for evidence of anomalous activity and suspicious behaviors, such as a spike in blocked outbound traffic in your virtual private cloud (VPC).

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-05-07
- **Author**: Bhavin Patel, Splunk
- **ID**: 2e8948a5-5239-406b-b56b-6c50f2168af3

#### Narrative

A virtual private cloud (VPC) is an on-demand managed cloud-computing service that isolates computing resources for each client. Inside the VPC container, the environment resembles a physical network. \
Amazon's VPC service enables you to launch EC2 instances and leverage other Amazon resources. The traffic that flows in and out of this VPC can be controlled via network access-control rules and security groups. Amazon also has a feature called VPC Flow Logs that enables you to log IP traffic going to and from the network interfaces in your VPC. This data is stored using Amazon CloudWatch Logs.\
 Attackers may abuse the AWS infrastructure with insecure VPCs so they can co-opt AWS resources for command-and-control nodes, data exfiltration, and more. Once an EC2 instance is compromised, an attacker may initiate outbound network connections for malicious reasons. Monitoring these network traffic behaviors is crucial for understanding the type of traffic flowing in and out of your network and to alert you to suspicious activities.\
The searches in this Analytic Story will monitor your AWS network traffic for evidence of anomalous activity and suspicious behaviors.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Detect Spike in blocked Outbound Traffic from your AWS](/cloud/detect_spike_in_blocked_outbound_traffic_from_your_aws/) | None| Anomaly |

#### Reference

* [https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/](https://rhinosecuritylabs.com/aws/hiding-cloudcobalt-strike-beacon-c2-using-amazon-apis/)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/suspicious_aws_traffic.yml) \| *version*: **1**