---
title: "Web Fraud Detection"
last_modified_at: 2018-10-08
toc: true
toc_label: ""
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - Actions on Objectives
  - Exploitation
---

[Try in Splunk Security Cloud](https://www.splunk.com/en_us/cyber-security.html){: .btn .btn--success}

#### Description

Monitor your environment for activity consistent with common attack techniques bad actors use when attempting to compromise web servers or other web-related assets.

- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2018-10-08
- **Author**: Jim Apger, Splunk
- **ID**: 18bb45b9-7684-45c6-9e97-1fdd0d98c0a7

#### Narrative

The Federal Bureau of Investigations (FBI) defines Internet fraud as the use of Internet services or software with Internet access to defraud victims or to otherwise take advantage of them. According to the Bureau, Internet crime schemes are used to steal millions of dollars each year from victims and continue to plague the Internet through various methods. The agency includes phishing scams, data breaches, Denial of Service (DOS) attacks, email account compromise, malware, spoofing, and ransomware in this category.\
These crimes are not the fraud itself, but rather the attack techniques commonly employed by fraudsters in their pursuit of data that enables them to commit malicious actssuch as obtaining and using stolen credit cards. They represent a serious problem that is steadily increasing and not likely to go away anytime soon.\
When developing a strategy for preventing fraud in your environment, its important to  look across all of your web services for evidence that attackers are abusing enterprise resources to enumerate systems, harvest data for secondary fraudulent activity, or abuse terms of service.This Analytic Story looks for evidence of common Internet attack techniques that could be indicative of web fraud in your environmentincluding account harvesting, anomalous user clickspeed, and password sharing across accounts, to name just a few.\
The account-harvesting search focuses on web pages used for user-account registration. It detects the creation of a large number of user accounts using the same email domain name, a type of activity frequently seen in advance of a fraud campaign.\
The anomalous clickspeed search looks for users who are moving through your website at a faster-than-normal speed or with a perfect click cadence (high periodicity or low standard deviation), which could indicate that the user is a script, not an actual human.\
Another search detects incidents wherein a single password is used across multiple accounts, which may indicate that a fraudster has infiltrated your environment and embedded a common password within a script.

#### Detections

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Web Fraud - Account Harvesting](/deprecated/web_fraud_-_account_harvesting/) | [Create Account](/tags/#create-account)| TTP |
| [Web Fraud - Anomalous User Clickspeed](/deprecated/web_fraud_-_anomalous_user_clickspeed/) | [Valid Accounts](/tags/#valid-accounts)| Anomaly |
| [Web Fraud - Password Sharing Across Accounts](/deprecated/web_fraud_-_password_sharing_across_accounts/) | None| Anomaly |

#### Reference

* [https://www.fbi.gov/scams-and-safety/common-fraud-schemes/internet-fraud](https://www.fbi.gov/scams-and-safety/common-fraud-schemes/internet-fraud)
* [https://www.fbi.gov/news/stories/2017-internet-crime-report-released-050718](https://www.fbi.gov/news/stories/2017-internet-crime-report-released-050718)



[*source*](https://github.com/splunk/security_content/tree/develop/stories/web_fraud_detection.yml) \| *version*: **1**