---
title: "ColdRoot MacOS RAT"
last_modified_at: 2019-01-09
toc: true
tags:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
---

#### Description

Leverage searches that allow you to detect and investigate unusual activities that relate to the ColdRoot Remote Access Trojan that affects MacOS. An example of some of these activities are changing sensative binaries in the MacOS sub-system, detecting process names and executables associated with the RAT, detecting when a keyboard tab is installed on a MacOS machine and more.

- **ID**: bd91a2bc-d20b-4f44-a982-1bea98e86390
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: 
- **Last Updated**: 2019-01-09
- **Author**: Jose Hernandez, Splunk

#### Detection profiles

| Name        | Technique   | Type         |
| ----------- | ----------- |--------------|
| [Processes Tapping Keyboard Events](/endpoint/processes_tapping_keyboard_events/) | None | TTP |

#### Kill Chain Phase



#### Reference

* [https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/](https://www.intego.com/mac-security-blog/osxcoldroot-and-the-rat-invasion/)
* [https://objective-see.com/blog/blog_0x2A.html](https://objective-see.com/blog/blog_0x2A.html)
* [https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/](https://www.bleepingcomputer.com/news/security/coldroot-rat-still-undetectable-despite-being-uploaded-on-github-two-years-ago/)



_version_: 1