---
title: "Hunting for Log4Shell"
excerpt: "Exploit Public-Facing Application
"
categories:
  - Endpoint
last_modified_at: 2021-12-14
toc: true
toc_label: ""
tags:
  - Exploit Public-Facing Application
  - Initial Access
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  - CVE-2021-44228
  - Web
---



[Try in Splunk Security Cloud](https://www.splunk.com/en_splunk_app_enrichmentus/cyber-security.html){: .btn .btn--success}

#### Description

The following hunting query assists with quickly assessing CVE-2021-44228, or Log4Shell, activity mapped to the Web Datamodel. This is a combination query attempting to identify, score and dashboard. Because the Log4Shell vulnerability requires the string to be in the logs, this will work to identify the activity anywhere in the HTTP headers using _raw. Modify the first line to use the same pattern matching against other log sources. Scoring is based on a simple rubric of 0-5. 5 being the best match, and less than 5 meant to identify additional patterns that will equate to a higher total score. \
The first jndi match identifies the standard pattern of `{jndi:` \
jndi_fastmatch is meant to identify any jndi in the logs. The score is set low and is meant to be the "base" score used later. \
jndi_proto is a protocol match that identifies `jndi` and one of `ldap, ldaps, rmi, dns, nis, iiop, corba, nds, http, https.` \
all_match is a very well written regex by https://gist.github.com/Schvenn that identifies nearly all patterns of this attack behavior. \
env works to identify environment variables in the header, meant to capture `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `env`. \
uri_detect is string match looking for the common uri paths currently being scanned/abused in the wild. \
keywords matches on enumerated values that, like `$ctx:loginId`, that may be found in the header used by the adversary. \
lookup matching is meant to catch some basic obfuscation that has been identified using upper, lower and date. \
Scoring will then occur based on any findings. The base score is meant to be 2 , created by jndi_fastmatch. Everything else is meant to increase that score. \
Finally, a simple table is created to show the scoring and the _raw field. Sort based on score or columns of interest.

- **Type**: [Hunting](https://github.com/splunk/security_content/wiki/Detection-Analytic-Types)
- **Product**: Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud
- **Datamodel**: [Web](https://docs.splunk.com/Documentation/CIM/latest/User/Web)
- **Last Updated**: 2021-12-14
- **Author**: Michael Haag, Splunk
- **ID**: 158b68fa-5d1a-11ec-aac8-acde48001122


#### Annotations

<details>
  <summary>ATT&CK</summary>

<div markdown="1">


| ID             | Technique        |  Tactic             |
| -------------- | ---------------- |-------------------- |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | Initial Access |

</div>
</details>


<details>
  <summary>Kill Chain Phase</summary>

<div markdown="1">

* Exploitation


</div>
</details>


<details>
  <summary>NIST</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CIS20</summary>

<div markdown="1">



</div>
</details>

<details>
  <summary>CVE</summary>

<div markdown="1">
| ID          | Summary | [CVSS](https://nvd.nist.gov/vuln-metrics/cvss) |
| ----------- | ----------- | -------------- |
| [CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228) | Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects. | 9.3 |



</div>
</details>

#### Search

```

| from datamodel Web.Web 
| eval jndi=if(match(_raw, "(\{
|%7B)[jJnNdDiI]{4}:"),4,0) 
| eval jndi_fastmatch=if(match(_raw, "[jJnNdDiI]{4}"),2,0) 
| eval jndi_proto=if(match(_raw,"(?i)jndi:(ldap[s]?
|rmi
|dns
|nis
|iiop
|corba
|nds
|http
|https):"),5,0) 
| eval all_match = if(match(_raw, "(?i)(%(25){0,}20
|\s)*(%(25){0,}24
|\$)(%(25){0,}20
|\s)*(%(25){0,}7B
|{)(%(25){0,}20
|\s)*(%(25){0,}(6A
|4A)
|J)(%(25){0,}(6E
|4E)
|N)(%(25){0,}(64
|44)
|D)(%(25){0,}(69
|49)
|I)(%(25){0,}20
|\s)*(%(25){0,}3A
|:)[\w\%]+(%(25){1,}3A
|:)(%(25){1,}2F
|\/)[^\n]+"),5,0) 
| eval env_var = if(match(_raw, "env:") OR match(_raw, "env:AWS_ACCESS_KEY_ID") OR match(_raw, "env:AWS_SECRET_ACCESS_KEY"),5,0) 
| eval uridetect = if(match(_raw, "(?i)Basic\/Command\/Base64
|Basic\/ReverseShell
|Basic\/TomcatMemshell
|Basic\/JBossMemshell
|Basic\/WebsphereMemshell
|Basic\/SpringMemshell
|Basic\/Command
|Deserialization\/CommonsCollectionsK
|Deserialization\/CommonsBeanutils
|Deserialization\/Jre8u20\/TomcatMemshell
|Deserialization\/CVE_2020_2555\/WeblogicMemshell
|TomcatBypass
|GroovyBypass
|WebsphereBypass"),4,0) 
| eval keywords = if(match(_raw,"(?i)\$\{ctx\:loginId\}
|\$\{map\:type\}
|\$\{filename\}
|\$\{date\:MM-dd-yyyy\}
|\$\{docker\:containerId\}
|\$\{docker\:containerName\}
|\$\{docker\:imageName\}
|\$\{env\:USER\}
|\$\{event\:Marker\}
|\$\{mdc\:UserId\}
|\$\{java\:runtime\}
|\$\{java\:vm\}
|\$\{java\:os\}
|\$\{jndi\:logging/context-name\}
|\$\{hostName\}
|\$\{docker\:containerId\}
|\$\{k8s\:accountName\}
|\$\{k8s\:clusterName\}
|\$\{k8s\:containerId\}
|\$\{k8s\:containerName\}
|\$\{k8s\:host\}
|\$\{k8s\:labels.app\}
|\$\{k8s\:labels.podTemplateHash\}
|\$\{k8s\:masterUrl\}
|\$\{k8s\:namespaceId\}
|\$\{k8s\:namespaceName\}
|\$\{k8s\:podId\}
|\$\{k8s\:podIp\}
|\$\{k8s\:podName\}
|\$\{k8s\:imageId\}
|\$\{k8s\:imageName\}
|\$\{log4j\:configLocation\}
|\$\{log4j\:configParentLocation\}
|\$\{spring\:spring.application.name\}
|\$\{main\:myString\}
|\$\{main\:0\}
|\$\{main\:1\}
|\$\{main\:2\}
|\$\{main\:3\}
|\$\{main\:4\}
|\$\{main\:bar\}
|\$\{name\}
|\$\{marker\}
|\$\{marker\:name\}
|\$\{spring\:profiles.active[0]
|\$\{sys\:logPath\}
|\$\{web\:rootDir\}
|\$\{sys\:user.name\}"),4,0) 
| eval obf = if(match(_raw, "(\$
|%24)[^ /]*({
|%7b)[^ /]*(j
|%6a)[^ /]*(n
|%6e)[^ /]*(d
|%64)[^ /]*(i
|%69)[^ /]*(:
|%3a)[^ /]*(:
|%3a)[^ /]*(/
|%2f)"),5,0) 
| eval lookups = if(match(_raw, "(?i)({
|%7b)(main
|sys
|k8s
|spring
|lower
|upper
|env
|date
|sd)"),4,0)  
| addtotals fieldname=Score, jndi, jndi_proto, env_var, uridetect, all_match, jndi_fastmatch, keywords, obf, lookups 
| where Score > 2 
| stats values(Score) by  jndi, jndi_proto, env_var, uridetect, all_match, jndi_fastmatch, keywords, lookups, obf, _raw 
| `hunting_for_log4shell_filter`
```

#### Macros
The SPL above uses the following Macros:

Note that **hunting_for_log4shell_filter** is a empty macro by default. It allows the user to filter out any results (false positives) without editing the SPL.

#### Required field
* _time
* Web.http_method
* Web.url
* Web.url_length
* Web.src
* Web.dest
* Web.http_user_agent
* _raw


#### How To Implement
Out of the box, the Web datamodel is required to be pre-filled. However, tested was performed against raw httpd access logs. Change the first line to any dataset to pass the regex's against.

#### Known False Positives
It is highly possible you will find false positives, however, the base score is set to 2 for _any_ jndi found in raw logs. tune and change as needed, include any filtering.

#### Associated Analytic story
* [Log4Shell CVE-2021-44228](/stories/log4shell_cve-2021-44228)




#### RBA

| Risk Score  | Impact      | Confidence   | Message      |
| ----------- | ----------- |--------------|--------------|
| 40.0 | 80 | 50 | Hunting for Log4Shell exploitation has occurred. |


#### Reference

* [https://gist.github.com/olafhartong/916ebc673ba066537740164f7e7e1d72](https://gist.github.com/olafhartong/916ebc673ba066537740164f7e7e1d72)
* [https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3994449](https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3994449)
* [https://regex101.com/r/OSrm0q/1/](https://regex101.com/r/OSrm0q/1/)
* [https://github.com/Neo23x0/signature-base/blob/master/yara/expl_log4j_cve_2021_44228.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_log4j_cve_2021_44228.yar)
* [https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/](https://news.sophos.com/en-us/2021/12/12/log4shell-hell-anatomy-of-an-exploit-outbreak/)
* [https://gist.github.com/MHaggis/1899b8554f38c8692a9fb0ceba60b44c](https://gist.github.com/MHaggis/1899b8554f38c8692a9fb0ceba60b44c)
* [https://twitter.com/sasi2103/status/1469764719850442760?s=20](https://twitter.com/sasi2103/status/1469764719850442760?s=20)



#### Test Dataset
Replay any dataset to Splunk Enterprise by using our [replay.py](https://github.com/splunk/attack_data#using-replaypy) tool or the [UI](https://github.com/splunk/attack_data#using-ui).
Alternatively you can replay a dataset into a [Splunk Attack Range](https://github.com/splunk/attack_range#replay-dumps-into-attack-range-splunk-server)


* [https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/log4shell-nginx.log](https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/log4shell-nginx.log)



[*source*](https://github.com/splunk/security_content/tree/develop/detections/endpoint/hunting_for_log4shell.yml) \| *version*: **1**