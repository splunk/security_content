import enchant

import nltk
nltk.download('stopwords')
nltk.download('punkt')
nltk.download('wordnet')


common_manifest_words = [
    "App", "Splunk", "AWS", "CVE", "IAM", "ESCU", "Netbackup", "CLI", "DNS", "CloudTrail",
    "DNSTwist", "IP", "DHCP", "AMIs", "EventCode", "PowerShell", "dest", "instanceId",
    "malware", "exfiltration", "exfiltrate", "Spectre", "Mitre", "ul", "li", "JBoss", "admin",
    "subsearch", "cleartext", "WMI", "URL", "URLs", "ATT", "CK", "SMB", "ACL", "ACLs", "CIDR",
    "VPC", "TXT", "USB", "SQL", "src", "VPN", "src", "br", "phishing", "weaponized",
    "Ransomware", "ransomware", "VirusTotal", "RDP", "kerberized", "IMAP", "SSL",
    "instanceType", "subsearch", "SPL", "rhaegal", "drogon", "BadRabbit", "WannaCry",
    "CARBANAK", "wevtutil", "UAC", "ModifiedPersistence", "whoami", "tstats", "IPs",
    "sourcetype", "JexBoss", "iptables", "wget", "NTFS", "noninteractive", "DLL", "DLLs",
    "faux", "eval", "userName", "outlier", "DDoS", "logon", "noninteractive", "PID", "whois",
    "misconfigured", "ARN", "MITM", "UDP", "MX", "Noriaki", "Iwasaki", "API", "APIs",
    "awsRegion", "wmic", "vssadmin", "IDAPro", "AppData", "lifecycle", "prepending",
    "prepended", "exfiltrating", "SDKs", "FQDN", "FQDNs", "DDNS", "Multipart", "CDN",
    "cryptomining", "Cryptomining", "cryptojacking", "Cryptojacking", "typosquatting",
    "DHL", "Samsam", "usernames", "antivirus", "NtLmSsP", "NTLM", "dnstwist", "url",
    "netsh", "Netsh", "hostname", "hostnames", "csv", "amiID", "whitelist", "whitelisting",
    "CVEs", "Cyber", "backticks", "backend", "backdoor", "backdoored", "wormable",
    "RunDLL", "Schtasks", "logons", "spearphishing", "driveby", "cyber", "firstTime",
    "lastTime", "ARNs", "GeoIP", "MaxMind", "DHS", "localgroup","PsExec", "psexec",
    "accepteula", "cmdline", "apiCalls", "latestCount", "ol","internet","numberOfBlockedConnections", "arn", "AssumedRole",
    "dataPointThreshold", "deviationThreshold", "eventNames","CloudWatch","VPCs", "ICMP"
    "AssumeRole", "isnotnull", "requestingAccountId",
    "http", "Sysmon", "CIM", "resourceId", "NetworkACLEvents", "securityGroupAPIs",
    "CIDRs", "https", "username", "pst", "ost", "AccessKeyId","AssumeRole","isnotnull","AccessKeyId","redhat","bucketName","serviceName","javascript","VBScript",
    "Mimikatz","SeDebugPrivilege","sekurlsa","lsass","offline","ExecutionPolicy","NirSoft","scomma","stext","Nirsoft","Clickspeed","clickstream","IIS","fraudster","splunk","DDOS","clickstreams",
    "wscript", "cscript", "WinEventLog","filesystem","Recurly","whitelisted", "POC","Playbook", "SamSam", "Bruteforce", "POSTs", "java", "RCE"
]


d = enchant.Dict("en_US")

for word in common_manifest_words:
    if not d.is_added(word):
        d.add(word)

