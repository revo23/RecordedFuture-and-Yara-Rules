# RecordedFuture-and-Yara-Sigma-Rules

<img width="528" height="353" alt="image" src="https://github.com/user-attachments/assets/6488c52b-8bbb-4e0f-99ef-0069c9085588" />

<img width="500" height="350" alt="image" src="https://github.com/user-attachments/assets/582690a2-cc23-4fa3-aadd-98daacf4c9b2" />


**Overview**
1. Access Recorded Future
2. Search for specific malware family
3. Generate YARA rule
4. Generate Sigma rule
5. Convert YARA rule for Splunk use
6. Search using rule onto sample log dataset in Splunk

**Situation**
Treat actors can easily change a file (hash values) or infrastructure (IPs, domains) to evade detection, making threat hunting harder. There are various threat hunting techniques such as using hypothesis-driven threat hunting, CTI integration, AI/ML, graph-based threat hunting and adversary emulation.
In this example we look into more effective threat hunting depends by fusing threat intelligence with customized YARA/Sigma rules. CTI provides the adversary insights while integrated data sources in the SIEM supply the evidence.

**Task**
Scale threat hunting through automation from CTI platforms such as RecordedFuture. Eliminate hours of manual rule-writing with Auto YARA and Sigma rules.
```
New Feature Announcement - Auto Sigma
Support Article
This capability allows for automated Sigma rule generation from Malware Intelligence search results with one-click functionality. Auto Sigma accelerates incident response workflows by eliminating time traditionally spent manually writing detection rules, and empowers proactive threat hunting
```

**Steps**

1. Access RecordedFuture > Threat > Malware Intelligence 
<img width="1815" height="917" alt="image" src="https://github.com/user-attachments/assets/26360aa9-cc9c-4d45-8a76-5644875e3f1f" />

2. Search for malware family (e.g. privateloader)
3. 

**Result**


**References**

https://support.recordedfuture.com/hc/en-us/articles/44633853787795-Auto-Sigma-Rules
https://www.youtube.com/watch?v=hU8mUJb2Wq0
