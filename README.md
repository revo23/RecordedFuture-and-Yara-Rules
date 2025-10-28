# RecordedFuture-and-Yara-Sigma-Rules

<img width="528" height="353" alt="image" src="https://github.com/user-attachments/assets/6488c52b-8bbb-4e0f-99ef-0069c9085588" />

<img width="500" height="350" alt="image" src="https://github.com/user-attachments/assets/582690a2-cc23-4fa3-aadd-98daacf4c9b2" />


**Overview**  
1. Access Recorded Future
2. Search for specific malware family
3. Generate YARA rule
4. Generate Sigma rule
5. Convert YARA rule for Splunk use
6. Apply rule onto sample log dataset in Splunk

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
<img width="1815" height="917" alt="image" src="https://github.com/user-attachments/assets/88262f7d-fa04-4617-b131-a9ffe08abb00" />

2. Search for malware family (e.g. privateloader)

3. Generate YARA
```
rule composite_hex_1 {
    meta:
        author = "Jenson Goh"
        date = "2025-10-28"
        impact = "Matching binaries: 8"
        hash = "0306778313b74289e440495de6de20e2d26452d9dd82451303d3441f16f8c66f"
        hash = "22275b7c5a57111aca919f6bbfae171e5e99f5ef777d1043802deb672f5136a0"
        hash = "3bd8e0efe68826f448c82133ed2115d8752cdc119fe6d3861d2afb6e8a9442f1"
        hash = "afa631b0721ed1e0f22d8464b19c2571859b470f17d9c04e03f80d1c62fbc5d2"
        hash = "b2aefe9f49a84f067eded0c993c3cb5acf3504d29a978de02f9c1592f6e1f15b"
        hash = "ba1d5e82bf560f617d718f6e680b4655b88952251891175e828122390879266f"
        hash = "ba6b18f6a7590ec1dc2ac2881ddc857f505fed25ff29dc761e204538e3feb96d"
        hash = "ffb7eb4d41dc3309a61521f921834d31272477fcd2996679a698b672d70aa91e"
    strings:
        $str_1 = { 83c418c3909090908b4424088b4c2404 }
        $str_2 = { 5e5fc39090909090909090909090568b }
    condition:
        uint16(0) == 0x5a4d
        and all of them
}
```

| Section   | Purpose                                              |
| --------- | ---------------------------------------------------- |
| meta      | Documentation (non-functional)                       |
| strings   | Indicators to match (text, regex, hex, wide, nocase) |
| condition | Logic that defines a match                           |


**Result**  


**References**  

https://support.recordedfuture.com/hc/en-us/articles/44633853787795-Auto-Sigma-Rules
https://www.youtube.com/watch?v=hU8mUJb2Wq0
