# RecordedFuture-and-Yara-Sigma-Rules

<img width="528" height="353" alt="image" src="https://github.com/user-attachments/assets/6488c52b-8bbb-4e0f-99ef-0069c9085588" />

<img width="500" height="350" alt="image" src="https://github.com/user-attachments/assets/582690a2-cc23-4fa3-aadd-98daacf4c9b2" />

The Pyramid of Pain consists of seven levels, from easiest to hardest for attackers to change:

- Hash Values: Unique file signatures (e.g., SHA1, MD5) that attackers can easily modify by recompiling malware
- IP Addresses: Network locations that attackers can quickly change by switching servers
- Domain Names: More costly than IPs to replace, but still manageable for determined adversaries
- Network Artifacts: Observable patterns in traffic like URI structures or unusual user-agents
- Host Artifacts: Evidence left on endpoints such as registry keys, file paths, or processes
- Tools: Attack software (e.g., Mimikatz, Cobalt Strike) that requires significant effort to replace
- TTPs: (Tactics, Techniques, Procedures): The attacker’s behavioral patterns—the most painful to change

**Overview**  
1. Export YARA/Sigma rules from Recorded Future
2. Conversion to acceptable format
3. Scan files/logs


**Situation**  
Treat actors can easily change a file (hash values) or infrastructure (IPs, domains) to evade detection, making threat hunting harder. There are various threat hunting techniques such as using hypothesis-driven threat hunting, CTI integration, AI/ML, graph-based threat hunting and adversary emulation. Our organization received a tip-off from regulators that the PrivateLoader Pay-per-install(PPI) provider are listing our systems in the APAC region as target systems. In this scenario, we look into conducting more effective threat hunting by using the latest threat intelligence via customized YARA/Sigma rules from CTI platform that provides the latest adversary insight.

**Task**  
Look for PrivateLoader malware downloaders in environment that have evaded current security tools (i.e. EDR). Scale threat hunting through automation from CTI platforms such as RecordedFuture. Eliminate hours of manual rule-writing with Auto YARA and Sigma rules. 
```
New Feature Announcement - Auto Sigma
Support Article
This capability allows for automated Sigma rule generation from Malware Intelligence search results with one-click functionality. Auto Sigma accelerates incident response workflows by eliminating time traditionally spent manually writing detection rules, and empowers proactive threat hunting. 
```

**Steps**  
1. Access RecordedFuture > Threat > Malware Intelligence > Malware Hunting
<img width="1815" height="917" alt="image" src="https://github.com/user-attachments/assets/88262f7d-fa04-4617-b131-a9ffe08abb00" />

2. Search for malware family (e.g. privateloader)

3. Generate YARA
truncated 
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
        uint16(0) == 0x5a4d >>> This enforces detection only in Windows PE files (MZ header).
        and all of them
}
```

| Section   | Purpose                                              |
| --------- | ---------------------------------------------------- |
| meta      | Documentation (non-functional)                       |
| strings   | Indicators to match (text, regex, hex, wide, nocase) |
| condition | Logic that defines a match                           |

There are three types of strings in YARA: hexadecimal strings (curly brackets), text strings (double quotes) and regular expressions.
Recorded Future outputs those byte sequences as continuous raw hex because it is a neutral data format suitable for many security tools. 

Usage: yara64.exe [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID

Sample rule to test first
```
rule hello_world_str {
    meta:
        description = "simple proof-of-concept to show YARA rules"
        author = "Jenson Goh"

    strings:
        $hello = "Hello World!"

    condition:
        $hello
}
```

Install MinGW  

Create test C++ file
```
#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}
```
Build C++ file into EXE  
```
g++ -g .\helloworld.cpp -o helloworld.exe
```
Test Yara rule on sample EXE  
```
.\yara64.exe .\helloworldstr.yara .\helloworld.exe
<img width="636" height="61" alt="image" src="https://github.com/user-attachments/assets/8db04148-4eca-4a1c-b7c8-b7465179042a" />  

Match seen! It works



Turn off Defender

```
Method 2: Using the Group Policy Editor (For Windows Pro and Enterprise)

Open the Group Policy Editor:
Press Windows + R, type gpedit.msc, and press Enter.
Navigate to Windows Defender Settings:
Go to Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus.
Disable Microsoft Defender Antivirus:
Double-click on Turn off Microsoft Defender Antivirus.
Select Enabled and click Apply, then OK.
Restart Your Computer:
Restart your computer to apply the changes. Windows Defender should now be permanently disabled.
```
<img width="1679" height="897" alt="image" src="https://github.com/user-attachments/assets/477c26ee-78da-442d-8cc8-c3e576836d4d" />

Download PrivateLoader zip files and extract using 7zip (password: infected)


**Result**  


**References**  
https://yara.readthedocs.io/en/stable/index.html  
https://support.recordedfuture.com/hc/en-us/articles/44633853787795-Auto-Sigma-Rules  
https://www.youtube.com/watch?v=hU8mUJb2Wq0  
https://www.darktrace.com/blog/privateloader-network-based-indicators-of-compromise  
