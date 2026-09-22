# Attack Narrative & Methodology

## Scenario
Modern ransomware operations rarely begin with immediate file encryption. Adversaries systematically dismantle host-level defenses and recovery mechanisms to maximize impact and ensure the victim cannot easily restore data. This simulation replicates a two-phase attack model.

## Phase 1: Defense Impairment (T1490 & T1070.001)
Before encrypting data, the adversary ensures that local backups and recovery tools are disabled. 
* **Inhibit System Recovery (T1490):** The adversary executes `vssadmin` to silently delete all Volume Shadow Copies. Additionally, `bcdedit` is modified to ensure the Windows Recovery Environment (WinRE) is ignored upon reboot.
* **Indicator Removal on Host (T1070.001):** To slow down incident response and obscure the initial access vector, the adversary clears the primary Windows Event Logs (Application, System, and Security) using `wevtutil`.

**Detection Strategy:** Wazuh ingests Sysmon Event ID 1 (Process Creation) logs to identify the execution of `vssadmin.exe`, `bcdedit.exe`, and `wevtutil.exe` with specific malicious command-line arguments. This triggers custom Rule `100030` (Level 12).

## Phase 2: Data Encrypted for Impact (T1486)
With recovery options dismantled, the adversary targets the `C:\Finance_Data` directory. The malware iterates through legitimate business files (e.g., `.txt`, `.pdf`, `.docx`) and encrypts the contents, appending a `.crypt` extension to signify the hostage data.

**Detection Strategy:** Wazuh's File Integrity Monitoring (`syscheck`) is configured to monitor the `C:\Finance_Data` directory in real-time. Custom Rule `100031` (Level 12) utilizes a substring match to immediately trigger a critical alert whenever a file ending in `.crypt` is added or modified.
