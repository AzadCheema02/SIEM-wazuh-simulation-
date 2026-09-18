# DET-002: Advanced LotL Credential Theft and Exfiltration

## Objective
Simulate an advanced persistent threat (APT) utilizing "Living off the Land" (LotL) binaries to bypass static endpoint defenses, extract locked credential hives, and exfiltrate data over the network.

## Attack Infrastructure
* **Target:** Windows 11 (10.10.10.10)
* **Attacker / C2:** Kali Linux (10.10.10.40)
* **Tools:** MSBuild.exe, PowerShell (CIM Cmdlets), Rclone (renamed to `backup_service.exe`)

## Execution Steps

### 1. Defense Evasion (T1127.001)
Executed a malicious XML payload using the trusted Microsoft build engine (`MSBuild.exe`) to spawn a hidden command shell in memory, bypassing standard Application Allowlisting (AAL).

### 2. Credential Access (T1003.002, T1047)
Standard `vssadmin` commands are restricted on Windows 11 client OS. Pivoted to PowerShell and the Common Information Model (CIM) to silently create a Volume Shadow Copy of the `C:\` drive. Successfully extracted the locked `SAM` and `SYSTEM` registry hives to `C:\Temp` for offline hash cracking.

### 3. Data Exfiltration (T1567.002)
Downloaded and extracted the Rclone binary. Renamed `rclone.exe` to `backup_service.exe` to evade basic file name detection. Initiated an outbound webdav connection to a simulated attacker-controlled server (Kali Linux on port 8080) to exfiltrate the `sam.save` file.
