# OpenSearch / ElasticSearch Queries for DET-002 (Advanced LotL Credential Theft)

## 1. Hunt for MSBuild spawning shells
```data.win.system.eventID: "1" AND data.win.eventdata.parentImage: *MSBuild.exe* AND (data.win.eventdata.image: *cmd.exe* OR data.win.eventdata.image: *powershell.exe*) ```

## 2. Hunt for Volume Shadow Copy creation via WMI/CIM
```data.win.system.eventID: "1" AND data.win.eventdata.commandLine: *Win32_ShadowCopy*```

## 3. Hunt for Rclone execution regardless of file name rename
```data.win.system.eventID: "1" AND data.win.eventdata.originalFileName: "rclone.exe"```

## 4. Correlate renamed exfiltration binary to network connections
```data.win.system.eventID: "3" AND data.win.eventdata.image: *backup_service.exe* AND data.win.eventdata.destinationPort: "8080"```
