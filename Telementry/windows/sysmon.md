# 📊 Windows Sysmon Telemetry

> **Purpose:** Sysmon provides detailed Windows endpoint telemetry used for detection engineering and threat investigation.

## 🗄️ Data Source

`Microsoft-Windows-Sysmon/Operational`

## ⚡ Key Events

- Process creation
- Network connections
- File activity
- Process termination
- Registry activity
- Image loading

## 🔄 Collection Pipeline

    Windows
       ↓
    Sysmon
       ↓
    Windows Event Channel
       ↓
    Wazuh Agent
       ↓
    Wazuh Server
       ↓
    Detection Engine
       ↓
    Alert
