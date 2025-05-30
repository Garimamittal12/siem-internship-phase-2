# 🛡 SIEM-INTERNSHIP-PHASE-2  
*Advanced Threat Detection & Post-Exploitation Simulation on Linux*

---

## 📌 Overview  
This repository documents Phase 2 of the SIEM internship, emphasizing the detection of post-exploitation attacker activity on Linux systems using *Splunk Enterprise. The environment simulates adversary behavior and tracks logs through the **Splunk Universal Forwarder*, providing a hands-on approach to threat detection.

Realistic attacker emulation is carried out using tools such as:
- LinPEAS
- CrackMapExec
- Metasploit
- LaZagne

These tools simulate privilege escalation, lateral movement, credential dumping, C2 communication, and more.

---

## 🏗 Architecture

The Phase 2 lab environment simulates real-world attacker activity on Linux systems, with logs collected and analyzed in Splunk Enterprise.

text
+------------------------+        Log Forwarding         +---------------------------+
|  Linux Host (Attacker) | ───────────────────────────▶ | Splunk Universal Forwarder |
|  Tools: LinPEAS,       |                               | Configured to monitor:    |
|  CrackMapExec, etc.    |                               | - /var/log/auth.log       |
+------------------------+                               | - /var/log/syslog         |
                                                         | - /var/log/audit/audit.log|
                                                         | - /home/*/.bash_history   |
                                                         | - /etc/passwd, /shadow    |
                                                         +---------------------------+
                                                                   │
                                                                   ▼
                                                      +---------------------------------+
                                                      |   Splunk Enterprise (SIEM)      |
                                                      |  - Index: postexploitation_logs |
                                                      |  - Real-time search & alerts    |
                                                      +---------------------------------+




### 🧰 Components

- *Linux Hosts:*  
  Emulate attacker behavior: privilege escalation, lateral movement, C2 communication, and credential dumping.

- *Splunk Universal Forwarder:*  
  Installed on each host to collect and forward logs to Splunk over TCP port 9997.

- *Splunk Enterprise (Indexer & Search Head):*  
  Receives and indexes logs for real-time monitoring, detection rules, MITRE ATT&CK mapping, and alerting.

---

## 🔓 Exploitation & Post-Exploitation Techniques Simulated

- *🔼 Privilege Escalation:*  
  Simulated using LinPEAS, usermod, useradd, and direct modification of /etc/passwd

- *➡ Lateral Movement:*  
  Via SSH, mount-based file sharing (e.g., NFS, SMB, SSHFS), and CrackMapExec

- *📥 Suspicious File Downloads:*  
  Using wget, curl, ftp, and scp

- *🔐 Credential Dumping:*  
  With tools like LaZagne, and by parsing sensitive files (/etc/passwd, /etc/shadow)

- *📡 Command & Control:*  
  Simulated reverse shell using Metasploit Meterpreter and outbound beaconing

- *🧭 Anomalous User Behavior:*  
  Off-hour logins, rapid access to sensitive directories, and burst activity

---

## 🧍 Privilege Escalation Detection

*Indicators:*
- Usage of: sudo, usermod, useradd, or LinPEAS
- File edits: /etc/passwd, /etc/group

*Log Sources:*
- /var/log/auth.log
- /etc/passwd, /etc/group
- auditd

*Detection Strategy:*
Monitor group membership changes and unauthorized user privilege modifications.

---

## 🔄 Lateral Movement Detection

### 🗃 Mount-Based Movement
Attackers may use shared mounts like NFS, SMB, or SSHFS.

*Detection:*
- *Log Source:* /var/log/audit/audit.log
- *Tool:* auditd

### 📡 Internal IP Communication
Reverse shells or lateral tools may generate outbound connections to internal IPs.

*Detection:*
- *Log Source:* /var/log/sysmon/sysmon.log
- *Event ID:* 3 (Network Connection)

---

## 🧪 Suspicious File Downloads & Execution

*Techniques:*
- Download using: wget, curl, ftp, scp
- Execute with: bash, chmod, ./payload

*Detection:*
Correlate downloads with subsequent executions, especially in temp directories or unusual extensions (.sh, .py, .elf)

*Log Sources:*
- auditd
- syslog
- .bash_history

---

## 🧭 Anomalous User Behavior

*Indicators:*
- Logins at unusual times
- Sudden directory traversal
- Mass file access or exfiltration

*Log Sources:*
- /var/log/auth.log
- /var/log/audit/audit.log
- /var/log/syslog

*Detection:*
Use behavioral analytics or threshold alerts for off-pattern activities.

---

## 📡 Command & Control (C2) Beaconing

Simulated using:
- Metasploit Meterpreter
- Repeated curl, dig to external domains

*Log Sources:*
- /var/log/syslog (Sysmon)
- *Event ID:* 3 (Network Connection)

*Detection Strategy:*
Look for fixed-interval outbound connections or unexpected domains.

---

## 🗂 Log Sources for Detection

Monitored Linux logs:
- /var/log/auth.log
- /var/log/audit/audit.log
- /var/log/syslog
- /home/*/.bash_history
- /etc/passwd, /etc/group, /etc/shadow

All logs are forwarded using *Splunk Universal Forwarder*.

---

## 🖥 Splunk Integration: Log Forwarding Setup

*Configured Log Sources:*
- auth.log, audit.log, syslog, .bash_history, passwd, group, shadow

*Configuration Files:*
- inputs.conf: Specifies paths to monitor
- outputs.conf: Defines forwarding rules to Splunk Indexer (TCP 9997)

*Index:*
- Logs stored under: postexploitation_logs
- Sourcetypes: auth, syslog, auditd, bash

---

## 🎯 Detection Mapping: MITRE ATT&CK
__ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ ___
| Tactic               | Simulated Techniques                     |
|----------------------|------------------------------------------|
| Privilege Escalation | sudo, usermod, LinPEAS                   |
| Lateral Movement     | SSH, SMB/NFS mounts, CrackMapExec        |
| Credential Access    | LaZagne, /etc/shadow parsing             |
| Execution            | wget, bash, chmod, ./payload             |
| Command & Control    | Reverse shells, Meterpreter              |
| Defense Evasion      | Obfuscated scripts, unusual user creation|
__ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ __ ___
