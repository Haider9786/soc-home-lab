# SOC Home Lab: Threat Detection and Incident Investigation

**Environment:** Wazuh SIEM | Kali Linux | Windows 11 | Sysmon | Microsoft Defender for Endpoint  
**Focus:** Blue Team | Alert Triage | MITRE ATT&CK Mapping | Incident Investigation  
**Status:** Active — continuously updated

---

## Table of Contents

1. [Lab Overview](#lab-overview)
2. [Architecture](#architecture)
3. [Setup and Configuration](#setup-and-configuration)
4. [Attack Simulations](#attack-simulations)
5. [Alert Investigation and Triage](#alert-investigation-and-triage)
6. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
7. [Key Findings and Lessons Learned](#key-findings-and-lessons-learned)
8. [Screenshots](#screenshots)

---

## Lab Overview

This project documents a functional Security Operations Center (SOC) home lab built to develop and demonstrate real-world Tier 1 SOC skills. The goal was not to follow a tutorial,it was to build a lab that mirrors the tools and workflows used in actual SOC environments, then use it to practice the full analyst cycle from alert generation through investigation and documentation.

The lab is built on VMware Workstation running on a Windows 11 host machine. Kali Linux hosts the Wazuh SIEM manager and dashboard. The Windows 11 host machine is registered as a live Wazuh agent, generating real endpoint telemetry that feeds into the SIEM.

---

## Architecture

```
+---------------------------+          +---------------------------+
|   Kali Linux (VMware)     |          |   Windows 11 Host         |
|                           |          |                           |
|   Wazuh Manager           |<-------->|   Wazuh Agent (whiplash)  |
|   Wazuh Dashboard         |          |   Sysmon                  |
|   IP: 192.168.31.131      |          |   Microsoft Defender XDR  |
|                           |          |   IP: 192.168.31.1        |
+---------------------------+          +---------------------------+
          |
          | Attack simulation
          v
+---------------------------+
|   Kali Linux (Attacker)   |
|                           |
|   Nmap                    |
|   Metasploit (Basic)      |
|   Hydra (Brute Force)     |
|   Custom Python scripts   |
+---------------------------+
```

**Components:**
- **Wazuh SIEM** : centralised log collection, rule-based detection, alert dashboard
- **Sysmon** : Windows endpoint telemetry including process creation, network connections, file changes
- **Microsoft Defender for Endpoint** : EDR telemetry correlated alongside SIEM alerts
- **Kali Linux** : attack simulation platform for generating realistic security events

---

## Setup and Configuration

### Wazuh Manager Installation
Wazuh was installed on Kali Linux as the central SIEM manager. The Wazuh dashboard is accessible at `https://127.0.0.1` and provides real-time visibility into agent telemetry, alerts, and security events.

```bash
# Verify Wazuh manager status
sudo systemctl status wazuh-manager
# Output: Active (running)
```

### Windows 11 Agent Registration
The Windows 11 host was registered as a Wazuh agent named **whiplash** at IP `192.168.31.1`. The agent forwards Windows Security Event Logs, Sysmon logs, and system events to the Wazuh manager at `192.168.31.131`.

Agent details visible in Wazuh dashboard:
- Agent name: whiplash
- OS: Microsoft Windows 11 Pro 10.0.26200
- Agent version: v4.7.5
- Status: Active

### Sysmon Configuration
Sysmon was deployed on the Windows 11 endpoint using the SwiftOnSecurity configuration, enabling detailed telemetry for:
- Process creation and termination (Event ID 1)
- Network connections (Event ID 3)
- File creation (Event ID 11)
- Registry modifications (Event ID 13)
- PowerShell execution (Event ID 4104)

---

## Attack Simulations

### Simulation 1: Network Reconnaissance (Nmap Scan)

**Objective:** Simulate an attacker performing network discovery against the Windows endpoint.

**Command executed from Kali:**
```bash
nmap -sV -p 1-1000 192.168.31.1
```

**What happened:**
- Nmap performed a service version scan across the first 1000 ports of the Windows 11 endpoint
- Open ports detected: 135 (RPC), 139 (NetBIOS), 445 (SMB), 3389 (RDP)
- Wazuh generated alerts for port scanning activity detected from the Kali IP

**Alert generated in Wazuh:**
- Rule ID: 40101: Multiple port scans detected
- Severity: Level 10
- Source IP: 192.168.31.131 (Kali)
- Destination: 192.168.31.1 (Windows endpoint)

**MITRE ATT&CK mapping:**
- Tactic: TA0043: Reconnaissance
- Technique: T1046: Network Service Discovery

---

### Simulation 2: Brute Force Authentication Attempt

**Objective:** Simulate credential stuffing against Windows Remote Desktop Protocol.

**Tool used:** Hydra from Kali Linux targeting RDP on the Windows endpoint.

**What happened:**
- Multiple failed authentication attempts generated Windows Security Event ID 4625 (Failed Logon)
- Wazuh correlated the repeated failures and triggered a brute force detection alert
- Sysmon logged the network connection attempts from the Kali IP

**Alert generated in Wazuh:**
- Rule ID: 18152: Multiple Windows Logon Failures
- Severity: Level 10
- Account targeted: Administrator
- Source IP: 192.168.31.131

**MITRE ATT&CK mapping:**
- Tactic: TA0006: Credential Access
- Technique: T1110: Brute Force
- Sub-technique: T1110.001: Password Guessing

---

### Simulation 3: Suspicious PowerShell Execution

**Objective:** Simulate a post-exploitation technique using encoded PowerShell commands.

**Command executed on Windows endpoint:**
```powershell
powershell -EncodedCommand <base64-encoded-whoami>
```

**What happened:**
- Sysmon captured the PowerShell execution with Event ID 1 (Process Creation)
- The encoded command flag (-EncodedCommand) triggered Wazuh detection rules for suspicious PowerShell activity
- Windows Defender also flagged the behaviour and generated an EDR alert

**Alert generated in Wazuh:**
- Rule ID: 92200: PowerShell suspicious execution detected
- Severity: Level 12
- Process: powershell.exe
- Command line: included -EncodedCommand flag

**MITRE ATT&CK mapping:**
- Tactic: TA0002: Execution
- Technique: T1059.001: Command and Scripting Interpreter: PowerShell
- Defence evasion via: T1027: Obfuscated Files or Information

---

## Alert Investigation and Triage

For each alert generated, I followed this triage workflow:

```
ALERT RECEIVED
      |
      v
1. CHECK SEVERITY — is this Level 7+ requiring immediate review?
      |
      v
2. IDENTIFY SOURCE — which agent? which IP? internal or external?
      |
      v
3. CHECK CONTEXT — what was happening before and after? correlated events?
      |
      v
4. ASSESS — true positive or false positive?
      |
      +---> FALSE POSITIVE — document and tune rule to reduce noise
      |
      +---> TRUE POSITIVE — escalate, contain, document in ticket
```

**Example investigation: Brute Force Alert:**

When the brute force alert fired, I investigated by:

1. Opening the alert in the Wazuh dashboard and reviewing the raw log data
2. Confirming the source IP (192.168.31.131: Kali VM, known attacker in this lab)
3. Reviewing Windows Security Event logs for Event ID 4625: confirmed 47 failed logon attempts in 3 minutes
4. Checking if any successful logon followed the failures (Event ID 4624): none found
5. Classification: True positive: brute force attempt, no successful authentication
6. Action: Documented in Jira ticket, noted source IP for blocking recommendation

---

## MITRE ATT&CK Mapping

| Simulation | Tactic | Technique | ID |
|---|---|---|---|
| Nmap port scan | Reconnaissance | Network Service Discovery | T1046 |
| Brute force RDP | Credential Access | Brute Force — Password Guessing | T1110.001 |
| Encoded PowerShell | Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Encoded PowerShell | Defence Evasion | Obfuscated Files or Information | T1027 |
| SMB exposure | Discovery | Network Share Discovery | T1135 |
| RDP exposure | Lateral Movement | Remote Services: RDP | T1021.001 |

---

## Key Findings and Lessons Learned

**Finding 1: Default Windows logging is insufficient**
Before installing Sysmon, many of the attack simulations generated no meaningful Windows Event logs. Sysmon transformed the visibility — particularly for PowerShell execution and network connections. In a real SOC, ensuring proper endpoint logging configuration is as important as the SIEM itself.

**Finding 2: Alert volume vs signal quality**
The Nmap scan generated 200+ raw alerts but most were duplicate port scan entries. Learning to tune rules and group related alerts into a single investigation was a key skill developed in this lab. Reducing noise without losing signal is the core challenge of Tier 1 SOC work.

**Finding 3: Correlation matters more than individual alerts**
The brute force alert alone was useful. But correlating it with Sysmon network connection logs and then checking for any subsequent successful logon gave a complete picture. Single alerts in isolation rarely tell the full story.

**Finding 4: MITRE ATT&CK is a thinking framework, not just a label**
Mapping detections to MITRE is not just a checkbox. Understanding that T1046 is typically a precursor to T1110 and then T1059 helped me think about the attacker's likely next step and what to look for proactively.

---

## Screenshots

> Screenshots of the Wazuh dashboard showing:
> - Agent whiplash connected and active
> - Brute force alert with full event details
> - PowerShell detection with Sysmon telemetry
> - MITRE ATT&CK module showing technique coverage

*(Screenshots to be added — lab is active)*

---

## Tools Used

| Tool | Purpose |
|---|---|
| Wazuh 4.7.5 | SIEM — log collection, detection, alerting |
| VMware Workstation | Virtualisation platform |
| Kali Linux 2025.4 | Attack simulation |
| Sysmon | Windows endpoint telemetry |
| Microsoft Defender for Endpoint | EDR telemetry |
| Nmap | Network reconnaissance simulation |
| Hydra | Brute force simulation |
| Windows 11 Pro | Endpoint agent host |

---

## Next Steps

- Connect Splunk alongside Wazuh for comparative SIEM analysis
- Install and configure MISP for threat intelligence feed integration
- Add Metasploitable2 VM as additional vulnerable target
- Write custom Wazuh detection rules for additional MITRE techniques
- Document full detection engineering workflow for 10 MITRE techniques
