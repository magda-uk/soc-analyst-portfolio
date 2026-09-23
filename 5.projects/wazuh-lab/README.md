# 💠 Enterprise SOC & Threat Triage Lab 
# (Wazuh + Sysmon)

## 💠 Overview
This project documents a corporate security lab environment (Enterprise SOC) designed to simulate adversarial tactics, ingest host-level telemetry, and validate detection rules. 

The primary objective is to demonstrate the full lifecycle of Blue Team operations: from network attack execution, through the correlation of native Windows logs, to the final triage of critical alerts within the SIEM.

## 💠 Network & Sensor Architecture

The environment replicates a standard corporate infrastructure using three dedicated nodes:

*   **SIEM / Manager:** Wazuh Server (Ubuntu Linux) responsible for alert ingestion, normalisation, and correlation.
*   **Victim Endpoint:** Windows 10/11 Enterprise equipped with the Wazuh agent and Sysmon (using the SwiftOnSecurity baseline configuration to reduce noise).
*   **Adversary / Red Team:** Kali Linux used to launch controlled attack simulations.

## 💠 Implemented Detection Capabilities

This lab is fine-tuned to hunt specific threats across multiple telemetry sources:
*   Monitoring anomalous process execution (Sysmon Event ID 1).
*   Auditing authentication, brute-force attempts, and logon failures (Windows Security Logs).
*   Detection of privilege escalation and local account persistence.
*   Network restriction evasion (NLA Bypass).

## 💠 Case Studies & Investigations (Threat Triage)

The following reports detail the simulated attacks, the generated telemetry, and incident response (IR) recommendations.

| MITRE Tactic | Investigation Title | Status |
| :--- | :--- | :--- |
| **T1110.001** | [RDP Brute Force & NLA Evasion](t1110-rdp-bruteforce.md) | ✅ Completed |
| **T1136.001** | [Local Account Persistence](t1136-persistence-lab.md) | ✅ Completed |

>*(Note: The Ransomware and FIM simulation is documented in an independent project within the repository to maintain tactic separation).*

---
💠 **Authored by:** Magda Dominguez  
*Security Operations 💠 Detection Engineering 💠 Blue Team*