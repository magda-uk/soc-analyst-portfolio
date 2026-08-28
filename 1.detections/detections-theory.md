# Detection Theory. SOC Analyst Overview
## Purpose of This Document
This document provides a concise, SOC-focused introduction to detection engineering in Microsoft Sentinel, written for junior analysts building practical experience.  
It explains what detections are, how they work, and how SOC analysts use them during investigations.

---

## What Is a Detection?
A detection is a rule that identifies suspicious or malicious behaviour in log data.

In a SOC environment, detections:
* Generate alerts
* Highlight abnormal activity
* Provide early warning of attacks
* Support investigation and escalation

> Without detections, a SOC would have no visibility into threats.

---

## Why Detections Matter for SOC Analysts
A SOC L1 analyst must be able to:

* Understand why an alert fired
* Interpret the detection logic
* Recognise suspicious patterns
* Validate whether the alert is genuine
* Map behaviour to MITRE ATT&CK
* Follow investigation and escalation workflows

---

## What Is Microsoft Sentinel?
Microsoft Sentinel is a cloud-native SIEM that provides:

* Log collection
* Real-time alerting
* Threat detection
* Investigation tools
* Automation (SOAR)

Sentinel uses **Kusto Query Language (KQL)** to analyse logs and build detection rules.

---

## Analytics Rules in Sentinel
An Analytics Rule defines the logic that determines whether an alert should fire.

A typical rule contains:
* **KQL query:** Detection logic
* **Entity mappings:** User, host, IP, process
* **MITRE ATT&CK technique:** Tactic and technique mapping
* **Severity:** High, Medium, Low, Informational
* **Alert description & recommended response:** Triage and response guidance

---

## Identity-Based Detections
Modern attacks frequently target identity rather than endpoints.

Common techniques include:
* Brute force
* Password spraying
* MFA fatigue
* Impossible travel
* Session hijacking

Because of this, many Sentinel alerts originate from authentication anomalies.

---

## SigninLogs — Core Identity Table
`SigninLogs` contains information about:

* Successful and failed sign-ins
* MFA prompts and failures
* IP addresses and geolocation
* Device and browser details
* Conditional Access results

SOC analysts use this table to detect:
* Brute force attempts
* Impossible travel
* Suspicious MFA behaviour
* Account takeover
* Abnormal authentication patterns

---

## MITRE ATT&CK for Identity Detections
Identity anomalies commonly map to:

* **T1078 — Valid Accounts:** Attackers use legitimate credentials to access systems.

This technique is dangerous because valid credentials allow attackers to:
* Bypass perimeter controls
* Blend in with normal traffic
* Access cloud resources
* Escalate privileges
* Move laterally

---

## How SOC Analysts Validate Identity Alerts
Validation typically includes:

* Reviewing MFA activity
* Checking IP reputation
* Analysing device information
* Confirming user behaviour
* Identifying signs of phishing or compromise

---

## How SOC Analysts Investigate Identity Alerts
Key investigation steps:

* Review sign-in timeline
* Check for impossible travel
* Analyse MFA logs
* Examine post-authentication activity
* Identify lateral movement
* Assess risk and scope

---

## Response Actions
Common response actions include:

* Resetting passwords
* Revoking tokens (active sessions)
* Forcing re-authentication
* Blocking suspicious IPs
* Applying Conditional Access
* Notifying the user
* Escalating if compromise is confirmed
---