# Wazuh Lab Environment

## Objective
To test host-based detection and log collection using Wazuh.

## Setup
- Wazuh Manager
- Wazuh Agent on Windows VM
- Sysmon integrated with Wazuh

## Activities Performed
- Simulated suspicious PowerShell activity.
- Generated network scanning behaviour.
- Tested script execution via WScript and CScript.

## Logs Generated
- Process creation
- Script execution
- Network activity

## Outcome
Wazuh logs used to validate Sigma and Elastic detections.
